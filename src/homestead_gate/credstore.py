"""Credential custody: the gate holds the email credentials, the agent never sees them.

Why: practitioners keep credentials in a broker the agent can't reach (vault research,
agentsec_insights_2026-09-30). If the agent holds an SMTP password or API token it can send
without asking the gate, and the 2-of-2 is decoration. Here the password lives in the OS
credential store under the gate's own entry; the agent's environment never contains it and the
sandbox hides the gate's config.

  macOS  keychain item "homestead-gate-smtp", created with -T <this interpreter>, so the gate reads
         it silently and anything else that asks (a sandboxed agent calling `security`) gets a
         visible macOS permission dialog instead of the password.
  Linux  libsecret via `secret-tool`. No plaintext fallback: without libsecret, live email is refused.

Non-secret settings (host, port, user, starttls) go to ~/.homestead-gate/smtp.toml, mode 0600.
The password is only ever typed by the human into the credential store's own prompt; it is never
an argument, an environment variable, a log line or a receipt.

The assistant's read-only IMAP login (mailbox.py) is a separate entry, "homestead-gate-imap", so a
password saved for reading mail is never used to send: live email still needs `creds set-smtp`
and `--live`.

The receipt ledger's key is a third entry, "homestead-gate-ledger-key". Unlike the passwords it is
generated here (32 random bytes, stored as hex) on first use, handed to the store on stdin, never in
argv, and never written to a file. receipts.py derives the checkpoint signing key and the per-record
MAC key from it.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from subprocess import TimeoutExpired      # by name: tests swap the subprocess module out

SERVICE = "homestead-gate-smtp"
IMAP_SERVICE = "homestead-gate-imap"
LEDGER_KEY_SERVICE = "homestead-gate-ledger-key"
LEDGER_KEY_ACCOUNT = "receipts"
# The last head the gate sealed for each ledger ("records:head", one entry per ledger path). Not a
# secret, but kept here because it is the one local record someone with only your files can't rewrite:
# a rebuilt chain that also deletes every checkpoint file still has to extend it.
LEDGER_HEAD_SERVICE = "homestead-gate-ledger-head"
LOOKUP_TIMEOUT_S = 20
HOME = Path.home() / ".homestead-gate"
CONFIG = HOME / "smtp.toml"


class CredentialError(RuntimeError):
    pass


def _backend() -> str:
    if sys.platform == "darwin" and shutil.which("security"):
        return "keychain"
    if sys.platform.startswith("linux") and shutil.which("secret-tool"):
        return "libsecret"
    raise CredentialError("no supported credential store (macOS keychain or Linux libsecret/secret-tool); "
                          "live email stays off rather than keeping a password in a file")


def _write_config(host: str, port: int, user: str, starttls: bool) -> None:
    HOME.mkdir(parents=True, exist_ok=True)
    body = f'host = "{host}"\nport = {int(port)}\nuser = "{user}"\nstarttls = {"true" if starttls else "false"}\n'
    fd = os.open(CONFIG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(body)
    os.chmod(CONFIG, 0o600)


def check_value(field: str, value: str) -> None:
    """Settings are written into TOML by hand; refuse anything that could break out of a string."""
    if not value or any(c in value for c in '"\n\\'):
        raise CredentialError(f"invalid {field}")


def _store_secret(service: str, user: str, label: str) -> None:
    """Have the OS store prompt the human for the secret (interactive). It never passes through here."""
    if _backend() == "keychain":
        # `-w` as the LAST argument makes `security` prompt for the password on the terminal, so it
        # never appears in argv or the process list. -T limits silent access to this interpreter.
        r = subprocess.run(["security", "add-generic-password", "-U", "-s", service, "-a", user,
                            "-T", sys.executable, "-w"])
    else:
        # secret-tool reads the secret from stdin/tty itself.
        r = subprocess.run(["secret-tool", "store", "--label", label, "service", service, "user", user])
    if r.returncode != 0:
        raise CredentialError("the credential store did not save the password")


def _load_secret(service: str, user: str) -> str | None:
    # A timeout, because the store may answer with a permission dialog that nobody is there to
    # click (launchd, cron): an unattended pass must fail, not hang holding its lock.
    argv = (["security", "find-generic-password", "-s", service, "-a", user, "-w"] if _backend() == "keychain"
            else ["secret-tool", "lookup", "service", service, "user", user])
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=LOOKUP_TIMEOUT_S)
    except TimeoutExpired:
        raise CredentialError(f"the credential store did not answer within {LOOKUP_TIMEOUT_S}s "
                              "(a permission dialog nobody answered?)") from None
    pw = (r.stdout or "").rstrip("\n")
    return pw if r.returncode == 0 and pw else None


def _delete_secret(service: str, user: str) -> None:
    if _backend() == "keychain":
        subprocess.run(["security", "delete-generic-password", "-s", service, "-a", user], capture_output=True)
    else:
        subprocess.run(["secret-tool", "clear", "service", service, "user", user], capture_output=True)


def _store_generated_secret(service: str, user: str, secret: str, label: str) -> None:
    """Store a secret this process generated, without it ever appearing in argv or a file.

    macOS: `security -i` reads its command from stdin, so the key is never in the process list
    (`add-generic-password ... -w KEY` as arguments would be). -T limits silent access to this
    interpreter, as for the passwords. Linux: secret-tool reads the secret from stdin when stdin
    is not a terminal."""
    if not re.fullmatch(r"[0-9a-f:]+", secret) or not re.fullmatch(r"[0-9a-z-]+", user):
        raise CredentialError("refusing to store a generated value with unexpected characters")
    if _backend() == "keychain":
        exe = sys.executable.replace("\\", "\\\\").replace('"', '\\"')
        cmd = f'add-generic-password -U -s {service} -a {user} -T "{exe}" -w {secret}\n'
        argv, stdin = ["security", "-i"], cmd
    else:
        argv, stdin = ["secret-tool", "store", "--label", label, "service", service, "user", user], secret
    try:
        r = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=LOOKUP_TIMEOUT_S)
    except TimeoutExpired:
        raise CredentialError(f"the credential store did not answer within {LOOKUP_TIMEOUT_S}s") from None
    if r.returncode != 0:
        raise CredentialError("the credential store did not save the ledger key")


def _ledger_key_from_store(create: bool) -> bytes | None:
    _backend()                                  # CredentialError when there is no store at all
    hexkey = _load_secret(LEDGER_KEY_SERVICE, LEDGER_KEY_ACCOUNT)
    if hexkey is None:
        if not create:
            return None
        _store_generated_secret(LEDGER_KEY_SERVICE, LEDGER_KEY_ACCOUNT, secrets.token_hex(32),
                                "homestead-gate receipt ledger key")
        hexkey = _load_secret(LEDGER_KEY_SERVICE, LEDGER_KEY_ACCOUNT)
        if hexkey is None:
            raise CredentialError("the credential store did not keep the ledger key")
    hexkey = hexkey.strip()
    if not re.fullmatch(r"[0-9a-f]{64}", hexkey):
        raise CredentialError(f"the {LEDGER_KEY_SERVICE} entry is not a 32-byte hex key")
    return bytes.fromhex(hexkey)


def load_or_create_ledger_key() -> bytes:
    """The receipt ledger's master key from the OS credential store, generated on first use.
    Raises CredentialError when there is no store; the caller warns and degrades."""
    key = _ledger_key_from_store(create=True)
    assert key is not None
    return key


def store_ledger_head(account: str, value: str) -> None:
    """Record the last sealed head ("records:head") for one ledger; replaces the previous value."""
    _store_generated_secret(LEDGER_HEAD_SERVICE, account, value, "homestead-gate receipt ledger head")


def load_ledger_head(account: str) -> str | None:
    _backend()
    return _load_secret(LEDGER_HEAD_SERVICE, account)


def load_ledger_key() -> bytes | None:
    """The ledger key if this machine has one. Never creates one: verifying a copied ledger on an
    auditor's machine must not plant a key in their keychain."""
    return _ledger_key_from_store(create=False)


def store_smtp(host: str, port: int, user: str, starttls: bool = True) -> None:
    """Save settings and have the OS store prompt the human for the password (interactive)."""
    _backend()
    for field, value in (("host", host), ("user", user)):
        check_value(field, value)
    _store_secret(SERVICE, user, "homestead-gate smtp")
    _write_config(host, port, user, starttls)


def load_smtp() -> dict | None:
    """Settings + password for the gate's own sender, or None if not configured."""
    if not CONFIG.exists():
        return None
    cfg = tomllib.loads(CONFIG.read_text())
    pw = _load_secret(SERVICE, cfg["user"])
    if pw is None:
        return None
    return {"host": cfg["host"], "port": int(cfg.get("port", 587)), "user": cfg["user"],
            "starttls": bool(cfg.get("starttls", True)), "password": pw}


def store_imap(user: str) -> None:
    """The assistant's IMAP password, typed by the human into the OS store's own prompt. The
    settings (host, port, mailbox) live in the assistant's policy.toml, not here."""
    _backend()
    check_value("user", user)
    _store_secret(IMAP_SERVICE, user, "homestead-gate imap (read-only)")


def load_imap_password(user: str) -> str | None:
    return _load_secret(IMAP_SERVICE, user)


def clear_imap(user: str) -> None:
    _delete_secret(IMAP_SERVICE, user)


def status() -> str:
    """Human-readable state. Never includes the password."""
    if not CONFIG.exists():
        return "smtp: not configured (email stays dry-run). Set it with `homestead-gate creds set-smtp`."
    cfg = tomllib.loads(CONFIG.read_text())
    try:
        have = load_smtp() is not None
    except CredentialError as e:
        return f"smtp: {cfg.get('user')}@{cfg.get('host')}, but {e}"
    return (f"smtp: {cfg.get('user')} via {cfg.get('host')}:{cfg.get('port')}, password "
            + ("stored in the OS credential store" if have else "MISSING from the credential store"))


def clear() -> None:
    if not CONFIG.exists():
        return
    cfg = tomllib.loads(CONFIG.read_text())
    try:
        _delete_secret(SERVICE, cfg["user"])
    finally:
        CONFIG.unlink(missing_ok=True)
