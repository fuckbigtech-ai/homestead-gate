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
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

SERVICE = "homestead-gate-smtp"
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


def store_smtp(host: str, port: int, user: str, starttls: bool = True) -> None:
    """Save settings and have the OS store prompt the human for the password (interactive)."""
    backend = _backend()
    for field, value in (("host", host), ("user", user)):
        if not value or any(c in value for c in '"\n\\'):
            raise CredentialError(f"invalid {field}")
    if backend == "keychain":
        # `-w` as the LAST argument makes `security` prompt for the password on the terminal, so it
        # never appears in argv or the process list. -T limits silent access to this interpreter.
        r = subprocess.run(["security", "add-generic-password", "-U", "-s", SERVICE, "-a", user,
                            "-T", sys.executable, "-w"])
    else:
        # secret-tool reads the secret from stdin/tty itself.
        r = subprocess.run(["secret-tool", "store", "--label", "homestead-gate smtp",
                            "service", SERVICE, "user", user])
    if r.returncode != 0:
        raise CredentialError("the credential store did not save the password")
    _write_config(host, port, user, starttls)


def load_smtp() -> dict | None:
    """Settings + password for the gate's own sender, or None if not configured."""
    if not CONFIG.exists():
        return None
    cfg = tomllib.loads(CONFIG.read_text())
    backend = _backend()
    if backend == "keychain":
        r = subprocess.run(["security", "find-generic-password", "-s", SERVICE, "-a", cfg["user"], "-w"],
                           capture_output=True, text=True)
    else:
        r = subprocess.run(["secret-tool", "lookup", "service", SERVICE, "user", cfg["user"]],
                           capture_output=True, text=True)
    pw = (r.stdout or "").rstrip("\n")
    if r.returncode != 0 or not pw:
        return None
    return {"host": cfg["host"], "port": int(cfg.get("port", 587)), "user": cfg["user"],
            "starttls": bool(cfg.get("starttls", True)), "password": pw}


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
        backend = _backend()
        if backend == "keychain":
            subprocess.run(["security", "delete-generic-password", "-s", SERVICE, "-a", cfg["user"]],
                           capture_output=True)
        else:
            subprocess.run(["secret-tool", "clear", "service", SERVICE, "user", cfg["user"]], capture_output=True)
    finally:
        CONFIG.unlink(missing_ok=True)
