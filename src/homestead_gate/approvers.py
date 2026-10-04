"""Second approvers for dual control: a name and a salted scrypt hash of a passphrase only they know.

`homestead-gate approver add NAME` has the second person type their passphrase (twice, no echo). The
file keeps the name, a per-approver random salt, the scrypt parameters and the derived hash; never the
passphrase. At approval time the gate asks for it after the first person's yes and checks it here.

What this is and is not: dual control on ONE machine. It stops one person acting alone, because the
first person does not know the second person's passphrase. It does not stop someone who controls the
machine: anyone with this OS login can edit approvers.json or turn dual control off in the policy.
That edit is not prevented, it is recorded: the gate puts this file's sha256 into its policy receipts,
so the next start writes a policy.changed receipt with the old and new hashes.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path

FILE = "approvers.json"
# scrypt (RFC 7914) from the standard library. n=2**14, r=8 is the interactive-login setting:
# about 16 MB and tens of milliseconds per check, which is plenty for a typed passphrase.
N, R, P, DKLEN = 2 ** 14, 8, 1, 32
MIN_LEN = 8
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$")


def path(directory: Path) -> Path:
    return Path(directory) / FILE


def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(passphrase.encode(), salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=64 * 1024 * 1024)


def load(directory: Path | None) -> dict[str, dict]:
    """Registered approvers, by name. Missing or unreadable file means none, which fails closed."""
    if directory is None:
        return {}
    try:
        d = json.loads(path(directory).read_text())
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in d.items() if isinstance(v, dict)} if isinstance(d, dict) else {}


def file_sha256(directory: Path | None) -> str | None:
    """sha256 of approvers.json as it is on disk, or None if there is none. Goes into policy receipts."""
    if directory is None:
        return None
    try:
        return hashlib.sha256(path(directory).read_bytes()).hexdigest()
    except OSError:
        return None


def add(directory: Path, name: str, passphrase: str) -> None:
    name = name.strip()
    if not NAME.match(name):
        raise ValueError("name: letters, digits, space, dot, dash or underscore; up to 40 characters")
    if len(passphrase) < MIN_LEN:
        raise ValueError(f"passphrase: at least {MIN_LEN} characters")
    salt = secrets.token_bytes(16)
    rec = {"kdf": "scrypt", "n": N, "r": R, "p": P, "dklen": DKLEN, "salt": salt.hex(),
           "hash": _derive(passphrase, salt, N, R, P, DKLEN).hex(),
           "added": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    _write(directory, {**load(directory), name: rec})


def remove(directory: Path, name: str) -> bool:
    current = load(directory)
    if name not in current:
        return False
    del current[name]
    _write(directory, current)
    return True


def _write(directory: Path, data: dict) -> None:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = path(directory)
    tmp = target.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=1, sort_keys=True)
    os.replace(tmp, target)
    os.chmod(target, 0o600)


def verify(approvers: dict[str, dict], name: str, passphrase: str) -> bool:
    """True only for a registered name whose stored hash matches. Anything malformed is False."""
    rec = approvers.get((name or "").strip())
    if not rec or rec.get("kdf") != "scrypt" or not passphrase:
        return False
    try:
        salt, want = bytes.fromhex(rec["salt"]), bytes.fromhex(rec["hash"])
        got = _derive(passphrase, salt, int(rec["n"]), int(rec["r"]), int(rec["p"]), int(rec["dklen"]))
    except (KeyError, TypeError, ValueError):
        return False
    return hmac.compare_digest(got, want)
