"""Your real inbox, read-only: IMAP over TLS into the assistant's inbox.json.

  homestead-gate assistant --data ~/.homestead-gate/mail --imap-setup   host, user; the OS store asks for the app password
  homestead-gate assistant --data ~/.homestead-gate/mail --sync         one sync, prints how many are new
  homestead-gate assistant --data ~/.homestead-gate/mail --watch        syncs before each pass

Read-only is enforced by this code at the protocol level, not by the credential (an app password
can do anything to the mailbox):
- the mailbox is opened with EXAMINE (`select(readonly=True)`), which the server holds read-only;
- messages are fetched with BODY.PEEK[], which does not set \\Seen;
- the only commands sent are LOGIN, EXAMINE, UID SEARCH, UID FETCH and LOGOUT. `_uid` refuses any
  other UID command, and nothing here calls store, copy, move, expunge, append, delete or close.

What is kept: sender, subject, date and the text of each message (text/plain, else the HTML with
the tags stripped), cut to BODY_MAX characters. Attachments are never kept; their names are noted.
State (UIDVALIDITY and the last UID synced) is in imap_state.json; when the server renumbers the
mailbox (UIDVALIDITY changes), the next sync starts over from the last few days and Message-ID
dedupe keeps the inbox from doubling.

The password comes from the OS credential store (credstore.IMAP_SERVICE) for each sync and is never
written to the data dir, printed, or kept in an error message.
"""
from __future__ import annotations

import email
import imaplib
import json
import os
import ssl
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from email.header import decode_header, make_header
from email.policy import default as default_policy
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable

from . import credstore

STATE_FILE = "imap_state.json"
BODY_MAX = 8000                  # characters of text kept per message
FETCH_BYTES = 512 * 1024         # at most this much of each message is downloaded (BODY.PEEK[]<0.N>)
TIMEOUT_S = 30
_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
_READ_ONLY_UID = ("SEARCH", "FETCH")
APP_PASSWORDS = "https://myaccount.google.com/apppasswords"


class MailboxError(RuntimeError):
    """kind: config (not set up), auth (login refused), network (could not talk to the server),
    protocol (the server said no to something else)."""
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


@dataclass
class ImapConfig:
    host: str
    user: str
    port: int = 993
    mailbox: str = "INBOX"
    days: int = 3                # first sync: only mail from the last N days
    max_messages: int = 50       # per sync, newest first

    @property
    def account(self) -> str:
        return f"{self.user}@{self.host}:{self.port}/{self.mailbox}"


@dataclass
class SyncResult:
    host: str
    mailbox: str
    new: list[dict] = field(default_factory=list)
    duplicates: int = 0
    not_fetched: int = 0         # older than the newest max_messages; skipped for good
    reset: bool = False          # the server renumbered the mailbox (UIDVALIDITY changed)

    def summary(self) -> str:
        n = len(self.new)
        s = f"{n} new message{'s' if n != 1 else ''} from {self.mailbox} on {self.host} (read-only)"
        if self.not_fetched:
            s += f"; {self.not_fetched} older one{'s' if self.not_fetched != 1 else ''} skipped (over the per-sync limit)"
        if self.reset:
            s += "; the server renumbered the mailbox, so this sync started over from the last few days"
        return s


# ---------------------------------------------------------------- config in the assistant's policy.toml

def load_config(data: Path) -> ImapConfig | None:
    try:
        d = tomllib.loads((Path(data) / "policy.toml").read_text()).get("imap")
    except (OSError, tomllib.TOMLDecodeError):
        return None
    if not isinstance(d, dict) or not d.get("host") or not d.get("user"):
        return None
    return ImapConfig(host=str(d["host"]), user=str(d["user"]), port=int(d.get("port", 993)),
                      mailbox=str(d.get("mailbox", "INBOX")), days=max(1, int(d.get("days", 3))),
                      max_messages=max(1, int(d.get("max_messages", 50))))


def _imap_section(cfg: ImapConfig) -> str:
    return ("[imap]\n# read-only: EXAMINE + BODY.PEEK. The password is in the OS credential store, not here.\n"
            f'host = "{cfg.host}"\nport = {int(cfg.port)}\nuser = "{cfg.user}"\nmailbox = "{cfg.mailbox}"\n'
            f"days = {int(cfg.days)}\nmax_messages = {int(cfg.max_messages)}\n")


def write_config(data: Path, cfg: ImapConfig) -> None:
    """Put an [imap] section into the data dir's policy.toml, replacing any earlier one."""
    for name, value in (("host", cfg.host), ("user", cfg.user), ("mailbox", cfg.mailbox)):
        credstore.check_value(name, value)
    p = Path(data) / "policy.toml"
    old = p.read_text() if p.exists() else ""
    kept, skipping = [], False
    for line in old.splitlines():
        head = line.strip()
        if head.startswith("["):
            skipping = head == "[imap]"
        if not skipping:
            kept.append(line)
    text = "\n".join(kept).rstrip() + ("\n\n" if kept else "") + _imap_section(cfg)
    tomllib.loads(text)              # never leave a policy the gate cannot load
    _write_private(p, text)


def holds_demo_inbox(data: Path) -> bool:
    """True when inbox.json has mail that did not come from IMAP (the seeded fake inbox)."""
    try:
        inbox = json.loads((Path(data) / "inbox.json").read_text())
    except (OSError, ValueError):
        return False
    return any(not str(m.get("id", "")).startswith("imap-") for m in inbox if isinstance(m, dict))


def prepare_data_dir(data: Path, user_email: str, model: str) -> list[str]:
    """A data dir for real mail: empty inbox and bills, a policy naming you, the default skills.
    Writes only what is missing. Refuses a dir holding the demo's fake inbox, so real mail and the
    fake 'my wallet changed' email are never mixed. Returns the files it wrote."""
    from . import skills as skills_mod
    data = Path(data)
    if holds_demo_inbox(data):
        raise MailboxError("config", f"{data} holds the demo's fake inbox. Use a separate data dir for your "
                                     "real mail, e.g. --data ~/.homestead-gate/mail")
    data.mkdir(parents=True, exist_ok=True)
    os.chmod(data, 0o700)            # real mail lives here: inbox, held reads, briefs
    wrote = []
    for name, body in (("inbox.json", "[]\n"), ("bills.json", "[]\n")):
        if not (data / name).exists():
            _write_private(data / name, body)
            wrote.append(name)
    if not (data / "policy.toml").exists():
        email_line = f'email = "{user_email}"\n' if "@" in user_email else ""
        _write_private(data / "policy.toml", "# homestead assistant policy for your real inbox\n"
                       f"[user]\n{email_line}\n[review]\nmodel = \"{model}\"\n"
                       "# the reviewer reasons before its verdict (slower, far fewer false blocks); false = faster\n"
                       "think = true\n")
        wrote.append("policy.toml")
    if skills_mod.ensure_skills_file(data):
        wrote.append("skills.toml")
    return wrote


# ---------------------------------------------------------------- parsing

class _HTMLText(HTMLParser):
    """Visible text of an HTML body. Comments, scripts and styles are dropped (this is for reading,
    not a defense: hidden text in visible tags still comes through)."""
    _SKIP = {"script", "style", "head", "title", "noscript"}
    _BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6", "table", "blockquote",
              "section", "article", "header", "footer", "hr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: list[str] = []
        self.skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self.skip += 1
        elif tag in self._BLOCK:
            self.out.append("\n- " if tag == "li" else "\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP:
            self.skip = max(0, self.skip - 1)
        elif tag in self._BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)


def html_to_text(html: str) -> str:
    p = _HTMLText()
    try:
        p.feed(html)
        p.close()
    except Exception:  # noqa: BLE001 - a broken page still gives whatever text was parsed
        pass
    return _tidy("".join(p.out))


def _tidy(text: str) -> str:
    lines = [" ".join(ln.split()) for ln in text.replace("\r", "").split("\n")]
    out: list[str] = []
    for ln in lines:
        if ln or (out and out[-1]):
            out.append(ln)
    return "\n".join(out).strip()


def _header(msg, name: str) -> str:
    v = msg.get(name)
    if v is None:
        return ""
    try:
        s = str(make_header(decode_header(str(v))))
    except Exception:  # noqa: BLE001 - a malformed encoded word: keep it as it came
        s = str(v)
    return " ".join(s.split())


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:  # noqa: BLE001 - unknown charset or broken transfer encoding
        raw = part.get_payload(decode=True) or b""
        try:
            return raw.decode(part.get_content_charset() or "utf-8", "replace")
        except LookupError:
            return raw.decode("utf-8", "replace")


def _body(msg) -> tuple[str, list[str]]:
    plain = html = None
    attachments: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        name = part.get_filename()
        if name or part.get_content_disposition() == "attachment":
            attachments.append(" ".join(str(name or "(unnamed)").split())[:120])
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain" and plain is None:
            plain = _part_text(part)
        elif ctype == "text/html" and html is None:
            html = _part_text(part)
    if plain and plain.strip():
        return _tidy(plain), attachments
    return (html_to_text(html) if html else ""), attachments


def _date(raw: str) -> str:
    try:
        dt = parsedate_to_datetime(raw)
        return (dt.astimezone() if dt.tzinfo else dt).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError, IndexError):
        return raw[:40]


def parse_message(raw: bytes, msg_id: str, *, cut_short: bool = False) -> dict:
    """One RFC 822 message as an inbox.json entry."""
    hdr = email.message_from_bytes(raw)                              # compat32: raw headers
    msg = email.message_from_bytes(raw, policy=default_policy)       # for the body
    name, addr = parseaddr(_header(hdr, "From"))
    body, attachments = _body(msg)
    if len(body) > BODY_MAX:
        body = body[:BODY_MAX] + f"\n[... {len(body) - BODY_MAX} more characters cut]"
    if cut_short:
        body += f"\n[only the first {FETCH_BYTES // 1024} KB of this message was downloaded]"
    if attachments:
        body += "\n[attachments, not downloaded: " + ", ".join(attachments) + "]"
    return {"id": msg_id, "from": addr or _header(hdr, "From")[:200], "name": name[:120],
            "subject": _header(hdr, "Subject")[:300] or "(no subject)", "date": _date(_header(hdr, "Date")),
            "body": body, "attachments": attachments, "message_id": _header(hdr, "Message-ID")[:300],
            "source": "imap"}


# ---------------------------------------------------------------- sync

def default_connect(host: str, port: int):
    return imaplib.IMAP4_SSL(host, port, ssl_context=ssl.create_default_context(), timeout=TIMEOUT_S)


def _quote(mailbox: str) -> str:
    return '"' + mailbox.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _imap_date(d: datetime) -> str:
    return f"{d.day:02d}-{_MONTHS[d.month - 1]}-{d.year}"          # never %b: it follows the locale


def _uid(conn, command: str, *args):
    if command not in _READ_ONLY_UID:
        raise MailboxError("protocol", f"refused UID {command}: this connection is read-only")
    typ, data = conn.uid(command, *args)
    if typ != "OK":
        raise MailboxError("protocol", f"the server refused UID {command}")
    return data


def _fetch(conn, uid: int) -> bytes | None:
    for item in _uid(conn, "FETCH", str(uid), f"(BODY.PEEK[]<0.{FETCH_BYTES}>)") or []:
        if isinstance(item, tuple) and len(item) >= 2 and isinstance(item[1], bytes):
            return item[1]
    return None              # gone since the search


def _uidvalidity(conn) -> int:
    try:
        _, data = conn.response("UIDVALIDITY")
        return int(data[0])
    except (TypeError, ValueError, IndexError):
        return 0


def load_state(data: Path) -> dict:
    try:
        st = json.loads((Path(data) / STATE_FILE).read_text())
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_private(path: Path, text: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def is_gmail(host: str) -> bool:
    return host.lower().rstrip(".").endswith(("gmail.com", "googlemail.com"))


def auth_help(cfg: ImapConfig) -> str:
    if is_gmail(cfg.host):
        return ("Gmail only accepts an app password here, not your normal password, and app passwords "
                "need 2-Step Verification:\n"
                "  1. turn on 2-Step Verification: https://myaccount.google.com/security\n"
                f"  2. create an app password: {APP_PASSWORDS}\n"
                "  3. run --imap-setup again (same --data) and paste the 16 letters into the password prompt.\n"
                "Some work or school accounts (and Advanced Protection) do not offer app passwords.")
    return (f"check the user ({cfg.user}) and password for {cfg.host}; many providers want an app "
            "password for IMAP. Run --imap-setup again to replace it.")


def _scrub(text: str, password: str) -> str:
    for secret in {password, "".join(password.split())} - {""}:
        text = text.replace(secret, "***")
    return text


def sync(data: Path, cfg: ImapConfig, password: str, *, connect: Callable | None = None,
         now: datetime | None = None) -> SyncResult:
    """Fetch the mail that is new since the last sync into inbox.json. Raises MailboxError."""
    data, now = Path(data), now or datetime.now()
    if is_gmail(cfg.host):
        password = "".join(password.split())     # Google shows app passwords as four groups of four
    conn = None
    try:
        try:
            conn = (connect or default_connect)(cfg.host, cfg.port)
        except (OSError, imaplib.IMAP4.error) as e:
            raise MailboxError("network", f"could not reach {cfg.host}:{cfg.port}: {e}") from None
        try:
            conn.login(cfg.user, password)
        except imaplib.IMAP4.abort as e:
            raise MailboxError("network", f"{cfg.host} dropped the connection during login: {e}") from None
        except imaplib.IMAP4.error as e:
            raise MailboxError("auth", f"{cfg.host} refused the login for {cfg.user}: {e}\n" + auth_help(cfg)) from None
        try:
            return _sync(conn, data, cfg, now)
        except imaplib.IMAP4.abort as e:
            raise MailboxError("network", f"lost the connection to {cfg.host}: {e}") from None
        except OSError as e:
            raise MailboxError("network", f"lost the connection to {cfg.host}: {e}") from None
        except imaplib.IMAP4.error as e:
            raise MailboxError("protocol", f"{cfg.host}: {e}") from None
    except MailboxError as e:
        raise MailboxError(e.kind, _scrub(str(e), password)) from None
    finally:
        if conn is not None:
            try:
                conn.logout()
            except Exception:  # noqa: BLE001 - already done reading; a failed goodbye changes nothing
                pass


def _sync(conn, data: Path, cfg: ImapConfig, now: datetime) -> SyncResult:
    typ, _ = conn.select(_quote(cfg.mailbox), readonly=True)            # EXAMINE
    if typ != "OK":
        raise MailboxError("protocol", f"could not open the mailbox {cfg.mailbox!r} on {cfg.host}")
    uidvalidity = _uidvalidity(conn)
    state = load_state(data)
    out = SyncResult(host=cfg.host, mailbox=cfg.mailbox)
    same = state.get("account") == cfg.account and state.get("uidvalidity") == uidvalidity
    out.reset = bool(state) and state.get("account") == cfg.account and not same
    last = int(state.get("last_uid") or 0) if same else 0
    if last:
        found = _uid(conn, "SEARCH", None, "UID", f"{last + 1}:*")
    else:
        found = _uid(conn, "SEARCH", None, "SINCE", _imap_date(now - timedelta(days=cfg.days)))
    # `UID n:*` always matches the newest message, even when its UID is below n
    uids = sorted({n for n in (int(x) for x in ((found or [b""])[0] or b"").split() if x.isdigit()) if n > last})
    take = uids[-cfg.max_messages:]
    out.not_fetched = len(uids) - len(take)

    p = data / "inbox.json"
    try:
        inbox = json.loads(p.read_text())
        inbox = inbox if isinstance(inbox, list) else []
    except (OSError, ValueError):
        inbox = []
    ids = {m.get("id") for m in inbox if isinstance(m, dict)}
    mids = {m.get("message_id") for m in inbox if isinstance(m, dict) and m.get("message_id")}
    for uid in take:
        mid = f"imap-{uidvalidity}-{uid}"
        if mid in ids:
            out.duplicates += 1
            continue
        raw = _fetch(conn, uid)
        if raw is None:
            continue
        try:
            entry = parse_message(raw, mid, cut_short=len(raw) >= FETCH_BYTES)
        except Exception:  # noqa: BLE001 - one malformed message must not stop the sync
            entry = {"id": mid, "from": "", "name": "", "subject": "(could not be read)", "date": "",
                     "body": "[this message could not be parsed]", "attachments": [], "message_id": "",
                     "source": "imap"}
        if entry["message_id"] and entry["message_id"] in mids:
            out.duplicates += 1
            continue
        out.new.append(entry)
        ids.add(mid)
        if entry["message_id"]:
            mids.add(entry["message_id"])
    if out.new:
        _write_private(p, json.dumps(inbox + out.new, indent=1))       # inbox first: a re-sync dedupes
    _write_private(data / STATE_FILE, json.dumps({
        "account": cfg.account, "uidvalidity": uidvalidity, "last_uid": max([last, *uids]),
        "last_sync": now.isoformat(timespec="seconds")}, indent=1))
    return out


def sync_configured(data: Path, *, connect: Callable | None = None, now: datetime | None = None) -> SyncResult:
    """Sync with the data dir's [imap] settings and the password from the OS credential store."""
    cfg = load_config(data)
    if cfg is None:
        raise MailboxError("config", "IMAP is not set up for this data dir. Run: homestead-gate assistant "
                                     f"--data {data} --imap-setup")
    try:
        password = credstore.load_imap_password(cfg.user)
    except credstore.CredentialError as e:
        raise MailboxError("config", f"cannot read the IMAP password: {e}") from None
    if not password:
        raise MailboxError("config", f"no IMAP password for {cfg.user}: it is missing, or the credential store "
                                     "refused to hand it over. Run --imap-setup again (same --data).")
    return sync(data, cfg, password, connect=connect, now=now)
