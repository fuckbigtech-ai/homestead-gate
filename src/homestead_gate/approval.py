"""The human half of the 2-of-2 gate.

The yes comes from the terminal the human started the gate in, and from nowhere else.
There is deliberately no approve endpoint on the daemon: anything that can reach
127.0.0.1:6000 (the agent, another local process, a web page doing cross-site requests
to localhost) could otherwise approve its own request, and 2-of-2 would quietly become
1-of-1.

Override friction: approving something the model flagged takes a typed phrase, then a
wait, then a second yes. Approval fatigue is the known way these gates fail; the friction
lands only on the rare flagged case, so it is cheap where it matters.

What you approve is what you saw: when the card has to cut something short (a body over
BODY_LINES lines, any other field over FIELD_CHARS characters), a yes is not accepted until
you have paged through all of it with `v`. A no is always accepted.

Every answer records who gave it, as the OS reports it for the approving process: user,
uid, host and tty, plus the channel. That names an account, not a person: anyone at this
login is that user. Dual control (approvers.py) is what needs a second person.
"""
from __future__ import annotations

import json
import os
import re
import select
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

OVERRIDE_PHRASE = "send anyway"
BODY_LINES = 20
FIELD_CHARS = 600        # any other field longer than this is cut on the card (calldata within the default cap is not)
PAGE_LINES = 40          # the full view is paged in chunks this long
WRAP = 100               # long single-line fields are wrapped to this width in the full view
NO_MODEL_REASON = "no reviewer model (--no-model)"   # shown as is, never as a flag
# C0 and C1 control characters, ESC included. Everything shown here was written by the
# agent or quotes what it read, and one ANSI sequence (conceal, cursor-up, colour matched
# to the background) is enough to hide the model's flag line from the human.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
CARD_FIELDS = ("type", "to", "cc", "bcc", "subject", "value_eth", "chain_id", "data", "attachments")


def clean(value) -> str:
    return _CONTROL.sub("?", str(value))


def _text(value) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)) and all(isinstance(v, str) for v in value):
        return ", ".join(value)
    return json.dumps(value, sort_keys=True, default=str)


def _present(v) -> bool:
    return v is not None and v != "" and v != [] and v != {}


def needs_full_view(action: dict) -> list[str]:
    """The fields the card has to cut short. Shared by the terminal card and the web demo, so both
    refuse a yes on the same actions until the whole thing has been shown."""
    cut = []
    body = action.get("body")
    if _present(body) and len(str(body).splitlines()) > BODY_LINES:
        cut.append("body")
    for k in CARD_FIELDS:
        v = action.get(k)
        if _present(v) and len(_text(v)) > FIELD_CHARS:
            cut.append(k)
    return cut


def approver_identity(channel: str) -> dict:
    """Who answered, as the OS reports it for this process: the account, not a verified person."""
    try:
        import pwd
        user = pwd.getpwuid(os.getuid()).pw_name
    except (ImportError, KeyError, OSError):
        user = os.environ.get("USER") or os.environ.get("USERNAME")
    try:
        tty = os.ttyname(sys.stdin.fileno())
    except (OSError, ValueError, AttributeError):
        tty = None                     # not a terminal (piped, a test, a service)
    return {"channel": channel, "os_user": user, "uid": os.getuid() if hasattr(os, "getuid") else None,
            "host": socket.gethostname(), "tty": tty}


@dataclass
class HumanDecision:
    decision: str        # approve | deny | expired
    channel: str
    latency_s: float
    overrode_flag: bool = False
    approver: dict | None = None           # approver_identity(), or None when nobody answered (held)
    full_view_required: bool = False       # the card had to cut something short
    full_view_seen: bool = False           # ...and the approver paged through all of it
    # Dual control: what the second approver typed. The gate checks it against approvers.json and
    # then drops it; it is never written anywhere. A typed name is not logged on failure either.
    second_name: str | None = field(default=None, repr=False)
    second_secret: str | None = field(default=None, repr=False)


def _tty_input(prompt: str, timeout_s: float) -> str | None:
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [], [], max(0.0, timeout_s))
    if not ready:
        return None
    line = sys.stdin.readline()
    return line.strip() if line else None


def _tty_secret(prompt: str, timeout_s: float) -> str | None:
    """Like _tty_input, with echo off, so the second approver's passphrase never shows on screen.
    Keeps the timeout (getpass has none): a second person who never comes must not hang the gate."""
    try:
        import termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
    except (ImportError, OSError, ValueError, AttributeError):
        return _tty_input(prompt, timeout_s)
    new = termios.tcgetattr(fd)
    new[3] &= ~termios.ECHO
    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, new)
        line = _tty_input(prompt, timeout_s)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
        sys.stdout.write("\n")
        sys.stdout.flush()
    return line


def _full_lines(action: dict) -> list[str]:
    out = []
    for k in CARD_FIELDS:
        v = action.get(k)
        if not _present(v):
            continue
        t = clean(_text(v))
        chunks = [t[i:i + WRAP] for i in range(0, len(t), WRAP)] or [""]
        out.append(f"  {k:<9} {chunks[0]}")
        out += [f"  {'':<9} {c}" for c in chunks[1:]]
    if _present(action.get("body")):
        lines = str(action["body"]).splitlines()
        out.append(f"  body ({len(lines)} lines):")
        out += [f"    | {clean(ln)}" for ln in lines]
    return out


class TerminalApprover:
    collects_second = True        # can ask a second approver for their passphrase (dual control)

    def __init__(self, *, override_delay_s: float = 60, timeout_s: float = 300,
                 input_fn: Callable[[str, float], str | None] = _tty_input,
                 out: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
                 channel: str = "terminal",
                 secret_fn: Callable[[str, float], str | None] = _tty_secret,
                 identity_fn: Callable[[str], dict] = approver_identity):
        self.delay, self.timeout = override_delay_s, timeout_s
        self.input, self.out, self.sleep, self.channel = input_fn, out, sleep, channel
        self.secret, self.identity = secret_fn, identity_fn
        self._lock = threading.Lock()      # one prompt at a time, even with parallel requests

    def _show_card(self, action: dict) -> None:
        for k in CARD_FIELDS:
            v = action.get(k)
            if not _present(v):
                continue
            t = _text(v)
            if len(t) > FIELD_CHARS:
                self.out(f"  {k:<9} {clean(t[:FIELD_CHARS])}")
                self.out(f"            (+{len(t) - FIELD_CHARS} characters not shown)")
            else:
                self.out(f"  {k:<9} {clean(t)}")
        if _present(action.get("body")):
            lines = str(action["body"]).splitlines()
            self.out("  body:")
            for ln in lines[:BODY_LINES]:
                self.out(f"    | {clean(ln)}")
            if len(lines) > BODY_LINES:
                hidden = sum(len(x) + 1 for x in lines[BODY_LINES:])
                self.out(f"    (+{len(lines) - BODY_LINES} more lines, {hidden} characters not shown)")

    def _page_all(self, action: dict, left: Callable[[], float]) -> bool:
        """Show every field in full, PAGE_LINES at a time. False if the time ran out on the way."""
        lines = _full_lines(action)
        self.out("== full content, exactly as it would be sent ==")
        for i in range(0, len(lines), PAGE_LINES):
            for ln in lines[i:i + PAGE_LINES]:
                self.out(ln)
            if i + PAGE_LINES < len(lines):
                more = self.input(f"  -- {i + PAGE_LINES}/{len(lines)} lines shown. enter for more -- ", left())
                if more is None:
                    return False
        self.out("== end of content ==")
        return True

    def ask(self, *, rid: str, action: dict, flagged: bool, review_reason: str, span: str,
            second: list[str] | None = None) -> HumanDecision:
        with self._lock:
            t0 = time.time()
            left = lambda: self.timeout - (time.time() - t0)
            cut = needs_full_view(action)
            seen = False

            def done(decision: str, overrode: bool = False, **kw) -> HumanDecision:
                return HumanDecision(decision, self.channel, round(time.time() - t0, 2), overrode_flag=overrode,
                                     approver=self.identity(self.channel), full_view_required=bool(cut),
                                     full_view_seen=seen, **kw)

            self.out("")
            self.out(f"== approval needed [{rid}] ==")
            self._show_card(action)
            if flagged and review_reason.startswith(NO_MODEL_REASON):
                self.out(f"  -- {clean(review_reason)}")
            elif flagged:
                self.out(f"  !! reviewer FLAGGED this: {clean(review_reason)}")
                if span:
                    self.out(f"  !! suspicious text: {clean(span[:200])}")
            else:
                self.out(f"  reviewer: ok ({clean(review_reason)})")
            if cut:
                self.out(f"  the card cut {', '.join(cut)} short. type v to see all of it; "
                         "you can approve only after that.")

            reminded = False
            while True:
                ans = self.input("approve? [y/N] " if not cut or seen else "approve? [v = view all / N] ", left())
                if ans is None:
                    return done("expired")
                a = ans.strip().lower()
                if a == "v":
                    if not self._page_all(action, left):
                        return done("expired")
                    seen = True
                    continue
                if a not in ("y", "yes"):
                    return done("deny")
                if cut and not seen:
                    if reminded:            # bounded: a second unviewed yes is a no
                        return done("deny")
                    reminded = True
                    self.out("  not yet: part of this was not shown. type v to see all of it first.")
                    continue
                break

            overrode = False
            if flagged:
                phrase = self.input(f"the model flagged this. type '{OVERRIDE_PHRASE}' to continue: ", left())
                if phrase is None:
                    return done("expired")
                if phrase.strip().lower() != OVERRIDE_PHRASE:
                    return done("deny")
                self.out(f"  waiting {self.delay:g}s before the final yes. read it again.")
                self.sleep(self.delay)
                final = self.input("still send it? [y/N] ", left())
                if final is None:
                    return done("expired")
                if final.lower() not in ("y", "yes"):
                    return done("deny")
                overrode = True

            if second is None:
                return done("approve", overrode)
            # Dual control: the first yes is in. A second, named person confirms with a passphrase only
            # they know. They get a fresh window (they may have to walk over); silence is expired.
            t1 = time.time()
            left2 = lambda: self.timeout - (time.time() - t1)
            self.out(f"  dual control: a second approver must confirm. registered: {', '.join(second)}")
            name = self.input("second approver name: ", left2())
            if name is None:
                return done("expired", overrode)
            secret = self.secret("their passphrase (not shown): ", left2())
            if secret is None:
                return done("expired", overrode)
            return done("approve", overrode, second_name=name.strip(), second_secret=secret)
