"""Web lookup of an unknown recipient (optional, Tavily), shown to the HUMAN on the approval card.

When an action comes to you and its recipient is not a known contact, the gate can ask Tavily what
the web says about the recipient's domain (email) or address (wallet), so you decide with context.

The trust rule. What comes back is UNTRUSTED web text, written by whoever ranks for that domain,
possibly the attacker. So:
  - it is shown only to the human, on the approval card (terminal or web demo);
  - it is NEVER put into the reviewer model's prompt (the lookup runs after the review, and nothing
    here feeds back into render()), never returned to the agent, and never changes policy or the
    verdict. The gate's decision is exactly what it would be without it;
  - the ledger records that a lookup happened (target, number of results, ok or not), never the text.

What goes to Tavily: the registrable domain of the email recipient (example.com, never the local
part, subject, body or your name) or the wallet address, inside a fixed query. Nothing else. A `to`
that does not parse as one clean address or 0x wallet sends nothing.

Off unless configured: policy `[lookup] tavily = true` and a key in the OS credential store
(service "tavily-api-key"). Off, no key, a timeout or any error: the card says "web lookup
unavailable" and nothing else changes. It never blocks or approves anything.
"""
from __future__ import annotations

import json
import re
import threading
import unicodedata
import urllib.request
from dataclasses import dataclass, field
from email.utils import parseaddr
from typing import Callable

API_URL = "https://api.tavily.com/search"
TIMEOUT_S = 6.0
MAX_RESULTS = 3
SNIPPET_CHARS = 200
TITLE_CHARS = 100
URL_CHARS = 120
MAX_RESPONSE_BYTES = 256 * 1024

# One registrable host: lowercase labels, at least one dot, 253 chars or fewer, nothing else.
_HOST = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_WALLET = re.compile(r"^0x[0-9a-fA-F]{40}$")
# second-level labels under a two-letter country code that are not the registrable name (co.uk)
_SECOND_LEVEL = {"co", "com", "net", "org", "ac", "gov", "edu", "ne", "or", "go"}

# transport(url, body, headers, timeout) -> response bytes. Injected in tests; never the real API there.
Transport = Callable[[str, bytes, dict, float], bytes]


def _urllib_transport(url: str, body: bytes, headers: dict, timeout: float) -> bytes:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 - fixed https URL
        return r.read(MAX_RESPONSE_BYTES + 1)


def registrable(host: str) -> str:
    """example.com from mail.eu.example.com; example.co.uk from x.example.co.uk. A subdomain is
    agent-chosen text, so it never leaves the machine."""
    labels = host.split(".")
    keep = 3 if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL else 2
    return ".".join(labels[-keep:])


def target_of(action: dict) -> tuple[str, str] | None:
    """("domain", "example.com") or ("wallet", "0x..."), or None if `to` is not exactly one clean
    recipient. Nothing is sent for None."""
    to = str(action.get("to") or "").strip()
    if action.get("type") == "wallet_tx":
        return ("wallet", to.lower()) if _WALLET.match(to) else None
    if action.get("type") != "email" or "," in to or ";" in to:
        return None
    name, addr = parseaddr(to)
    # parseaddr repairs input ("a@exa mple.com" -> a@example.com); only an address written verbatim counts
    if not addr or addr.count("@") != 1 or addr not in to:
        return None
    host = addr.rsplit("@", 1)[1].lower().rstrip(".")
    if not _HOST.match(host):
        return None
    return "domain", registrable(host)


def is_known(action: dict, policy) -> bool:
    """Known contacts are never looked up: yourself, your allowlist (which includes the contacts you
    wrote into memory), or an email domain that is yours or one of theirs."""
    if policy.is_self(action) or policy.is_allowlisted(action):
        return True
    if action.get("type") != "email":
        return False
    t = target_of(action)
    if t is None:
        return False
    mine = [policy.user_email] + list(policy.email_allow)
    domains = {registrable(a.rsplit("@", 1)[1].lower()) for a in mine if a and "@" in a}
    return t[1] in domains


def query_for(target: str) -> str:
    return f'"{target}" scam OR phishing OR company'


def sanitize(value, cap: int) -> str:
    """One line of plain text: control and format characters dropped (ANSI, bidi overrides),
    every run of whitespace (newlines included) collapsed to one space, then capped. A newline in a
    snippet could otherwise forge a line of the gate's own card."""
    s = "".join(" " if c.isspace() else c for c in str(value or "")
                if c.isspace() or unicodedata.category(c) not in ("Cc", "Cf", "Co", "Cs"))
    s = " ".join(s.split())
    return s if len(s) <= cap else s[:cap - 3].rstrip() + "..."


def _safe_url(value) -> str:
    u = sanitize(value, 2000)
    if not re.match(r"^https?://[^\s]+$", u, re.I):
        return ""
    return u if len(u) <= URL_CHARS else u[:URL_CHARS - 3] + "..."


@dataclass
class LookupResult:
    kind: str                 # domain | wallet
    target: str
    ok: bool
    results: list[dict] = field(default_factory=list)    # [{"title", "url", "snippet"}], sanitized
    reason: str = ""          # why unavailable: "not configured", "timed out", "error (HTTPError)"

    def card(self) -> dict:
        """What the approval card shows. Untrusted text, for the human only."""
        return {"kind": self.kind, "target": self.target, "ok": self.ok,
                "results": [dict(r) for r in self.results], "reason": self.reason,
                "label": (f"What the web says about {self.target}" if self.ok
                          else f"web lookup unavailable ({self.reason})"),
                "warning": "Untrusted web text. Shown to you only; the reviewer never sees it."}

    def receipt(self) -> dict:
        """What the ledger keeps: that it happened, never the text."""
        return {"lookup_kind": self.kind, "lookup_target": self.target, "lookup_ok": self.ok,
                "lookup_results": len(self.results),
                **({"lookup_error": self.reason} if not self.ok else {})}


def unavailable(kind: str, target: str, reason: str) -> LookupResult:
    return LookupResult(kind, target, False, [], reason)


class TavilyLookup:
    """Tavily search for one domain or address. Never raises: any failure is a LookupResult with
    ok=False. The key is held here and sent only as the Authorization header."""

    def __init__(self, api_key: str, *, transport: Transport | None = None, timeout_s: float = TIMEOUT_S,
                 max_results: int = MAX_RESULTS):
        self._key, self.timeout_s, self.max_results = api_key, timeout_s, max_results
        self.transport = transport or _urllib_transport

    def __repr__(self) -> str:                      # never print the key
        return f"TavilyLookup(timeout_s={self.timeout_s})"

    def search(self, kind: str, target: str) -> LookupResult:
        body = json.dumps({"query": query_for(target), "search_depth": "basic",
                           "max_results": self.max_results, "include_answer": False,
                           "include_raw_content": False, "include_images": False}).encode()
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self._key}"}
        box: dict = {}

        def call():
            try:
                box["raw"] = self.transport(API_URL, body, headers, self.timeout_s)
            except BaseException as e:  # noqa: BLE001 - reported as unavailable, never raised
                box["err"] = e
        # urllib's timeout does not bound DNS resolution; a daemon thread and join() does.
        th = threading.Thread(target=call, daemon=True)
        th.start()
        th.join(self.timeout_s)
        if th.is_alive():
            return unavailable(kind, target, "timed out")
        if "err" in box:
            e = box["err"]
            return unavailable(kind, target, "timed out" if isinstance(e, TimeoutError)
                               else f"error ({type(e).__name__})")
        try:
            raw = box.get("raw") or b""
            if len(raw) > MAX_RESPONSE_BYTES:
                return unavailable(kind, target, "error (response too large)")
            data = json.loads(raw)
            items = data.get("results") if isinstance(data, dict) else None
            if not isinstance(items, list):
                return unavailable(kind, target, "error (unexpected response)")
        except Exception as e:  # noqa: BLE001
            return unavailable(kind, target, f"error ({type(e).__name__})")
        out = []
        for it in items:
            if not isinstance(it, dict):
                continue
            url = _safe_url(it.get("url"))
            if not url:
                continue
            out.append({"title": sanitize(it.get("title"), TITLE_CHARS), "url": url,
                        "snippet": sanitize(it.get("content"), SNIPPET_CHARS)})
            if len(out) >= self.max_results:
                break
        return LookupResult(kind, target, True, out)


def from_policy(policy) -> TavilyLookup | None:
    """The lookup for the CLI, or None (off). Needs `[lookup] tavily = true` AND a key in the OS
    credential store. The key is read once, here, not per request."""
    if not getattr(policy, "lookup_tavily", False):
        return None
    from . import credstore
    try:
        key = credstore.load_tavily_key()
    except credstore.CredentialError:
        return None
    return TavilyLookup(key) if key else None


def from_env(environ) -> TavilyLookup | None:
    """The lookup for the web demo (and its Modal secret): on only if TAVILY_API_KEY is set."""
    key = (environ.get("TAVILY_API_KEY") or "").strip()
    return TavilyLookup(key) if key else None
