"""The web demo's approver: the human half of the gate, answered from a browser page.

DEMO ONLY. The product's rule is that approval happens in the terminal the gate was started in
and nowhere else; there is no approve endpoint on the network (src/homestead_gate/approval.py).
This class exists only under demo/web, and nothing in src/homestead_gate imports it.

It keeps the product's other rules:
- fails closed: no answer before the timeout is "expired", which the gate never executes; an
  unknown or already-answered request id changes nothing.
- override friction: approving something the reviewer flagged needs the typed phrase
  "send anyway", and is refused until a wait has passed since the card was shown. The receipt
  records overrode_flag.
- receipts say where the yes came from: channel "web-demo", never "terminal".
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from homestead_gate.approval import OVERRIDE_PHRASE, HumanDecision

CHANNEL = "web-demo"


@dataclass
class _Pending:
    rid: str
    flagged: bool
    shown_at: float
    done: threading.Event = field(default_factory=threading.Event)
    decision: str | None = None
    overrode: bool = False


class WebApprover:
    def __init__(self, *, timeout_s: float = 180, override_delay_s: float = 10,
                 on_ask: Callable[[dict], None] = lambda card: None,
                 clock: Callable[[], float] = time.monotonic):
        self.timeout_s, self.override_delay_s = timeout_s, override_delay_s
        self.on_ask, self.clock = on_ask, clock
        self._lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}
        self._closed = False

    # -- the gate's side
    def ask(self, *, rid: str, action: dict, flagged: bool, review_reason: str, span: str,
            context: dict | None = None) -> HumanDecision:
        t0 = time.time()
        p = _Pending(rid=rid, flagged=bool(flagged), shown_at=self.clock())
        with self._lock:
            if self._closed:
                return HumanDecision("deny", CHANNEL, 0.0)
            self._pending[rid] = p
        try:
            self.on_ask({"rid": rid, "action": action, "flagged": bool(flagged),
                         "review_reason": review_reason, "span": span,
                         # untrusted web text about an unknown recipient, for the human's card only
                         "web_lookup": (context or {}).get("web_lookup"),
                         "timeout_s": self.timeout_s, "deadline": time.time() + self.timeout_s,
                         "override_delay_s": self.override_delay_s if flagged else 0})
        except Exception:  # noqa: BLE001 - a broken page must not turn into a yes
            pass
        answered = p.done.wait(self.timeout_s)
        with self._lock:
            self._pending.pop(rid, None)
            decision = p.decision if answered else None
        latency = round(time.time() - t0, 2)
        if decision is None:
            return HumanDecision("expired", CHANNEL, latency)
        return HumanDecision(decision, CHANNEL, latency, overrode_flag=p.overrode and decision == "approve")

    # -- the page's side
    def decide(self, rid: str, decision: str, phrase: str = "") -> tuple[bool, str]:
        """Answer a waiting card. Returns (accepted, message). Anything not understood is refused
        and leaves the card waiting, so it can only end in a clear yes, a no, or the timeout."""
        with self._lock:
            p = self._pending.get(str(rid))
            if p is None or p.done.is_set():
                return False, "no approval is waiting with that id"
            if decision == "deny":
                p.decision = "deny"
                p.done.set()
                return True, "denied"
            if decision != "approve":
                return False, "decision must be approve or deny"
            if p.flagged:
                if str(phrase).strip().lower() != OVERRIDE_PHRASE:
                    return False, f"the reviewer flagged this. type '{OVERRIDE_PHRASE}' to approve it"
                left = self.override_delay_s - (self.clock() - p.shown_at)
                if left > 0:
                    return False, f"wait {left:.0f}s more and read it again"
                p.overrode = True
            p.decision = "approve"
            p.done.set()
            return True, "approved"

    def pending(self) -> list[str]:
        with self._lock:
            return list(self._pending)

    def close(self) -> None:
        """Session ending: every waiting card resolves to deny so no run thread hangs."""
        with self._lock:
            self._closed = True
            for p in self._pending.values():
                if not p.done.is_set():
                    p.decision = "deny"
                    p.done.set()
