"""Deterministic policy: runs before the model, and some of it cannot be overridden.

Three outcomes per request:
  deny   a hard rule the human set in advance (wrong chain, value over cap, too many
         actions this hour). Nobody is asked; asking would invite approval fatigue on
         exactly the requests the human already decided about.
  auto   send-to-self. Harmless by construction, and keeping it silent is what keeps
         prompts rare enough that the human still reads them.
  review everything else: the local model reviews it, and the human decides unless the
         destination is allowlisted AND the model approves.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import tomllib
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

SEPOLIA = 11155111


SPEND_WORDS = re.compile(r"\b(pay|pays|paid|payment|payments|invoices?|bills?|tip|tips|reimburse\w*|refund\w*|transfer\w*|wire|settle)\b|\bsend\b[^.\n]{0,40}(\$\s?\d|\d[\d.,]*\s?(eth|usdc|usdt|usd|dollars?|cad)\b)", re.I)


@dataclass
class Policy:
    user_email: str = ""
    user_wallet: str = ""
    email_allow: list[str] = field(default_factory=list)
    evm_allow: list[str] = field(default_factory=list)
    chain_id: int = SEPOLIA
    max_value_eth: float = 0.05
    max_calldata_bytes: int = 256
    # Vitalik, "My self-sovereign / local / private / secure LLM setup" (2026-04-02): autonomous wallet
    # spending capped at about $100/day; anything above, or any tx carrying calldata, needs a human.
    # 0.035 ETH is ~$100 at ~$2.7k/ETH (2026-09-30). Set it in ETH; the gate never fetches a price.
    daily_auto_value_eth: float = 0.035
    max_actions_per_hour: int = 20
    model: str = "qwen3.5:9b"
    ollama_url: str = "http://127.0.0.1:11434"
    review_timeout_s: float = 120
    review_think: bool = False       # [review] think = true: the reviewer reasons first (slower, fewer false blocks)
    override_delay_s: float = 60
    approval_timeout_s: float = 300
    _recent: deque = field(default_factory=deque, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _auto_spent: deque = field(default_factory=deque, repr=False)   # (time, eth) auto-approved in 24h

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        d = tomllib.loads(Path(path).read_text())
        u, e, v = d.get("user", {}), d.get("email", {}), d.get("evm", {})
        lim, rv, ap = d.get("limits", {}), d.get("review", {}), d.get("approval", {})
        p = cls(
            user_email=u.get("email", ""), user_wallet=u.get("wallet", ""),
            email_allow=list(e.get("allow", [])), evm_allow=list(v.get("allow", [])),
            chain_id=int(v.get("chain_id", SEPOLIA)),
            max_value_eth=float(v.get("max_value_eth", 0.05)),
            max_calldata_bytes=int(v.get("max_calldata_bytes", 256)),
            daily_auto_value_eth=float(v.get("daily_auto_value_eth", 0.035)),
            max_actions_per_hour=int(lim.get("max_actions_per_hour", 20)),
            model=rv.get("model", "qwen3.5:9b"), ollama_url=rv.get("ollama_url", "http://127.0.0.1:11434"),
            review_timeout_s=float(rv.get("timeout_s", 120)), review_think=bool(rv.get("think", False)),
            override_delay_s=float(ap.get("override_delay_s", 60)),
            approval_timeout_s=float(ap.get("timeout_s", 300)),
        )
        if p.chain_id != SEPOLIA:
            # v1 is testnet only. Refusing to load beats a mainnet transaction nobody meant.
            raise ValueError(f"chain_id {p.chain_id} refused: v1 supports Sepolia ({SEPOLIA}) only")
        return p

    @property
    def version(self) -> str:
        """Short hash of every rule. Recorded with each decision so an approval given under one
        set of rules is never mistaken for one given under another (u/arthaudm, 2026-09-30:
        "include the policy version so a changed rule can't reuse an old approval")."""
        rules = {k: v for k, v in sorted(vars(self).items()) if not k.startswith("_")}
        return hashlib.sha256(json.dumps(rules, sort_keys=True, default=str).encode()).hexdigest()[:16]

    @property
    def identity(self) -> str:
        bits = [self.user_email] + ([f"own wallet {self.user_wallet}"] if self.user_wallet else [])
        return ", ".join(b for b in bits if b)

    def known_contacts(self) -> list[str]:
        return self.email_allow + self.evm_allow

    def is_self(self, action: dict) -> bool:
        to = (action.get("to") or "").lower()
        return bool(to) and to in {self.user_email.lower(), self.user_wallet.lower()} - {""}

    def is_allowlisted(self, action: dict) -> bool:
        to = (action.get("to") or "").lower()
        pool = self.email_allow if action.get("type") == "email" else self.evm_allow
        return to in {a.lower() for a in pool}

    def auto_spent_today(self, now: float | None = None) -> float:
        now = time.time() if now is None else now
        with self._lock:
            while self._auto_spent and now - self._auto_spent[0][0] > 86400:
                self._auto_spent.popleft()
            return sum(v for _, v in self._auto_spent)

    @staticmethod
    def task_asks_to_spend(task: str | None) -> bool:
        """Whether the user's own request asks for money to move. Deterministic on purpose: in a demo
        run (2026-10-01) the task was 'reply to anything that needs an answer', the agent paid an
        invoice anyway, and the model approved it. A request that never mentions paying can't
        authorise spending on its own, so such a payment always goes to the human."""
        return bool(SPEND_WORDS.search(task or ""))

    def may_auto(self, action: dict, now: float | None = None) -> tuple[bool, str]:
        """Whether an allowlisted action the model approved may go without a human (the 2-of-2's
        policy half standing in for the human). Wallet rules follow Vitalik's April 2026 setup."""
        if action.get("type") != "wallet_tx":
            return True, "allowlisted and the model approved"
        data = str(action.get("data") or "").removeprefix("0x")
        if data:
            return False, "carries calldata, which always needs a human"
        value = float(action.get("value_eth", 0) or 0)
        spent = self.auto_spent_today(now)
        if spent + value > self.daily_auto_value_eth:
            return False, (f"would take autonomous spending to {spent + value:g} ETH today, "
                           f"over the {self.daily_auto_value_eth:g} ETH daily limit")
        return True, "allowlisted, the model approved, within the daily autonomous limit"

    def record_auto(self, action: dict, now: float | None = None) -> None:
        if action.get("type") == "wallet_tx":
            with self._lock:
                self._auto_spent.append((time.time() if now is None else now,
                                         float(action.get("value_eth", 0) or 0)))

    def check(self, action: dict, now: float | None = None) -> tuple[str, str]:
        """Return (outcome, reason). Counts the action against the hourly cap."""
        now = time.time() if now is None else now
        with self._lock:      # the daemon handles requests on parallel threads
            while self._recent and now - self._recent[0] > 3600:
                self._recent.popleft()
            if len(self._recent) >= self.max_actions_per_hour:
                return "deny", f"over {self.max_actions_per_hour} actions this hour"
            self._recent.append(now)

        kind = action.get("type")
        if kind not in ("email", "wallet_tx"):
            return "deny", f"unsupported action type {kind!r}"
        if not action.get("to"):
            return "deny", "no recipient"
        if kind == "wallet_tx":
            if int(action.get("chain_id", SEPOLIA)) != self.chain_id:
                return "deny", f"chain {action.get('chain_id')} is not the allowed chain {self.chain_id}"
            if float(action.get("value_eth", 0) or 0) > self.max_value_eth:
                return "deny", f"value over the {self.max_value_eth} ETH cap"
            data = str(action.get("data") or "")
            nbytes = max(0, len(data.removeprefix("0x")) // 2)
            if nbytes > self.max_calldata_bytes:
                # Vitalik's exfiltration point: calldata is a covert channel out.
                return "deny", f"calldata {nbytes} bytes over the {self.max_calldata_bytes} byte cap"
        if self.is_self(action):
            return "auto", "send to self"
        return "review", "not to self"
