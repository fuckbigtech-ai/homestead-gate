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
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
# Settings that are not rules about actions, so they stay out of `version`: the [receipts] anchors,
# and the [lookup] switch, whose text goes only to the human and never changes a decision. Changing
# them must not invalidate approvals or payload hashes (the policy receipt's file hash still moves).
_NOT_RULES = frozenset({"anchor_dir", "anchor_command", "lookup_tavily", "receipt_calldata"})


# How rules and actions are hashed. 1: Python's repr of whatever types arrived (TOML gave floats where the
# code's defaults are ints, so the same rules had two versions; 1 and 1.0 gave two fingerprints).
# 2 (2026-10-05): numbers canonical (integral floats become ints) in Policy.version and in the payload
# fingerprint, plus addresses and calldata canonical in the fingerprint (core.canonical_action).
# Recorded as `hash_scheme` in policy receipts and on gate records, so an auditor knows which to recompute.
HASH_SCHEME = 2


def canonical_numbers(x):
    """1.0 -> 1, recursively through dicts and lists. bools, ints, non-integral floats (0.05) and
    everything else are unchanged, so most rules and actions hash exactly as before."""
    if isinstance(x, bool):
        return x
    if isinstance(x, float):
        return int(x) if x.is_integer() else x
    if isinstance(x, dict):
        return {k: canonical_numbers(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [canonical_numbers(v) for v in x]
    return x


SPEND_WORDS = re.compile(r"\b(pay|pays|paid|payment|payments|invoices?|bills?|tip|tips|reimburse\w*|refund\w*|transfer\w*|wire|settle)\b|\bsend\b[^.\n]{0,40}(\$\s?\d|\d[\d.,]*\s?(eth|usdc|usdt|usd|dollars?|cad)\b)", re.I)


def _dual_control(ap: dict) -> list[str]:
    kinds = ap.get("dual_control", [])
    if isinstance(kinds, str) or not isinstance(kinds, list) or not all(isinstance(k, str) for k in kinds):
        raise ValueError("[approval] dual_control must be a list of action types, e.g. [\"wallet_tx\"]")
    out = sorted(set(kinds))
    if bool(ap.get("second_approver", False)):
        out = ["*"]
    return out


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
    # [review] digest / manifest_digest: the exact reviewer model file (weights blob) and Ollama manifest,
    # written by `homestead-gate reviewer pin`. Both are rules, so once set both are in `version`: an
    # approval given under one model file is never mistaken for one given under another. Unset, they
    # stay out of it, so a policy that was never pinned keeps its earlier version.
    review_digest: str = ""
    review_manifest_digest: str = ""
    override_delay_s: float = 60
    approval_timeout_s: float = 300
    # [lookup] tavily = true: web lookup of unknown recipients, shown to the human only (lookup.py).
    # Also needs the key in the OS credential store. Off by default.
    lookup_tavily: bool = False
    # Dual control: action types that need a second, named approver's passphrase after the first yes.
    # [approval] second_approver = true means every type; dual_control = ["wallet_tx"] names some.
    dual_control: list[str] = field(default_factory=list)
    # [receipts]: where checkpoints are anchored off this machine. Not rules about actions, so they
    # are left out of `version` (an anchor change must not invalidate approvals or payload hashes).
    anchor_dir: str = ""
    anchor_command: str = ""
    # [receipts] record_calldata = true: keep an executed transaction's calldata in the receipt. Off by
    # default: the receipt carries its sha256 and length only (action content by fingerprint, not text).
    receipt_calldata: bool = False
    # Where this policy came from and the sha256 of the exact bytes parsed. Underscored, so the rule
    # hash (version) does not move when only the comments in the file change; the receipts carry both.
    _path: Path | None = field(default=None, repr=False)
    _file_sha256: str | None = field(default=None, repr=False)
    _recent: deque = field(default_factory=deque, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _auto_spent: deque = field(default_factory=deque, repr=False)   # (time, eth) auto-approved in 24h

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        raw = Path(path).read_bytes()
        d = tomllib.loads(raw.decode())
        u, e, v = d.get("user", {}), d.get("email", {}), d.get("evm", {})
        lim, rv, ap = d.get("limits", {}), d.get("review", {}), d.get("approval", {})
        lk = d.get("lookup", {})
        rc = d.get("receipts", {})
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
            review_digest=str(rv.get("digest", "")), review_manifest_digest=str(rv.get("manifest_digest", "")),
            override_delay_s=float(ap.get("override_delay_s", 60)),
            approval_timeout_s=float(ap.get("timeout_s", 300)),
            lookup_tavily=lk.get("tavily", False) is True,
            dual_control=_dual_control(ap),
            _path=Path(path).expanduser().resolve(), _file_sha256=hashlib.sha256(raw).hexdigest(),
            anchor_dir=str(rc.get("anchor_dir", "")), anchor_command=str(rc.get("anchor_command", "")),
            receipt_calldata=rc.get("record_calldata", False) is True,
        )
        for key, val in (("digest", p.review_digest), ("manifest_digest", p.review_manifest_digest)):
            if val and not DIGEST_RE.fullmatch(val):
                raise ValueError(f"[review] {key} {val!r} is not sha256:<64 hex>; re-pin with "
                                 "`homestead-gate reviewer pin`")
        if p.chain_id != SEPOLIA:
            # v1 is testnet only. Refusing to load beats a mainnet transaction nobody meant.
            raise ValueError(f"chain_id {p.chain_id} refused: v1 supports Sepolia ({SEPOLIA}) only")
        return p

    @property
    def version(self) -> str:
        """Short hash of every rule. Recorded with each decision so an approval given under one
        set of rules is never mistaken for one given under another (u/arthaudm, 2026-09-30:
        "include the policy version so a changed rule can't reuse an old approval")."""
        rules = {k: v for k, v in sorted(vars(self).items()) if not k.startswith("_") and k not in _NOT_RULES}
        # Rules added later enter the hash only once they are set, so a policy that does not use them
        # keeps the version it had before they existed (and old receipts and payload hashes still match).
        for k in ("dual_control", "review_digest", "review_manifest_digest"):
            if not rules[k]:
                del rules[k]
        # Hash scheme 2: integral floats as ints, so a policy loaded from TOML (timeout_s = 120 -> 120.0)
        # has the same version as the same rules built in code (120). Code-built versions did not move.
        rules = canonical_numbers(rules)
        return hashlib.sha256(json.dumps(rules, sort_keys=True, default=str).encode()).hexdigest()[:16]

    @property
    def file_sha256(self) -> str | None:
        """sha256 of the policy file as loaded; None for a policy built in code (tests, demos)."""
        return self._file_sha256

    @property
    def path(self) -> Path | None:
        return self._path

    @property
    def approvers_dir(self) -> Path | None:
        """Where `homestead-gate approver add` keeps the second approvers: next to the policy file."""
        return self._path.parent if self._path else None

    def requires_dual_control(self, action: dict) -> bool:
        return "*" in self.dual_control or action.get("type") in self.dual_control

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
