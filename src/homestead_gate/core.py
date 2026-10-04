"""One request through the gate: policy, local model, human, receipt, and only then action.

Ordering is the product. Every decision is appended to the homestead-memory ledger with
phase=pre_execution, and that append is fsynced, before any adapter runs. So the record
shows a denial was ENFORCED, not merely noted afterwards; a crash between decision and
send leaves a decision with no execution record, never the reverse.

What the agent sends is only the action and what it says it read. Anything else in the
request (a "user_intent", an "approved": true) is ignored. The user's intent is the task
the human gave when starting the gate, because a hijacked agent would lie about it.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import uuid
from pathlib import Path
from typing import Protocol

from homestead_memory.core import ledger

from . import adapters
from . import lookup as web_lookup
from .approval import HumanDecision
from .policy import Policy
from .reviewer import Verdict, render

AGENT = "homestead-gate"


class Reviewer(Protocol):
    def review(self, prompt: str) -> Verdict: ...


class Approver(Protocol):
    # context (optional): extra information for the human's eyes only, e.g. {"web_lookup": {...}}.
    # An approver written before it existed simply does not take it, and the gate does not pass it.
    def ask(self, *, rid: str, action: dict, flagged: bool, review_reason: str, span: str,
            context: dict | None = None) -> HumanDecision: ...


def _takes_context(fn) -> bool:
    """Checked from the signature, never by calling and catching TypeError: a TypeError from inside
    ask() must not get the human asked twice."""
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == "context" or p.kind is p.VAR_KEYWORD for p in params)


# The fields that decide what an action DOES, chosen by code per type, never by the model.
# Anything else in the request (notes, timestamps, the agent's commentary) cannot change the
# fingerprint, and anything here that changes produces a different one.
TYPED_FIELDS = {
    "email": ("type", "to", "cc", "bcc", "subject", "body", "attachments"),
    "wallet_tx": ("type", "chain_id", "to", "value_eth", "data"),
}


def typed_action(action: dict) -> dict:
    fields = TYPED_FIELDS.get(action.get("type"), tuple(sorted(action)))
    return {k: action.get(k) for k in fields}


def payload_hash(action: dict, policy_version: str = "") -> str:
    body = {"action": typed_action(action), "policy_version": policy_version}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def describe(action: dict) -> str:
    """Ledger summary line. Recipient and size only; the body stays out of the log."""
    if action.get("type") == "wallet_tx":
        return f"tx {action.get('value_eth', 0)} ETH -> {action.get('to')}"
    return f"email -> {action.get('to')}"


class Gate:
    def __init__(self, *, policy: Policy, reviewer: Reviewer, approver: Approver, ledger_dir: Path,
                 task: str, session: str, outbox: Path, smtp: dict | None = None, live: bool = False,
                 lookup: "web_lookup.TavilyLookup | None" = None):
        self.policy, self.reviewer, self.approver = policy, reviewer, approver
        # Optional web lookup of unknown recipients (lookup.py). None means off. Its results are
        # for the human only; see _recipient_context.
        self.lookup = lookup
        self._lookup_cache: dict[tuple[str, str], web_lookup.LookupResult] = {}   # per target, per session
        self.ledger_dir, self.task, self.session = Path(ledger_dir), task, session
        self.outbox, self.smtp, self.live = Path(outbox), smtp, live
        # payload hashes refused in this session (denied, blocked or unanswered). An identical retry is
        # refused by policy without a second review or a second question: on AgentDojo the one attack
        # that got past the thinking 4B was the sixth identical retry of a call it had blocked five times.
        self.refused: set[str] = set()

    def _log(self, action: str, summary: str, meta: dict, phase: str, target: str) -> None:
        ledger.append(action, target=target, summary=summary, meta=meta, vault=self.ledger_dir,
                      agent=AGENT, session=self.session, phase=phase)

    def _recipient_context(self, action: dict, pre) -> dict | None:
        """What the web says about an unknown recipient, for the approval card. None for a known contact.

        TRUST RULE: this is untrusted web text. It goes ONLY to the human (approver.ask's context).
        It is computed after the reviewer has answered and is never passed to render() or the
        reviewer, never returned from submit() (so the agent never sees it), and never changes the
        policy outcome or the verdict. Only the domain or wallet address is sent to Tavily. The
        ledger records that a lookup happened, not what it said."""
        if web_lookup.is_known(action, self.policy):
            return None
        t = web_lookup.target_of(action)
        kind, target = t if t else ("domain" if action.get("type") == "email" else "wallet", "")
        if self.lookup is None:
            return {"web_lookup": web_lookup.unavailable(kind, target, "not configured").card()}
        if t is None:
            return {"web_lookup": web_lookup.unavailable(kind, target,
                                                         "recipient is not one clean address").card()}
        res = self._lookup_cache.get(t)
        if res is None:
            try:
                res = self.lookup.search(kind, target)
            except Exception as e:  # noqa: BLE001 - search() never raises; fail safe regardless
                res = web_lookup.unavailable(kind, target, f"error ({type(e).__name__})")
            if res.ok:
                self._lookup_cache[t] = res      # a success is reused this session; a failure is retried
            pre("gate.lookup", f"web lookup {kind} {target}: " + (
                f"{len(res.results)} results" if res.ok else "unavailable"), **res.receipt())
        return {"web_lookup": res.card()}

    def _ask(self, context: dict | None, **kw) -> HumanDecision:
        if context is not None and _takes_context(self.approver.ask):
            return self.approver.ask(**kw, context=context)
        return self.approver.ask(**kw)

    def submit(self, request: dict) -> dict:
        action = dict(request.get("action") or {})
        reads = request.get("read") or []
        rid = uuid.uuid4().hex[:10]
        target = f"gate:{action.get('type', '?')}"
        pv = self.policy.version
        base = {"request_id": rid, "payload_sha256": payload_hash(action, pv), "policy_version": pv}
        pre = lambda a, s, **m: self._log(a, s, {**base, **m}, ledger.PHASE_PRE, target)
        post = lambda a, s, **m: self._log(a, s, {**base, **m}, ledger.PHASE_POST, target)

        pre("gate.request", f"request {describe(action)}", to=action.get("to"),
            read_sources=[str(r.get("source", "?")) for r in reads])

        if base["payload_sha256"] in self.refused:
            why = "the same action was already refused in this session"
            pre("gate.decision", f"policy:deny {why}", decided_by="policy", decision="deny")
            post("gate.denied", "not executed", reason=why)
            return {"id": rid, "status": "denied", "by": "policy", "reason": why}

        outcome, why = self.policy.check(action)
        if outcome == "deny":
            self.refused.add(base["payload_sha256"])
            pre("gate.decision", f"policy:deny {why}", decided_by="policy", decision="deny")
            post("gate.denied", "not executed", reason=why)
            return {"id": rid, "status": "denied", "by": "policy", "reason": why}

        verdict = None
        if outcome == "auto":
            decided_by, decision, reason = "policy", "approve", why
        else:
            prompt = render(
                user_identity=self.policy.identity or None, user_intent=self.task,
                known_contacts=self.policy.known_contacts(),
                untrusted_source=", ".join(str(r.get("source", "?")) for r in reads) or "nothing",
                untrusted_content="\n---\n".join(str(r.get("content", "")) for r in reads),
                action=action)
            verdict = self.reviewer.review(prompt)
            # llm:approve | llm:block | llm:invalid. "invalid" means the model did not review it
            # (missing, unreachable, no clear answer); the log must not call that a review.
            # The model's reason is kept out: it can quote the body, and the body stays out.
            pre("gate.review", f"llm:{verdict.verdict}", model=verdict.model,
                verdict=verdict.verdict, secs=verdict.secs)
            auto_ok, auto_why = (self.policy.may_auto(action) if not verdict.flagged
                                 and self.policy.is_allowlisted(action) else (False, ""))
            if auto_ok and action.get("type") in ("wallet_tx", "payment") \
                    and not self.policy.task_asks_to_spend(self.task):
                auto_ok = False                      # the user's request never asked for money to move
            if auto_ok:
                decided_by, decision, reason = "policy", "approve", auto_why
                self.policy.record_auto(action)
            else:
                # The review above is finished; the lookup cannot reach it (see _recipient_context).
                context = self._recipient_context(action, pre)
                h = self._ask(context, rid=rid, action=action, flagged=verdict.flagged,
                              review_reason=verdict.reason, span=verdict.span)
                decided_by, decision, reason = f"human:{h.channel}", h.decision, (
                    "overrode the model's flag" if h.overrode_flag else f"human {h.decision}")
                pre("gate.decision", f"human:{h.decision}" + (" (overrode flag)" if h.overrode_flag else ""),
                    decided_by=decided_by, decision=h.decision, channel=h.channel,
                    latency_s=h.latency_s, overrode_flag=h.overrode_flag)

        if decided_by == "policy":
            pre("gate.decision", f"policy:{decision} {reason}", decided_by="policy", decision=decision)

        if decision != "approve":
            self.refused.add(base["payload_sha256"])
            kind = "gate.expired" if decision == "expired" else "gate.denied"
            post(kind, "not executed", reason=reason)
            return {"id": rid, "status": "expired" if decision == "expired" else "denied",
                    "by": decided_by, "reason": reason,
                    "review": verdict.verdict if verdict else None}

        # Both yeses (or a policy auto-allow) are on disk. Only now does anything happen.
        try:
            if action["type"] == "email":
                result = adapters.send_email(action, sender=self.policy.user_email or "gate@localhost",
                                             outbox=self.outbox, smtp=self.smtp, live=self.live)
            else:
                result = adapters.prepare_tx(action)
        except Exception as e:  # noqa: BLE001 - any adapter failure is recorded, never swallowed
            post("gate.failed", f"approved but failed: {type(e).__name__}", error=str(e)[:300])
            return {"id": rid, "status": "failed", "error": str(e)}
        post("gate.executed", "executed" + (" (dry run)" if result.get("dry_run") else ""), result=result)
        return {"id": rid, "status": "executed", "by": decided_by, "result": result}
