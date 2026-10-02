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
import json
import uuid
from pathlib import Path
from typing import Protocol

from homestead_memory.core import ledger

from . import adapters
from .approval import HumanDecision
from .policy import Policy
from .reviewer import Verdict, render

AGENT = "homestead-gate"


class Reviewer(Protocol):
    def review(self, prompt: str) -> Verdict: ...


class Approver(Protocol):
    def ask(self, *, rid: str, action: dict, flagged: bool, review_reason: str, span: str) -> HumanDecision: ...


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
                 task: str, session: str, outbox: Path, smtp: dict | None = None, live: bool = False):
        self.policy, self.reviewer, self.approver = policy, reviewer, approver
        self.ledger_dir, self.task, self.session = Path(ledger_dir), task, session
        self.outbox, self.smtp, self.live = Path(outbox), smtp, live

    def _log(self, action: str, summary: str, meta: dict, phase: str, target: str) -> None:
        ledger.append(action, target=target, summary=summary, meta=meta, vault=self.ledger_dir,
                      agent=AGENT, session=self.session, phase=phase)

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

        outcome, why = self.policy.check(action)
        if outcome == "deny":
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
                h = self.approver.ask(rid=rid, action=action, flagged=verdict.flagged,
                                      review_reason=verdict.reason, span=verdict.span)
                decided_by, decision, reason = f"human:{h.channel}", h.decision, (
                    "overrode the model's flag" if h.overrode_flag else f"human {h.decision}")
                pre("gate.decision", f"human:{h.decision}" + (" (overrode flag)" if h.overrode_flag else ""),
                    decided_by=decided_by, decision=h.decision, channel=h.channel,
                    latency_s=h.latency_s, overrode_flag=h.overrode_flag)

        if decided_by == "policy":
            pre("gate.decision", f"policy:{decision} {reason}", decided_by="policy", decision=decision)

        if decision != "approve":
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
