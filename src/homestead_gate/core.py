"""One request through the gate: policy, local model, human, receipt, and only then action.

Ordering is the product. Every decision is appended to the homestead-memory ledger with
phase=pre_execution, and that append is fsynced, before any adapter runs. So the record
shows a denial was ENFORCED, not merely noted afterwards; a crash between decision and
send leaves a decision with no execution record, never the reverse.

What the agent sends is only the action and what it says it read. Anything else in the
request (a "user_intent", an "approved": true) is ignored. The user's intent is the task
the human gave when starting the gate, because a hijacked agent would lie about it.

Who changed the rules: each Gate writes a policy receipt when it starts serving (`up` at startup;
an assistant run or scheduled pass with its first request, so an idle pass adds nothing). policy.loaded carries the
policy file's sha256, the rule hash (version) and the sha256 of the second approvers' file;
policy.changed is written instead when any of those differ from the last policy receipt in the
ledger, with the old values next to the new. A policy file edited while the gate runs gets a
policy.edited receipt at the next request (the running gate keeps the rules it loaded).
"""
from __future__ import annotations

import hashlib
import inspect
import json
import threading
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Protocol

from homestead_memory.core import ledger

from . import adapters, approvers, receipts
from . import lookup as web_lookup
from .approval import NO_MODEL_REASON, HumanDecision, needs_full_view
from .policy import Policy
from .reviewer import Verdict, render

NO_MODEL = "none (--no-model)"       # the model name cli._NoModelReviewer reports
REVIEW_META_KEYS = {"digest": None, "manifest_digest": None, "prompt_version": None, "prompt_sha256": None}
AGENT = "homestead-gate"
# What a policy receipt pins. Any of these differing from the last receipt is a policy change.
POLICY_KEYS = ("policy_path", "policy_sha256", "policy_version", "approvers_sha256", "dual_control")


class Reviewer(Protocol):
    def review(self, prompt: str) -> Verdict: ...


class Approver(Protocol):
    # context (optional): extra information for the human's eyes only, e.g. {"web_lookup": {...}}.
    # An approver written before it existed simply does not take it, and the gate does not pass it.
    # second (dual control): the registered second approvers' names. Passed only to an approver whose
    # class sets collects_second = True; any other approver's yes on a dual-control action is a deny.
    def ask(self, *, rid: str, action: dict, flagged: bool, review_reason: str, span: str,
            context: dict | None = None, second: list[str] | None = None) -> HumanDecision: ...


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
                 lookup: "web_lookup.TavilyLookup | None" = None, lookup_cache: dict | None = None,
                 mac_key: bytes | None = None):
        self.policy, self.reviewer, self.approver = policy, reviewer, approver
        # Optional web lookup of unknown recipients (lookup.py). None means off. Its results are
        # for the human only; see _recipient_context. The cache is per target for the session; a
        # caller that builds several gates for one session (web demo runs, held items) passes one dict.
        self.lookup = lookup
        self._lookup_cache: dict = {} if lookup_cache is None else lookup_cache
        self.ledger_dir, self.task, self.session = Path(ledger_dir), task, session
        self.outbox, self.smtp, self.live = Path(outbox), smtp, live
        # The receipt ledger's MAC key (receipts.py), from the OS credential store. The caller fetches
        # it once; None (tests, the demo, no credential store) writes plain records as before.
        self.mac_key = mac_key
        # Payload hashes a human refused in this session: denied, or held by a scheduled pass. An identical
        # retry is refused by policy without a second review or a second question. Not stored: policy
        # denies (they repeat on their own, and the hourly cap lifts), and a terminal card nobody answered
        # in time (the person may have stepped away; they get asked again). Identical requests that arrive
        # together wait for the first one's decision instead of each asking the human.
        self.refused: set[str] = set()
        self._lock = threading.Lock()
        self._inflight: dict[str, threading.Event] = {}
        self._policy_lock = threading.Lock()
        self._recorded: dict | None = None        # the fingerprint of the last policy receipt this Gate wrote
        self._disk_seen: str | None = policy.file_sha256

    # ------------------------------------------------------------------ who changed the rules
    def _fingerprint(self) -> dict:
        p = self.policy
        return {"policy_path": str(p.path) if p.path else None, "policy_sha256": p.file_sha256,
                "policy_version": p.version, "approvers_sha256": approvers.file_sha256(p.approvers_dir),
                "dual_control": list(p.dual_control)}

    def _last_policy_receipt(self) -> dict | None:
        try:
            recs = ledger.read_all(self.ledger_dir)
        except Exception:  # noqa: BLE001 - no ledger yet: nothing recorded before
            return None
        for r in reversed(recs):
            if r.get("action") in ("policy.loaded", "policy.changed"):
                return r.get("meta") or {}
        return None

    def record_policy(self) -> None:
        """Write the start-of-serving policy receipt now (idempotent). `up` calls this at startup."""
        self._check_policy()

    def record_policy_if_changed(self) -> None:
        """For each scheduled pass, even one with nothing to send: write policy.changed if the policy
        differs from the last policy receipt in the ledger. Writes nothing otherwise (no noise)."""
        with self._policy_lock:
            if self._recorded is not None:
                return
            last = self._last_policy_receipt()
            if last is not None and any(last.get(k) != v for k, v in self._fingerprint().items()
                                        if k in POLICY_KEYS):
                self._record_policy(last, first=False)

    def _record_policy(self, last: dict | None = None, *, first: bool = True) -> None:
        fp = self._fingerprint()
        last = self._last_policy_receipt() if first else last
        changed = [k for k in POLICY_KEYS if last is not None and last.get(k) != fp[k]]
        if changed:
            prev = {k: last.get(k) for k in POLICY_KEYS}
            self._log("policy.changed", "policy changed: " + ", ".join(
                f"{k} {str(prev[k])[:12]} -> {str(fp[k])[:12]}" for k in changed),
                {**fp, "changed": changed, "previous": prev}, None, "gate:policy")
        elif first:
            self._log("policy.loaded", f"policy {fp['policy_version']} file "
                      f"{(fp['policy_sha256'] or 'none (built in code)')[:12]}", fp, None, "gate:policy")
        self._recorded = fp

    def _check_policy(self) -> None:
        """Per request: rules changed in memory since the last receipt (policy.changed), or the file
        edited on disk under a running gate (policy.edited, once per new file hash)."""
        with self._policy_lock:
            if self._recorded is None:
                self._record_policy()
            fp = self._fingerprint()
            if any(fp[k] != self._recorded.get(k) for k in POLICY_KEYS):
                self._record_policy(self._recorded, first=False)
            path = self.policy.path
            if path is None:
                return
            try:
                on_disk = hashlib.sha256(path.read_bytes()).hexdigest()
            except OSError:
                on_disk = None
            if on_disk != self._disk_seen:
                self._disk_seen = on_disk
                self._log("policy.edited", f"policy file changed on disk: {(on_disk or 'missing')[:12]}; "
                          "not in force until the gate restarts",
                          {"policy_path": str(path), "on_disk_sha256": on_disk,
                           "in_force_sha256": self.policy.file_sha256,
                           "policy_version": self.policy.version}, None, "gate:policy")

    def _log(self, action: str, summary: str, meta: dict, phase: str | None, target: str) -> None:
        if self.mac_key:
            receipts.append(self.mac_key, action, target=target, summary=summary, meta=meta,
                            vault=self.ledger_dir, agent=AGENT, session=self.session, phase=phase)
            return
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
            return None                      # off: the card shows nothing about lookups at all
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
        key = payload_hash(dict(request.get("action") or {}), self.policy.version)
        while True:
            with self._lock:
                first = self._inflight.get(key)
                if first is None:
                    self._inflight[key] = threading.Event()
                    break
            first.wait()                           # an identical request is being decided; then re-check
        try:
            return self._submit(request)
        finally:
            with self._lock:
                self._inflight.pop(key).set()

    def _submit(self, request: dict) -> dict:
        action = dict(request.get("action") or {})
        reads = request.get("read") or []
        rid = uuid.uuid4().hex[:10]
        target = f"gate:{action.get('type', '?')}"
        self._check_policy()
        pv = self.policy.version
        base = {"request_id": rid, "payload_sha256": payload_hash(action, pv), "policy_version": pv,
                "policy_sha256": self.policy.file_sha256}
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
            if verdict.model != NO_MODEL and verdict.reason.startswith(NO_MODEL_REASON):
                verdict = replace(verdict, reason="reviewer said: " + verdict.reason)  # the card keys its label on this text
            # llm:approve | llm:block | llm:invalid. "invalid" means the model did not review it
            # (missing, unreachable, no clear answer); the log must not call that a review.
            # The model's reason is kept out: it can quote the body, and the body stays out.
            # Which model file and which prompt judged it (None when no model reviewed: --no-model).
            pre("gate.review", f"llm:{verdict.verdict}", **{**REVIEW_META_KEYS, **verdict.meta},
                model=verdict.model, verdict=verdict.verdict, secs=verdict.secs)
            auto_ok, auto_why = (self.policy.may_auto(action) if not verdict.flagged
                                 and self.policy.is_allowlisted(action) else (False, ""))
            if auto_ok and action.get("type") in ("wallet_tx", "payment") \
                    and not self.policy.task_asks_to_spend(self.task):
                auto_ok = False                      # the user's request never asked for money to move
            dual = self.policy.requires_dual_control(action)
            registered = approvers.load(self.policy.approvers_dir) if dual else {}
            if auto_ok and dual:
                auto_ok = False                      # dual control means two people, never the policy alone
            if auto_ok:
                decided_by, decision, reason = "policy", "approve", auto_why
                self.policy.record_auto(action)
            elif dual and not registered:
                why = ("dual control is on for this action type but no second approver is registered "
                       "(homestead-gate approver add NAME)")
                pre("gate.decision", f"policy:deny {why}", decided_by="policy", decision="deny",
                    dual_control={"required": True, "satisfied": False})
                post("gate.denied", "not executed", reason=why)
                return {"id": rid, "status": "denied", "by": "policy", "reason": why,
                        "review": verdict.verdict}
            else:
                second = sorted(registered) if dual and getattr(self.approver, "collects_second", False) else None
                kw = {"second": second} if second is not None else {}
                # The review above is finished; the lookup cannot reach it (see _recipient_context).
                context = self._recipient_context(action, pre)
                h = self._ask(context, rid=rid, action=action, flagged=verdict.flagged,
                              review_reason=verdict.reason, span=verdict.span, **kw)
                decision = h.decision
                reason = "overrode the model's flag" if h.overrode_flag else f"human {h.decision}"
                extra = {}
                # The gate decides whether the card had to cut something short, not the approver. A yes
                # on such a card without the full view is refused, whatever channel it came from.
                must_view = bool(needs_full_view(action))
                if decision == "approve" and must_view and not h.full_view_seen:
                    decision, reason = "deny", "approved without being shown all of it"
                if dual:
                    ok = False
                    if decision == "approve":
                        ok = second is not None and approvers.verify(registered, h.second_name or "",
                                                                     h.second_secret or "")
                        if not ok:
                            decision = "deny"
                            reason = ("dual control not satisfied: the second approver was not confirmed"
                                      if second is not None else
                                      f"dual control: the {h.channel} channel cannot collect a second approver")
                    # The typed name is recorded only when it matched; a failed one could be anything.
                    extra["dual_control"] = {"required": True, "satisfied": ok,
                                             "second_approver": h.second_name if ok else None}
                h.second_name = h.second_secret = None          # checked; never kept, never written
                decided_by = f"human:{h.channel}"
                summary = f"human:{decision}" + (" (overrode flag)" if h.overrode_flag and decision == "approve" else "")
                if dual:
                    summary += " (dual control: " + (f"confirmed by {extra['dual_control']['second_approver']})"
                                                     if extra["dual_control"]["satisfied"] else "not satisfied)")
                pre("gate.decision", summary,
                    decided_by=decided_by, decision=decision, channel=h.channel,
                    latency_s=h.latency_s, overrode_flag=h.overrode_flag and decision == "approve",
                    approver=h.approver or {"channel": h.channel, "identified": False},
                    full_view={"required": must_view, "viewed": h.full_view_seen},
                    **extra)

        if decided_by == "policy":
            pre("gate.decision", f"policy:{decision} {reason}", decided_by="policy", decision=decision)

        if decision != "approve":
            if decided_by.startswith("human:") and (decision == "deny" or decided_by == "human:held"):
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
