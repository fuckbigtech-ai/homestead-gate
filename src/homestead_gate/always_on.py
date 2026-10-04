"""Always-on: wake on a schedule, handle only the mail that is new, leave a brief.

  homestead-gate assistant --watch --every 15m     # stay running, one pass every 15 minutes
  homestead-gate assistant --watch --once          # one pass, for launchd or cron
  homestead-gate assistant --pending               # approve or deny what the passes held for you

One pass:
  0. If a real inbox is set up (mailbox.py, read-only IMAP), sync it first. A failed sync does not
     stop the pass: it runs on the inbox as it was, and the brief says so.
  1. Read state.json in the data dir: the ids of the mail already handled.
  2. If nothing is new, write a short brief and stop. The cloud model is not called.
  3. Otherwise run one skill (triage by default) with list_inbox and read_email limited to the
     new mail, through the same Gate as every other run.
  4. Nobody is at the terminal, so the approver is HoldApprover: it never says yes. Anything that
     needs the human ends as "expired" in the receipts (decided_by human:held) and is queued in
     pending.json with what the run had read. `--pending` puts each item through the whole gate
     again, with the terminal approver: the queue file can be edited by anyone with your files,
     so it is never executed from directly.
  5. Mark the new mail handled (only when the run finished) and write brief.md plus a dated copy
     under briefs/. The "done" and "waiting for you" lists are built here, from the gate's
     results and the refusals, not from the model's summary; its words are quoted separately.
  6. Write a signed checkpoint of the receipts and anchor it (receipts.py; policy [receipts]).
     A checkpoint the gate refuses to sign (the chain no longer matches an earlier one) is in
     the brief and the notification, not only in a log.
  7. Show a desktop notification with counts only (no email text): osascript on macOS,
     notify-send on Linux, nothing if neither exists.

A lock file stops two passes (cron plus a manual run) from overlapping.
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from . import assistant as asst
from . import mailbox, receipts
from .approval import HumanDecision
from .core import Gate
from .llm import LLMError
from .skills import Skill

STATE_FILE, BRIEF_FILE, BRIEFS_DIR = "state.json", "brief.md", "briefs"
PENDING_FILE, LOCK_FILE = "pending.json", ".watch.lock"
HELD = "held"                # the approver channel; receipts say decided_by "human:held"
PENDING_CMD = "homestead-gate assistant --pending"


# ---------------------------------------------------------------- state

def load_state(data: Path) -> dict:
    try:
        st = json.loads((Path(data) / STATE_FILE).read_text())
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def save_state(data: Path, state: dict) -> None:
    p = Path(data) / STATE_FILE
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1))
    os.replace(tmp, p)


def new_mail(data: Path, state: dict | None = None) -> list[dict]:
    state = load_state(data) if state is None else state
    seen = set(state.get("seen") or [])
    inbox = json.loads((Path(data) / "inbox.json").read_text())
    return [m for m in inbox if m["id"] not in seen]


# ---------------------------------------------------------------- held approvals

class HoldApprover:
    """The approver for unattended passes. It cannot approve: every request that needs a human is
    held, which the gate records as expired and never executes."""
    channel = HELD

    def __init__(self):
        self.held: list[str] = []

    def ask(self, *, rid: str, action: dict, flagged: bool, review_reason: str, span: str,
            context: dict | None = None) -> HumanDecision:
        self.held.append(rid)
        return HumanDecision("expired", HELD, 0.0)


def load_pending(data: Path) -> list[dict]:
    try:
        items = json.loads((Path(data) / PENDING_FILE).read_text())
        return [i for i in items if isinstance(i, dict)] if isinstance(items, list) else []
    except (OSError, ValueError):
        return []


def save_pending(data: Path, items: list[dict]) -> None:
    p = Path(data) / PENDING_FILE
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, indent=1))
    os.replace(tmp, p)


def resolve_pending(data: Path, *, policy_factory: Callable[[], object], reviewer, approver,
                    log: Callable[[str], None] = print, lookup=None,
                    mac_key: bytes | None = None) -> list[dict]:
    """Put each held item through the full gate again (policy, reviewer, the terminal approver).
    Items the human answered leave the queue; an unanswered one stays. Returns
    [{"item", "result"}]."""
    data = Path(data)
    out, keep = [], []
    lookup_cache: dict = {}                  # one web-lookup cache for this sitting, across items
    saved = {f["value"].lower() for f in asst.AssistantMemory(data / "memory").user_facts("wallet")}
    for item in load_pending(data):
        action = item.get("action") or {}
        if action.get("type") == "wallet_tx" and str(action.get("to", "")).lower() not in saved:
            # The payee rule holds here too: the queue is an editable file, so a held payment to a
            # wallet you never saved is dropped, never put to the gate or to you.
            log(f"dropped a held payment to {action.get('to')}: not a wallet you saved")
            out.append({"item": item, "result": {"status": "refused", "reason": "not a wallet you saved"}})
            continue
        policy = policy_factory()
        asst.replay_auto_spend(policy, data / "ledger")
        gate = Gate(policy=policy, reviewer=reviewer, approver=approver, ledger_dir=data / "ledger",
                    task=str(item.get("task", "")), session=secrets.token_hex(4), outbox=data / "outbox",
                    lookup=lookup, lookup_cache=lookup_cache, mac_key=mac_key)
        log(f"held {item.get('created', '?')} by skill {item.get('skill', '?')}: "
            f"{_what(item.get('action') or {})}")
        res = gate.submit({"action": item.get("action") or {}, "read": item.get("reads") or []})
        out.append({"item": item, "result": res})
        if res.get("status") == "expired":
            keep.append(item)
    save_pending(data, keep)
    return out


# ---------------------------------------------------------------- notification

def notify(title: str, message: str) -> bool:
    """Desktop notification. Text goes as arguments, never into a script. Silent if unavailable."""
    if sys.platform == "darwin" and shutil.which("osascript"):
        argv = ["osascript", "-e", "on run argv",
                "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                "-e", "end run", title, message]
    elif shutil.which("notify-send"):
        argv = ["notify-send", title, message]
    else:
        return False
    try:
        subprocess.run(argv, capture_output=True, timeout=10, check=False)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


# ---------------------------------------------------------------- one pass

@dataclass
class Pass:
    at: str
    skill: str
    instruction: str
    new_mail: list[dict] = field(default_factory=list)
    done: list[str] = field(default_factory=list)
    waiting: list[str] = field(default_factory=list)
    earlier_waiting: int = 0
    facts_used: list[dict] = field(default_factory=list)
    final: str | None = None
    error: str | None = None
    skipped: str | None = None
    sync: str | None = None          # what the mail sync did, or why it could not
    sync_failed: bool = False
    receipts: str | None = None      # what the checkpoint did; set when it was refused or unsigned
    receipts_refused: bool = False
    brief: str = ""
    brief_path: str = ""

    def as_dict(self) -> dict:
        return dict(vars(self))


class _Lock:
    def __init__(self, path: Path):
        self.path, self.fh = path, None

    def __enter__(self) -> bool:
        import fcntl
        self.fh = open(self.path, "w")
        try:
            fcntl.flock(self.fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def __exit__(self, *exc) -> None:
        self.fh.close()          # closing releases the lock


def run_pass(data: Path, skill: Skill, *, llm, reviewer, now: datetime | None = None,
             notify_fn: Callable[[str, str], bool] | None = None, log: Callable[[str], None] = print,
             guard_prompt: bool = True, max_steps: int = 12, make_bot=None, wrap_submit=None,
             sync: Callable[[], "mailbox.SyncResult"] | None = None, seal: bool = True) -> Pass:
    """One scheduled pass over the new mail. make_bot and wrap_submit let a caller watch the run
    (the web demo uses them to show each step); they cannot change who approves. sync, when given,
    fetches real mail into inbox.json first, under the same lock. seal=False skips the receipt key
    and checkpoint (the web demo's throwaway sessions)."""
    data = Path(data)
    now = now or datetime.now()
    p = Pass(at=now.strftime("%Y-%m-%d %H:%M"), skill=skill.name, instruction=skill.instruction)
    with _Lock(data / LOCK_FILE) as got:
        if not got:
            p.skipped = "another pass is running"
            return p
        if sync is not None:
            try:
                p.sync = sync().summary()
            except mailbox.MailboxError as e:
                # not p.error: the pass still runs, on the inbox as it was
                p.sync, p.sync_failed = f"{e}\nThis pass used the inbox as it was.", True
        state = load_state(data)
        previous = state.get("last_run")
        p.new_mail = [{k: m.get(k) for k in ("id", "from", "subject")} for m in new_mail(data, state)]
        p.earlier_waiting = len(load_pending(data))
        memory = asst.AssistantMemory(data / "memory")
        names = {addr: f["entity"] for addr, f in memory.contacts().items()}
        keys = receipts.ledger_keys(warn=log) if seal else None
        # Each pass notices an edited policy, even with no new mail: policy.changed if it differs from
        # the last policy receipt, nothing otherwise. A policy that does not load fails the run below.
        try:
            Gate(policy=asst.load_policy(data, memory), reviewer=reviewer, approver=HoldApprover(),
                 ledger_dir=data / "ledger", task=skill.instruction, session=secrets.token_hex(4),
                 outbox=data / "outbox", mac_key=keys.mac_key if keys else None).record_policy_if_changed()
        except (OSError, ValueError) as e:
            log(f"policy check skipped: {e}")
        if p.new_mail:
            out = _run(data, skill, p, state, llm=llm, reviewer=reviewer, memory=memory, names=names,
                       guard_prompt=guard_prompt, max_steps=max_steps, make_bot=make_bot,
                       wrap_submit=wrap_submit, log=log, mac_key=keys.mac_key if keys else None)
            if out is not None:
                state["seen"] = sorted(set(state.get("seen") or []) | {m["id"] for m in p.new_mail})
        if seal:
            _seal(data, p, memory, reviewer, keys, log)
        state["last_run"] = now.isoformat(timespec="seconds")
        state["runs"] = int(state.get("runs") or 0) + 1
        save_state(data, state)
        p.brief = render_brief(p, last_run=previous)
        (data / BRIEF_FILE).write_text(p.brief)
        (data / BRIEFS_DIR).mkdir(exist_ok=True)
        dated = data / BRIEFS_DIR / f"{now.strftime('%Y-%m-%d-%H%M%S')}.md"
        dated.write_text(p.brief)
        p.brief_path = str(data / BRIEF_FILE)
    if p.new_mail or p.error or p.sync_failed or p.receipts_refused:
        (notify_fn or notify)("homestead", _counts(p))      # looked up now, so it can be replaced
    return p


def _seal(data: Path, p: Pass, memory, reviewer, keys, log) -> None:
    try:
        policy = asst.load_policy(data, memory)
    except (OSError, ValueError):
        policy = None                        # no anchors without a readable policy; still checkpoint locally
    try:
        r = receipts.seal(data / "ledger", policy=policy, reason="scheduled-pass", keys=keys, log=log,
                          reviewer_model=getattr(reviewer, "model", None) or (policy.model if policy else None))
    except (OSError, RuntimeError, ValueError, receipts.credstore.CredentialError) as e:
        # Never let the receipts stop the pass from saving which mail it handled: that would handle
        # the same mail again next time (held twice, prepared twice).
        p.receipts = f"no checkpoint was written this pass ({type(e).__name__}: {e})"
        return
    if r.status == "refused":
        p.receipts_refused = True
        p.receipts = "the gate REFUSED to sign a checkpoint: " + "; ".join(r.problems)
    elif r.warnings:
        p.receipts = "; ".join(r.warnings)


def _run(data, skill, p: Pass, state, *, llm, reviewer, memory, names, guard_prompt, max_steps,
         make_bot, wrap_submit, log, mac_key=None):
    policy = asst.load_policy(data, memory)
    asst.replay_auto_spend(policy, data / "ledger")
    gate = Gate(policy=policy, reviewer=reviewer, approver=HoldApprover(), ledger_dir=data / "ledger",
                task=skill.instruction, session=secrets.token_hex(4), outbox=data / "outbox", mac_key=mac_key)

    def submit(request: dict) -> dict:
        res = gate.submit(request)
        if res.get("status") == "expired" and res.get("by") == f"human:{HELD}":
            items = load_pending(data)
            items.append({"id": res.get("id"), "created": p.at, "skill": skill.name, "task": skill.instruction,
                          "action": request.get("action"), "reads": request.get("read") or []})
            save_pending(data, items)
        return res

    kw = dict(llm=llm, submit=wrap_submit(submit) if wrap_submit else submit, data_dir=data, memory=memory,
              task=skill.instruction, max_steps=max_steps, guard_prompt=guard_prompt, tools=skill.tools,
              only_ids={m["id"] for m in p.new_mail}, log=log)
    bot = (make_bot or asst.Assistant)(**kw)
    try:
        out = bot.run()
    except LLMError as e:
        p.error = f"the cloud model failed: {e}"
        _collect(p, bot, names)          # whatever reached the gate before the failure still counts
        return None
    p.final = out["final"]
    _collect(p, bot, names)
    return out


def _who(addr: str, names: dict) -> str:
    n = names.get(str(addr).lower())
    return f"{n} ({addr})" if n else str(addr)


def _what(action: dict, names: dict | None = None) -> str:
    to = _who(action.get("to", "?"), names or {})
    if action.get("type") == "wallet_tx":
        return f"pay {action.get('value_eth')} ETH to {to}"
    return f"email {to}, \"{action.get('subject', '')}\""


def _collect(p: Pass, bot, names: dict) -> None:
    for r in bot.requests:
        a, res = r["action"], r["result"]
        what, st, by = _what(a, names), res.get("status"), res.get("by", "")
        if st == "executed":
            how = ("unsigned transaction prepared, nothing broadcast" if a.get("type") == "wallet_tx"
                   else "written to the outbox (dry run)" if (res.get("result") or {}).get("dry_run")
                   else "sent")
            p.done.append(f"{what[0].upper()}{what[1:]}: approved by {'the policy' if by == 'policy' else by}, "
                          f"{how}.")
        elif st == "expired" and by == f"human:{HELD}":
            p.waiting.append(f"{what[0].upper()}{what[1:]}: held for your yes. Approve or deny it with "
                             f"`{PENDING_CMD}`.")
        else:
            why = f" ({res.get('reason')})" if res.get("reason") else ""
            p.waiting.append(f"{what[0].upper()}{what[1:]}: not done, {st} by {by or 'the gate'}{why}.")
    for r in bot.refusals:
        saved = ", ".join(f"{f['value']} (written by you; {f['source']})" for f in r.get("saved") or [])
        name = (r.get("saved") or [{}])[0].get("entity", "NAME")
        p.waiting.append(f"Pay {r['value_eth']} ETH to {r['to']}: not done, refused before the gate. "
                         f"{r['reason']}" + (f" The wallet you saved: {saved}." if saved else "")
                         + " If the change is real, confirm it with them yourself, then save it with "
                         f"`homestead-gate assistant --remember \"{name}\" wallet ADDRESS`.")
    p.facts_used = [dict(f) for f in bot.facts_used]


def _counts(p: Pass) -> str:
    if p.receipts_refused:
        return "the receipts no longer match an earlier checkpoint; see the brief"
    if p.error:
        return "a scheduled run failed; see the brief"
    return ("mail sync failed, see the brief; " if p.sync_failed else "") + (
        f"{len(p.new_mail)} new, {len(p.done)} done, {len(p.waiting) + p.earlier_waiting} waiting for you")


def render_brief(p: Pass, last_run: str | None = None) -> str:
    since = f" since the last run ({last_run.replace('T', ' ')[:16]})" if last_run else ""
    lines = [f"# Brief, {p.at}", "",
             f"Skill **{p.skill}**, in your words: \"{p.instruction}\"", ""]
    if p.skipped:
        return "\n".join(lines + [f"Skipped: {p.skipped}.", ""])
    if p.sync:
        lines += [("**Mail sync failed:** " if p.sync_failed else "Mail sync: ") + p.sync.replace("\n", "  \n"), ""]
    lines.append(f"**{len(p.new_mail)} new email{'s' if len(p.new_mail) != 1 else ''}**{since}.")
    if not p.new_mail:
        lines.append("Nothing new, so the cloud model was not called.")
    if p.error:
        lines += ["", f"**The run did not finish:** {p.error}. The new mail stays unread for the next run."]
    if p.receipts:
        lines += ["", ("**Receipts:** " if p.receipts_refused else "Receipts: ") + p.receipts
                  + (". Check them with `homestead-gate watch --ledger LEDGER --anchors DIR`." if p.receipts_refused
                     else "")]
    lines += ["", "## Done"] + ([f"- {d}" for d in p.done] or ["- Nothing sent or paid."])
    lines += ["", "## Waiting for you"] + ([f"- {w}" for w in p.waiting] or ["- Nothing from this run."])
    if p.earlier_waiting:
        lines.append(f"- {p.earlier_waiting} held from earlier runs. See them with `{PENDING_CMD}`.")
    if p.new_mail:
        lines += ["", "## New mail"] + [f"- {m['from']}: {m['subject']}" for m in p.new_mail]
    if p.facts_used:
        lines += ["", "## Memory it used"]
        for f in p.facts_used:
            who = "you" if f.get("written_by") == asst.USER else (f.get("written_by") or "unknown")
            dated = any(ch.isdigit() for ch in str(f.get("source") or ""))
            lines.append(f"- {f['entity']}, {f['field']}: {f['value']} (written by {who}"
                         + (f" at {str(f['at'])[:16].replace('T', ' ')}" if f.get("at") and not dated else "")
                         + f"; {f['source']})")
    if p.final:
        lines += ["", "## In the assistant's words", "",
                  "The lists above come from the gate's records. This part is the cloud model's own summary.", ""]
        lines += [f"> {ln}" if ln.strip() else ">" for ln in p.final.splitlines()]
    return "\n".join(lines) + "\n"
