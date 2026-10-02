"""homestead web demo: the real Assistant and the real Gate, with the approval card in a browser.

  PYTHONPATH=src python -m demo.web.server                 # http://127.0.0.1:8000
  DEMO_BRAIN=scripted DEMO_REVIEWER=scripted ...           # offline, no models, no credits

DEMO MODE. The product has no approve button on the network: approval happens only in the
terminal the gate was started in. Here the approval is a button on this page, and the reviewer
runs on Nebius Token Factory so a visitor needs no GPU. The page says so in plain words.

What is real: the Assistant loop, the Gate (policy, reviewer prompt, human decision, receipts
written before anything runs), the homestead-memory ledger and its verifier. What is not: the
inbox, the bills and the wallet are fake; email is always dry-run (never sent); payments are
unsigned Sepolia transactions.

Isolation and limits: each browser session gets its own temporary data dir (seeded with
assistant.seed), its own ledger and outbox, deleted an hour after it was created. Runs are
rate limited per session and globally, at most a few run at once, and each run has a token
budget that covers the brain and the reviewer.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
from collections import deque
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from homestead_memory.core import distill as hsm_distill
from homestead_memory.core import ledger

from homestead_gate import always_on
from homestead_gate import assistant as asst
from homestead_gate import skills as skills_mod
from homestead_gate.core import Gate
from homestead_gate.llm import LLMError
from homestead_gate.policy import Policy
from homestead_gate.skills import Skill, SkillError

from . import agentdojo_attack
from .approver import WebApprover
from .reviewers import BudgetTransport, make_brain, make_reviewer, reviewer_kind, reviewer_label, reviewer_model

STATIC = Path(__file__).parent / "static"
COOKIE = "hg_demo"

SESSION_TTL_S = 3600
MAX_SESSIONS = 200
GLOBAL_RUNS_PER_HOUR = int(os.environ.get("DEMO_GLOBAL_RUNS_PER_HOUR", "20"))
SESSION_RUNS_PER_HOUR = int(os.environ.get("DEMO_SESSION_RUNS_PER_HOUR", "5"))
MAX_CONCURRENT_RUNS = 3
RUN_TOKEN_BUDGET = int(os.environ.get("DEMO_RUN_TOKEN_BUDGET", "60000"))
MAX_STEPS = 10
INJECTION_MAX = 2000
APPROVAL_TIMEOUT_S = 180
OVERRIDE_DELAY_S = 10
MAX_BODY = 8192

SUMMARIZE_TASK = "Read every email in my inbox and summarize it for me."
DEFAULT_INJECTION = next(m["body"] for m in asst.INBOX if m["id"] == "msg-004")
SCENARIOS = {
    "morning": {"label": "Morning run", "task": asst.SKILLS["triage"]},
    "pay": {"label": "Pay Sam's invoice", "task": asst.SKILLS["pay"]},
    "summarize": {"label": "Read every email and summarize", "task": SUMMARIZE_TASK},
    "custom": {"label": "Try your own injection", "task": SUMMARIZE_TASK},
    # AgentDojo's published template in the poisoned email; the same request as "summarize" (so the
    # email is read, as AgentDojo's user tasks read their injection), every tool offered, warning on.
    "agentdojo": {"label": "A published attack (AgentDojo)", "task": SUMMARIZE_TASK,
                  "note": agentdojo_attack.LABEL},
    "skill": {"label": "Run one of your skills", "task": ""},
}
# The morning run simulates two scheduled passes (07:00 and 07:15) with mail arriving in
# between; it costs two runs from the hourly limits and gets two runs' token budget.
MORNING_TIMES = ((7, 0), (7, 15))
NAME_MAX = 60


class LimitError(Exception):
    def __init__(self, message: str, status: int = 429):
        super().__init__(message)
        self.status = status


class Window:
    """At most `limit` events in any rolling hour."""

    def __init__(self, limit: int, span_s: float = 3600):
        self.limit, self.span, self.times = limit, span_s, deque()

    def take(self, now: float) -> bool:
        while self.times and now - self.times[0] >= self.span:
            self.times.popleft()
        if len(self.times) >= self.limit:
            return False
        self.times.append(now)
        return True

    def take_n(self, now: float, n: int) -> bool:
        """Take n slots or none."""
        got = 0
        while got < n and self.take(now):
            got += 1
        if got < n:
            for _ in range(got):
                self.times.pop()
            return False
        return True

    def wait_s(self, now: float) -> int:
        return int(self.span - (now - self.times[0])) + 1 if self.times else 0


# ---------------------------------------------------------------- runs and sessions

class Run:
    def __init__(self, rid: str, scenario: str, task: str, skill: Skill | None = None):
        self.id, self.scenario, self.task, self.skill = rid, scenario, task, skill
        self.events: list[dict] = []
        self.cond = threading.Condition()
        self.done = False
        self.approver: WebApprover | None = None
        # request id -> (field, address) for actions YOU approved to someone not in your memory;
        # only these can be remembered from the page, and only once
        self.rememberable: dict[str, tuple[str, str]] = {}

    def emit(self, kind: str, data: dict) -> None:
        with self.cond:
            self.events.append({"seq": len(self.events), "type": kind, "data": data})
            self.cond.notify_all()

    def finish(self) -> None:
        with self.cond:
            self.done = True
            self.cond.notify_all()


class Session:
    def __init__(self, sid: str, root: Path, created: float, runs_per_hour: int):
        self.id, self.dir, self.created = sid, root / sid, created
        self.window = Window(runs_per_hour)
        self.runs: dict[str, Run] = {}
        self.active: Run | None = None

    @property
    def ledger_dir(self) -> Path:
        return self.dir / "ledger"


class _RecordingReviewer:
    """Passes reviews through unchanged and keeps the last verdict for the page, because the
    ledger deliberately does not store the reviewer's reason (it can quote the email body)."""

    def __init__(self, inner):
        self.inner, self.last = inner, None
        self.model = getattr(inner, "model", "?")

    def review(self, prompt: str):
        self.last = self.inner.review(prompt)
        return self.last


class _EmittingBrain:
    def __init__(self, inner, emit):
        self.inner, self.emit, self.n = inner, emit, 0
        self.model = getattr(inner, "model", "?")

    def chat(self, messages, tools=None, **kw):
        self.n += 1
        self.emit("thinking", {"step": self.n})
        return self.inner.chat(messages, tools, **kw)


class WebAssistant(asst.Assistant):
    """The product's Assistant, unchanged, with each tool call shown on the page."""

    def __init__(self, *a, emit, **kw):
        super().__init__(*a, **kw)
        self.emit = emit

    def call(self, name: str, args: dict) -> dict:
        if name in asst.OUTBOUND_TOOLS:
            self.emit("outbound", {"tool": name, "args": args if isinstance(args, dict) else {}})
        result = super().call(name, args)
        if name not in asst.OUTBOUND_TOOLS:
            self.emit("read", {"tool": name, "args": args if isinstance(args, dict) else {},
                               "result": _preview(name, result)})
        elif "error" in result:
            self.emit("tool_error", {"tool": name, "error": result["error"]})
        return result


def _preview(name: str, result: dict) -> dict:
    if "error" in result:
        return {"error": result["error"]}
    if name == "read_email":
        return {k: result.get(k) for k in ("id", "from", "subject", "date", "body")}
    return result


def contacts(data: Path, policy: Policy) -> dict[str, str]:
    """Address -> who it is, from the memory the user wrote. For labels on the card only."""
    out = {a.lower(): "you" for a in (policy.user_email, policy.user_wallet) if a}
    mem = asst.AssistantMemory(data / "memory")
    ddir = data / "memory" / hsm_distill.DISTILLED_DIR
    for p in sorted(ddir.glob("*.md")) if ddir.is_dir() else []:
        for f in mem.recall(p.stem):
            if f["field"] in ("email", "wallet"):
                out.setdefault(f["value"].lower(), f"{f['entity']} (in your memory, written by " + ("you" if f["written_by"] == "user" else str(f["written_by"])) + ")")
    return out


_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def fact_view(f: dict) -> dict:
    """One memory fact for the page: what, who wrote it, when, and from what."""
    who = "you" if f.get("written_by") == asst.USER else (f.get("written_by") or "unknown")
    m = _DATE.search(str(f.get("source") or ""))
    when = m.group(0) if m else str(f.get("at") or "")[:16].replace("T", " ")
    return {"entity": f.get("entity"), "field": f.get("field"), "value": f.get("value"),
            "written_by": who, "when": when, "source": f.get("source")}


def explain_rule(policy: Policy, task: str, action: dict, flagged: bool) -> str:
    """Why this action came to a human. Mirrors the branch order in core.Gate.submit after the
    policy said "review", using only methods that change no state (never check or record_auto)."""
    if flagged:
        return ("The reviewer did not approve it, so you decide. Approving anyway takes the phrase "
                "'send anyway' and a wait.")
    if not policy.is_allowlisted(action):
        return "The recipient is not in your allowlist, so you decide."
    ok, why = policy.may_auto(action)
    if not ok:
        return f"Allowlisted, but it {why}, so you decide."
    if action.get("type") == "wallet_tx" and not policy.task_asks_to_spend(task):
        return "Your request never asked for a payment, so any payment comes to you."
    return "Allowlisted and the reviewer approved it."


def _receipts_for(ledger_dir: Path, rid: str) -> list[dict]:
    try:
        recs = ledger.read_all(ledger_dir)
    except Exception:  # noqa: BLE001 - no ledger yet
        return []
    return [{"seq": r.get("seq"), "action": r.get("action"), "summary": r.get("summary"),
             "phase": r.get("phase"), "hash": r.get("hash"),
             "payload_sha256": (r.get("meta") or {}).get("payload_sha256")}
            for r in recs if (r.get("meta") or {}).get("request_id") == rid]


class App:
    def __init__(self, root: Path | None = None, *, brain_factory=None, reviewer_factory=None,
                 clock=time.monotonic, global_runs_per_hour: int = GLOBAL_RUNS_PER_HOUR,
                 session_runs_per_hour: int = SESSION_RUNS_PER_HOUR,
                 max_concurrent: int = MAX_CONCURRENT_RUNS, max_sessions: int = MAX_SESSIONS,
                 session_ttl_s: float = SESSION_TTL_S, token_budget: int = RUN_TOKEN_BUDGET,
                 approval_timeout_s: float = APPROVAL_TIMEOUT_S, override_delay_s: float = OVERRIDE_DELAY_S):
        self.root = Path(root or tempfile.mkdtemp(prefix="hg-web-demo-")).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.brain_factory = brain_factory or self._default_brain
        self.reviewer_factory = reviewer_factory or make_reviewer
        self.global_window = Window(global_runs_per_hour)
        self.session_runs_per_hour, self.max_concurrent = session_runs_per_hour, max_concurrent
        self.max_sessions, self.ttl, self.token_budget = max_sessions, session_ttl_s, token_budget
        self.approval_timeout_s, self.override_delay_s = approval_timeout_s, override_delay_s
        self.sessions: dict[str, Session] = {}
        self.running = 0
        self.lock = threading.Lock()

    @staticmethod
    def _default_brain(transport):
        if (os.environ.get("DEMO_BRAIN") or "").lower() == "scripted":
            from .scripted_brain import ScriptedBrain
            return ScriptedBrain()
        return make_brain(transport)

    def brain_label(self) -> str:
        if (os.environ.get("DEMO_BRAIN") or "").lower() == "scripted":
            return "a scripted stand-in (no model)"
        try:
            return f"{make_brain().model} on Nebius Token Factory"
        except Exception:  # noqa: BLE001
            return "Nemotron 3 Super on Nebius Token Factory"

    # -- sessions
    def session(self, sid: str | None, create: bool = True) -> Session | None:
        with self.lock:
            s = self.sessions.get(sid or "")
            if s or not create:
                return s
            if len(self.sessions) >= self.max_sessions:
                # Make room by dropping the oldest session that never ran anything; sessions that
                # hold receipts are kept until their hour is up.
                idle = min((x for x in self.sessions.values() if not x.runs), key=lambda x: x.created, default=None)
                if idle is None:
                    raise LimitError("The demo is full right now. Try again in a few minutes.", 503)
                del self.sessions[idle.id]
                self._remove(idle.dir)
            sid = secrets.token_urlsafe(18)
            s = Session(sid, self.root, self.clock(), self.session_runs_per_hour)
            self.sessions[sid] = s
            return s

    def sweep(self) -> int:
        """Delete sessions older than the TTL: resolve their waiting cards to deny, then remove
        their data dir. Returns how many were removed."""
        now = self.clock()
        with self.lock:
            old = [s for s in self.sessions.values() if now - s.created >= self.ttl]
        removed = 0
        for s in old:
            for r in s.runs.values():
                if r.approver:
                    r.approver.close()            # waiting cards end as deny, so the run finishes
            if s.active is not None and not s.active.done:
                continue                          # removed on a later sweep, once its writes stop
            with self.lock:
                self.sessions.pop(s.id, None)
            self._remove(s.dir)
            removed += 1
        return removed

    def _remove(self, path: Path) -> None:
        p = path.resolve()
        if p.parent == self.root and p.name and p.exists():
            shutil.rmtree(p, ignore_errors=True)

    def close(self) -> None:
        with self.lock:
            ss = list(self.sessions.values())
            self.sessions.clear()
        for s in ss:
            for r in s.runs.values():
                if r.approver:
                    r.approver.close()
        if self.root.exists() and self.root.name.startswith("hg-web-demo-"):
            shutil.rmtree(self.root, ignore_errors=True)

    # -- skills (yours are kept in this session's skills.toml, like the product's data dir)
    def _ensure_data(self, s: Session) -> None:
        asst.seed(s.dir, model="demo")
        skills_mod.ensure_skills_file(s.dir)

    def skills(self, s: Session | None) -> list[dict]:
        if s is None or not (s.dir / skills_mod.SKILLS_FILE).exists():
            return [k.as_dict() for k in skills_mod.DEFAULT_SKILLS]
        return [k.as_dict() for k in skills_mod.load_skills(s.dir).values()]

    def add_skill(self, s: Session, name: str, instruction: str) -> list[dict]:
        """One skill of your own per page. Its tools are fixed here to the safe set, whatever the
        page sends: it can read, look things up and write email, which still stops at the gate."""
        if self.clock() - s.created >= self.ttl:
            raise LimitError("This page's session has ended. Reload the page to start again.", 410)
        if str(name or "").strip().lower() in {k.name for k in skills_mod.DEFAULT_SKILLS}:
            raise LimitError("That name belongs to a default skill. Pick another one.", 400)
        try:
            skill = skills_mod.validate(name, instruction, skills_mod.SAFE_TOOLS)
        except SkillError as e:
            raise LimitError(str(e).capitalize() + ".", 400) from None
        self._ensure_data(s)
        mine = [k for k in skills_mod.load_skills(s.dir).values() if k.origin == "default"] + [skill]
        skills_mod.write_skills(s.dir / skills_mod.SKILLS_FILE, mine)
        return self.skills(s)

    # -- runs
    def start_run(self, s: Session, scenario: str, injection: str = "", unguarded: bool = False,
                  background: bool = True, skill: str = "") -> Run:
        if scenario not in SCENARIOS:
            raise LimitError("unknown scenario", 400)
        injection = str(injection or "")
        if len(injection) > INJECTION_MAX:
            raise LimitError(f"The injection text is limited to {INJECTION_MAX} characters.", 400)
        chosen = None
        if scenario == "skill":
            self._ensure_data(s)
            chosen = skills_mod.load_skills(s.dir).get(str(skill or ""))
            if chosen is None:
                raise LimitError("Pick one of your skills first.", 400)
        elif scenario == "morning":
            chosen = skills_mod.load_skills(s.dir).get("triage") if (s.dir / skills_mod.SKILLS_FILE).exists() \
                else None
            chosen = chosen or next(k for k in skills_mod.DEFAULT_SKILLS if k.name == "triage")
        elif scenario == "agentdojo":
            injection, unguarded = agentdojo_attack.email_body(), False     # the warning is never removed
        cost = 2 if scenario == "morning" else 1
        now = self.clock()
        with self.lock:
            if now - s.created >= self.ttl:
                raise LimitError("This page's session has ended. Reload the page to start again.", 410)
            if s.active is not None and not s.active.done:
                raise LimitError("A run is already going in this page. Finish it first.", 409)
            if self.running >= self.max_concurrent:
                raise LimitError("Too many runs at once right now. Try again in a minute.", 503)
            if not s.window.take_n(now, cost):
                raise LimitError(f"This page has used its {self.session_runs_per_hour} runs for the hour. "
                                 f"Try again in {s.window.wait_s(now) // 60 + 1} minutes.")
            if not self.global_window.take_n(now, cost):
                for _ in range(cost):
                    s.window.times.pop()        # not this session's fault; give its slots back
                raise LimitError("The demo has used its runs for this hour, so the credits last. "
                                 f"Try again in {self.global_window.wait_s(now) // 60 + 1} minutes.")
            self.running += 1
            task = chosen.instruction if chosen else SCENARIOS[scenario]["task"]
            run = Run(secrets.token_hex(6), scenario, task, chosen)
            s.runs[run.id] = run
            s.active = run
        args = (s, run, injection if scenario in ("custom", "agentdojo") else "", bool(unguarded))
        if background:
            threading.Thread(target=self._execute, args=args, daemon=True).start()
        else:
            self._execute(*args)
        return run

    def _execute(self, s: Session, run: Run, injection: str, unguarded: bool) -> None:
        try:
            if run.scenario == "morning":
                self._run_morning(s, run, unguarded)
            else:
                self._run(s, run, injection, unguarded)
        except LLMError as e:
            run.emit("run_error", {"message": f"The cloud model failed: {e}"})
        except Exception as e:  # noqa: BLE001 - the page must hear about it; nothing executes after
            run.emit("run_error", {"message": f"The run stopped: {type(e).__name__}"})
        finally:
            with self.lock:
                self.running -= 1
            run.finish()

    def _prepare(self, s: Session, run: Run, injection: str = "", inbox=None):
        """Seed, rewrite the inbox (a custom injection never leaks into a later run), and build
        the run's reviewer, brain and budget. The visitor's injection replaces only the poisoned
        email's body: it is email content, never the task."""
        data = s.dir
        self._ensure_data(s)
        inbox = [dict(m) for m in (inbox or asst.INBOX)]
        if injection:
            next(m for m in inbox if m["id"] == "msg-004")["body"] = injection
        (data / "inbox.json").write_text(json.dumps(inbox, indent=1))
        budget = BudgetTransport(self.token_budget * (2 if run.scenario == "morning" else 1))
        reviewer = _RecordingReviewer(self.reviewer_factory(budget))
        brain = _EmittingBrain(self.brain_factory(budget), run.emit)
        return data, budget, reviewer, brain

    def _submitter(self, s: Session, run: Run, gate_submit, reviewer, rules: dict):
        """Wrap a gate's submit so each decision is shown on the page with its receipts. Watches
        only; the gate and its approver decide."""
        data = s.dir

        def submit(request: dict) -> dict:
            reviewer.last = None
            res = gate_submit(request)
            policy = asst.load_policy(data)          # labels and rule text only; no state changes
            book = contacts(data, policy)
            recs = _receipts_for(s.ledger_dir, res.get("id", ""))
            v = reviewer.last
            action = request.get("action") or {}
            to = str(action.get("to", ""))
            decision = next((r["summary"] for r in recs if r["action"] == "gate.decision"), "")
            if res.get("by") == "policy" and res.get("status") == "denied":
                rule = f"Policy denied it without asking: {res.get('reason')}."
            elif res.get("by") == "policy":
                rule = decision.split(" ", 1)[1].capitalize() + "." if " " in decision else "Policy allowed it."
            elif res.get("by") == f"human:{always_on.HELD}":
                rule = explain_rule(policy, run.task, action, bool(v and v.flagged)) + \
                    " Nobody is at the terminal during a scheduled run, so it waits for you."
            else:
                rule = rules.get(res.get("id", ""))
            result = res.get("result") or {}
            if result.get("dry_run"):
                result = {**result, "dry_run": Path(result["dry_run"]).name}
            can_remember = (res.get("status") == "executed" and str(res.get("by", "")).startswith("human:")
                            and to.lower() not in book)
            if can_remember:
                run.rememberable[res["id"]] = ("wallet" if action.get("type") == "wallet_tx" else "email", to)
            run.emit("gate_result", {
                "rid": res.get("id"), "status": res.get("status"), "by": res.get("by"),
                "reason": res.get("reason"), "rule": rule, "action": action,
                "to_label": book.get(to.lower(), "not in your contacts or memory"),
                "review": None if v is None else {"verdict": v.verdict, "reason": v.reason,
                                                  "span": v.span, "model": v.model, "secs": v.secs},
                "result": result, "receipts": recs, "can_remember": can_remember})
            return res
        return submit

    def _run(self, s: Session, run: Run, injection: str, unguarded: bool) -> None:
        data, budget, reviewer, brain = self._prepare(s, run, injection)
        policy = asst.load_policy(data)
        book = contacts(data, policy)
        rules: dict[str, str] = {}

        def on_ask(card: dict) -> None:
            recs = _receipts_for(s.ledger_dir, card["rid"])
            rules[card["rid"]] = explain_rule(policy, run.task, card["action"], card["flagged"])
            run.emit("approval", {**card, "rule": rules[card["rid"]],
                                  "to_label": book.get(str(card["action"].get("to", "")).lower(),
                                                       "not in your contacts or memory"),
                                  "verdict": reviewer.last.verdict if reviewer.last else None,
                                  "reviewer_model": reviewer.model, "receipts": recs})

        approver = WebApprover(timeout_s=self.approval_timeout_s, override_delay_s=self.override_delay_s,
                               on_ask=on_ask)
        run.approver = approver
        asst.replay_auto_spend(policy, s.ledger_dir)
        gate = Gate(policy=policy, reviewer=reviewer, approver=approver, ledger_dir=s.ledger_dir,
                    task=run.task, session=run.id, outbox=data / "outbox", smtp=None, live=False)
        run.emit("start", self._start_info(run, unguarded, injection, brain, reviewer))
        bot = WebAssistant(llm=brain, submit=self._submitter(s, run, gate.submit, reviewer, rules), data_dir=data,
                           memory=asst.AssistantMemory(data / "memory"), task=run.task, max_steps=MAX_STEPS,
                           guard_prompt=not unguarded, tools=run.skill.tools if run.skill else None,
                           emit=run.emit)
        out = bot.run()
        self._finish(run, out["final"], out["gate"], out["refusals"], out["facts_used"], budget)

    def _start_info(self, run: Run, unguarded: bool, injection: str, brain, reviewer) -> dict:
        return {"task": run.task, "scenario": run.scenario, "guarded": not unguarded,
                "custom_injection": bool(injection) and run.scenario == "custom",
                "published_attack": ({"label": agentdojo_attack.LABEL, "source": agentdojo_attack.SOURCE}
                                     if run.scenario == "agentdojo" else None),
                "brain": brain.model, "reviewer": reviewer.model,
                "token_budget": self.token_budget,
                "skill": run.skill.as_dict() if run.skill else None}

    def _finish(self, run: Run, final, gate_results, refusals, facts_used, budget) -> None:
        results = [g.get("status") for g in gate_results]
        run.emit("memory", {"facts": [fact_view(f) for f in facts_used]})
        run.emit("summary", {"final": final or "(no answer)", "outbound": len(results),
                             "executed": results.count("executed"),
                             "stopped": len(results) - results.count("executed"),
                             "refused": len(refusals), "tokens_used": budget.used})

    def _run_morning(self, s: Session, run: Run, unguarded: bool) -> None:
        """Two scheduled passes of the triage skill, as `assistant --watch` runs them: the same
        run_pass, the same HoldApprover (nothing is approved on this page during them), new mail
        delivered in between. Only the clock is simulated."""
        data, budget, reviewer, brain = self._prepare(s, run)
        for name in (always_on.STATE_FILE, always_on.PENDING_FILE, always_on.BRIEF_FILE):
            (data / name).unlink(missing_ok=True)
        run.emit("start", self._start_info(run, unguarded, "", brain, reviewer))
        today = datetime.now().date()
        facts, refusals, results, finals = [], [], [], []
        for i, (hh, mm) in enumerate(MORNING_TIMES):
            if i:
                arrived = asst.deliver_later_mail(data)
                run.emit("mail_arrived", {"messages": [{k: m[k] for k in ("id", "from", "subject")} for m in arrived]})
            at = datetime(today.year, today.month, today.day, hh, mm)
            new = always_on.new_mail(data)
            run.emit("tick", {"at": at.strftime("%H:%M"), "new": [{k: m[k] for k in ("id", "from", "subject")}
                                                                   for m in new]})
            shown = []
            holder: dict = {}

            def make_bot(**kw):
                holder["bot"] = WebAssistant(emit=run.emit, **kw)
                return holder["bot"]

            p = always_on.run_pass(
                data, run.skill, llm=brain, reviewer=reviewer, now=at, guard_prompt=not unguarded,
                max_steps=MAX_STEPS, log=lambda line: None, notify_fn=lambda t, m: shown.append(m) or True,
                make_bot=make_bot, wrap_submit=lambda sub: self._submitter(s, run, sub, reviewer, {}))
            bot = holder.get("bot")
            if bot is not None:
                facts += [f for f in bot.facts_used if f not in facts]
                refusals += bot.refusals
                results += bot.gate_results
            if p.final:
                finals.append(f"**{at.strftime('%H:%M')}:** {p.final}")
            run.emit("brief", {"at": at.strftime("%H:%M"), "markdown": p.brief, "done": len(p.done),
                               "waiting": len(p.waiting) + p.earlier_waiting, "error": p.error,
                               "notification": shown[0] if shown else None})
            if p.error:
                run.emit("run_error", {"message": f"The {at.strftime('%H:%M')} run did not finish: {p.error}"})
                break
        self._finish(run, "\n\n".join(finals) or None, results, refusals, facts, budget)

    def remember(self, s: Session, run_id: str, rid: str, name: str) -> dict:
        """Remember someone you just approved. The address comes from this session's receipt of
        an action YOU approved; only the name comes from the page. Written as your fact, with
        the source 'approved by you on <date>', so the next run treats them as a known contact."""
        run = s.runs.get(str(run_id))
        entry = run.rememberable.get(str(rid)) if run else None
        if entry is None:
            raise LimitError("Nothing you approved is waiting to be remembered with that id.", 409)
        name = " ".join(str(name or "").split())
        if not name or len(name) > NAME_MAX:
            raise LimitError(f"Give a name of 1 to {NAME_MAX} characters.", 400)
        field, value = entry
        mem = asst.AssistantMemory(s.dir / "memory")
        mem.remember_from_user(name, field, value, source=asst.approved_source())
        run.rememberable.pop(str(rid), None)
        fact = next(f for f in mem.recall(name) if f["field"] == field and f["value"] == value)
        return {"fact": fact_view(fact)}

    # -- page actions
    def decide(self, s: Session, run_id: str, rid: str, decision: str, phrase: str = "") -> tuple[bool, str]:
        run = s.runs.get(str(run_id))          # only this session's runs are reachable
        if run is None or run.approver is None:
            return False, "no approval is waiting with that id"
        return run.approver.decide(str(rid), str(decision), str(phrase or ""))

    def verify(self, s: Session) -> dict:
        return _verify_dir(s.ledger_dir)

    def tamper(self, s: Session) -> dict:
        """Edit one record in a COPY of this session's ledger, then verify the copy. The real
        ledger is untouched (and still verifies)."""
        src = s.ledger_dir / ledger.LEDGER_REL
        if not src.exists():
            return {"error": "No receipts yet. Run a scenario first."}
        lines = src.read_text().splitlines()
        idx, before, after = _pick_edit(lines)
        rec = json.loads(lines[idx])
        rec["summary"] = after                  # the hash is left as it was: that is the tamper
        lines[idx] = json.dumps(rec, ensure_ascii=False)
        copy = s.dir / "tampered"
        if copy.exists():
            self._remove_inside(s, copy)
        (copy / ".hsm").mkdir(parents=True)
        (copy / ledger.LEDGER_REL).write_text("\n".join(lines) + "\n")
        return {"edit": {"line": idx + 1, "before": before, "after": after},
                "copy": _verify_dir(copy), "original": _verify_dir(s.ledger_dir)}

    def _remove_inside(self, s: Session, path: Path) -> None:
        p = path.resolve()
        if s.dir.resolve() in p.parents:
            shutil.rmtree(p, ignore_errors=True)


def _pick_edit(lines: list[str]) -> tuple[int, str, str]:
    """Prefer turning a deny into an approve: the edit someone would want to make."""
    recs = [json.loads(ln) for ln in lines]
    flips = {"human:deny": "human:approve", "policy:deny": "policy:approve", "llm:block": "llm:approve"}
    for want, flip in flips.items():
        for i, r in enumerate(recs):
            summ = str(r.get("summary", ""))
            if summ.startswith(want):
                return i, summ, flip + summ[len(want):]
    i = next((i for i, r in enumerate(recs) if r.get("action") == "gate.decision"), len(recs) - 1)
    summ = str(recs[i].get("summary", ""))
    return i, summ, summ + " (edited)"


def _verify_dir(vault: Path) -> dict:
    path = vault / ledger.LEDGER_REL
    if not path.exists():
        return {"ok": True, "count": 0, "records": [], "breaks": []}
    breaks = ledger.verify_chain(vault=vault)
    records = []
    for i, ln in enumerate(path.read_text().splitlines()):
        try:
            r = json.loads(ln)
        except ValueError:
            records.append({"line": i + 1, "summary": "(not valid JSON)"})
            continue
        records.append({"line": i + 1, "seq": r.get("seq"), "ts": r.get("ts"), "action": r.get("action"),
                        "summary": r.get("summary"), "hash": r.get("hash"), "prev_hash": r.get("prev_hash")})
    return {"ok": not breaks, "count": len(records), "records": records,
            "breaks": [{"line": b.index + 1, "kind": b.kind, "detail": b.detail} for b in breaks]}


# ---------------------------------------------------------------- HTTP

def make_handler(app: App):
    class H(BaseHTTPRequestHandler):
        server_version = "homestead-demo"
        sys_version = ""

        def log_message(self, fmt, *args):   # no bodies, no cookies in logs
            pass

        # -- helpers
        def _sid(self) -> str | None:
            c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return c[COOKIE].value if COOKIE in c else None

        def _session(self, create=True) -> Session | None:
            s = app.session(self._sid(), create=create)
            if s and s.id != self._sid():
                self._new_cookie = s.id
            return s

        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                             "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
            self._cookie_header()
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _cookie_header(self):
            sid = getattr(self, "_new_cookie", None)
            if sid:
                secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "") == "https" else ""
                self.send_header("Set-Cookie", f"{COOKIE}={sid}; Path=/; HttpOnly; SameSite=Strict; "
                                               f"Max-Age={int(app.ttl)}{secure}")
                self._new_cookie = None

        def _json(self, status: int, obj) -> None:
            self._send(status, json.dumps(obj).encode(), "application/json")

        def _body(self) -> dict | None:
            if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                self._json(415, {"error": "send JSON"})
                return None
            origin = self.headers.get("Origin")
            if origin and urlparse(origin).netloc != self.headers.get("Host", ""):
                self._json(403, {"error": "cross-site request refused"})
                return None
            n = int(self.headers.get("Content-Length") or 0)
            if n > MAX_BODY:
                self._json(413, {"error": "too large"})
                return None
            try:
                d = json.loads(self.rfile.read(n) or b"{}")
                return d if isinstance(d, dict) else {}
            except ValueError:
                self._json(400, {"error": "bad JSON"})
                return None

        # -- routes
        def do_GET(self):
            path = urlparse(self.path).path
            try:
                if path in ("/", "/index.html"):
                    return self._send(200, (STATIC / "index.html").read_bytes(), "text/html; charset=utf-8")
                if path in ("/static/app.js", "/static/md.js", "/static/style.css"):
                    ctype = "text/javascript" if path.endswith(".js") else "text/css"
                    return self._send(200, (STATIC / path.rsplit("/", 1)[1]).read_bytes(), ctype + "; charset=utf-8")
                if path == "/api/config":
                    s = self._session(create=False)       # a session starts with the first run
                    active = s.active if s and s.active and not s.active.done else None
                    return self._json(200, {
                        "active_run": active.id if active else None,
                        "reviewer_model": reviewer_model(),
                        "brain": app.brain_label(), "reviewer": reviewer_label(),
                        "reviewer_kind": reviewer_kind(),
                        "scenarios": {k: v for k, v in SCENARIOS.items()},
                        "skills": app.skills(s), "safe_tools": list(skills_mod.SAFE_TOOLS),
                        "skill_max": skills_mod.INSTRUCTION_MAX,
                        "default_injection": DEFAULT_INJECTION, "injection_max": INJECTION_MAX,
                        "limits": {"session_runs_per_hour": app.session_runs_per_hour,
                                   "global_runs_per_hour": app.global_window.limit,
                                   "token_budget": app.token_budget,
                                   "approval_timeout_s": app.approval_timeout_s,
                                   "override_delay_s": app.override_delay_s,
                                   "session_ttl_min": int(app.ttl // 60)}})
                if path == "/api/verify":
                    s = self._session(create=False)
                    return self._json(200, app.verify(s) if s else {"ok": True, "count": 0, "records": [], "breaks": []})
                if path.startswith("/api/runs/") and path.endswith("/events"):
                    return self._events(path.split("/")[3])
                if path == "/healthz":
                    return self._json(200, {"ok": True})
                return self._json(404, {"error": "not found"})
            except LimitError as e:
                return self._json(e.status, {"error": str(e)})

        def do_POST(self):
            path = urlparse(self.path).path
            d = self._body()
            if d is None:
                return
            try:
                if path == "/api/run":
                    s = self._session()
                    run = app.start_run(s, str(d.get("scenario", "")), str(d.get("injection") or ""),
                                        bool(d.get("unguarded")), skill=str(d.get("skill") or ""))
                    return self._json(200, {"run_id": run.id})
                if path == "/api/skill":
                    s = self._session()
                    return self._json(200, {"skills": app.add_skill(s, str(d.get("name") or ""),
                                                                    str(d.get("instruction") or ""))})
                s = self._session(create=False)
                if s is None:
                    return self._json(404, {"error": "no session"})
                if path == "/api/decide":
                    ok, msg = app.decide(s, d.get("run_id", ""), d.get("rid", ""), d.get("decision", ""),
                                         d.get("phrase", ""))
                    return self._json(200 if ok else 409, {"ok": ok, "message": msg})
                if path == "/api/tamper":
                    return self._json(200, app.tamper(s))
                if path == "/api/remember":
                    return self._json(200, app.remember(s, str(d.get("run_id") or ""), str(d.get("rid") or ""),
                                                        str(d.get("name") or "")))
                return self._json(404, {"error": "not found"})
            except LimitError as e:
                return self._json(e.status, {"error": str(e)})

        def _events(self, run_id: str):
            s = self._session(create=False)
            run = s.runs.get(run_id) if s else None
            if run is None:
                return self._json(404, {"error": "no such run"})
            try:
                idx = int(self.headers.get("Last-Event-ID", "-1")) + 1
            except ValueError:
                idx = 0
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()
            try:
                while True:
                    with run.cond:
                        if idx >= len(run.events) and not run.done:
                            run.cond.wait(15)
                        batch, finished = run.events[idx:], run.done
                    for ev in batch:
                        self.wfile.write(f"id: {ev['seq']}\nevent: {ev['type']}\ndata: {json.dumps(ev['data'])}\n\n".encode())
                    idx += len(batch)
                    if finished and idx >= len(run.events):
                        self.wfile.write(b"event: end\ndata: {}\n\n")
                        self.wfile.flush()
                        return
                    if not batch:
                        self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return

    return H


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    app = App()
    srv = ThreadingHTTPServer((host, port), make_handler(app))
    srv.daemon_threads = True

    def janitor():
        while True:
            time.sleep(60)
            app.sweep()

    threading.Thread(target=janitor, daemon=True).start()
    print(f"homestead web demo on http://{host}:{port}")
    print(f"  brain:    {app.brain_label()}")
    print(f"  reviewer: {reviewer_label()}")
    print(f"  sessions: {app.root} (each deleted {int(app.ttl // 60)} minutes after it starts)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        app.close()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m demo.web.server", description="homestead web demo (demo mode)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8000")))
    a = p.parse_args(argv)
    serve(a.host, a.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
