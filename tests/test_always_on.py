"""Always-on passes, held approvals, user-defined skills and memory from the CLI.
No network, no model loads, no real notifications."""
import json
import urllib.error
import urllib.request
from datetime import datetime

import pytest
from homestead_memory.core import ledger

from homestead_gate import always_on, cli
from homestead_gate import assistant as asst
from homestead_gate import skills as sk
from homestead_gate.approval import TerminalApprover
from homestead_gate.cli import main as cli_main
from homestead_gate.llm import ChatClient
from homestead_gate.policy import Policy
from test_assistant import ATTACKER, KEY, Asked, FakeReviewer, ScriptedLLM, call, calls, done

DENTIST = "appointments@brightsmile-dental.example"
REAL_NOTIFY = always_on.notify      # saved before the fixture swaps it out
REAL_FROM_PRESET = ChatClient.from_preset


@pytest.fixture(autouse=True)
def _guards(monkeypatch):
    def refuse(*a, **kw):
        raise AssertionError("a test tried to reach the network")

    def ollama_down(url, *a, **kw):
        # First setup reads the reviewer's digest from Ollama (pin.py); here Ollama is simply down.
        # Anything else is still the network, and still fails the test.
        if ":11434" in str(getattr(url, "full_url", url)):
            raise urllib.error.URLError("ollama is not running (test)")
        refuse()
    monkeypatch.setattr(urllib.request, "urlopen", ollama_down)
    monkeypatch.delenv("HSM_VAULT", raising=False)
    shown = []
    # no test may pop a real desktop notification: swap notify, and fail loudly if anything still
    # tries to run a notifier
    monkeypatch.setattr(always_on, "notify", lambda title, msg: shown.append((title, msg)) or True)
    inner = always_on.subprocess.run

    def no_notifier(argv, *a, **kw):
        if str((argv or [""])[0]).rsplit("/", 1)[-1] in ("osascript", "notify-send"):
            raise AssertionError("a test tried to show a real desktop notification")
        return inner(argv, *a, **kw)
    monkeypatch.setattr(always_on.subprocess, "run", no_notifier)
    return shown


def brain(*turns):
    t = ScriptedLLM(*turns)
    return ChatClient.from_preset("nim", api_key=KEY, transport=t, sleep=lambda s: None), t


def seeded(tmp_path):
    data = tmp_path / "d"
    asst.seed(data, model="fake")
    return data


FIRST = [calls(call("list_inbox")), calls(call("read_email", id="msg-001")),
         calls(call("send_email", to="dana@example.com", subject="Re: Saturday?", body="Yes, 7pm works.")),
         done("**Replied** to Dana.\n\n- nothing else")]
SECOND = [calls(call("list_inbox")), calls(call("read_email", id="msg-005")),
          calls(call("pay_invoice", invoice_id="INV-104", to=asst.NEW_WALLET, value_eth=0.02)),
          calls(call("read_email", id="msg-006")),
          calls(call("send_email", to=DENTIST, subject="Re: Cleaning on Tuesday", body="Confirmed.")),
          done("Sam says his wallet changed. I did not pay.")]


def run_pass(data, turns, notify=None, **kw):
    llm, t = brain(*turns)
    shown = []
    p = always_on.run_pass(data, sk.load_skills(data)["triage"], llm=llm, reviewer=kw.pop("reviewer", FakeReviewer()),
                           notify_fn=notify or (lambda a, b: shown.append((a, b))), log=lambda s: None, **kw)
    return p, t, shown


# ---- skills ----------------------------------------------------------------------------

def test_seed_writes_default_skills_and_old_data_dirs_get_them(tmp_path):
    data = seeded(tmp_path)
    skills = sk.load_skills(data)
    assert set(skills) == {"triage", "pay", "summarize"} and skills["triage"].schedule == "every 15m"
    assert all(s.origin == "default" for s in skills.values())
    (data / "skills.toml").unlink()
    assert asst.seed(data, model="fake") is False          # an old data dir: seed stops early...
    assert sk.ensure_skills_file(data) and (data / "skills.toml").exists()   # ...this writes them


def test_default_skill_instructions_only_ask_to_spend_when_they_mean_it():
    asks = {s.name: Policy.task_asks_to_spend(s.instruction) for s in sk.DEFAULT_SKILLS}
    assert asks == {"triage": False, "pay": True, "summarize": False}


def test_your_own_skill_round_trips_and_bad_ones_are_refused(tmp_path):
    data = seeded(tmp_path)
    mine = sk.validate("rent", "Email my landlord that the sink is fixed.", ["list_inbox", "send_email"], "1h")
    sk.save_skill(data, mine)
    skills = sk.load_skills(data)
    assert skills["rent"].instruction == mine.instruction and skills["rent"].origin == "yours"
    assert skills["triage"].origin == "default"                       # the others are kept
    for bad in [("Bad Name", "x", None, ""), ("ok", "", None, ""), ("ok", "x", ["approve"], ""),
                ("ok", "x", ["send_email"], "whenever"), ("ok", "x" * 501, None, "")]:
        with pytest.raises(sk.SkillError):
            sk.validate(*bad)
    (data / "skills.toml").write_text('[skills.evil]\ninstruction = "x"\ntools = ["gate_approve"]\n')
    with pytest.raises(sk.SkillError, match="do not exist"):
        sk.load_skills(data)


def test_parse_interval():
    assert sk.parse_interval("15m") == 900 and sk.parse_interval("every 1h") == 3600
    assert sk.parse_interval("90s") == 90 and sk.parse_interval("every 2 hours") == 7200
    with pytest.raises(sk.SkillError):
        sk.parse_interval("soon")


def test_a_skill_only_offers_and_accepts_its_tools(tmp_path):
    data = seeded(tmp_path)
    llm, t = brain(calls(call("send_email", to="dana@example.com", subject="hi", body="x")),
                   calls(call("pay_invoice", invoice_id="INV-104", to=asst.SAM_WALLET, value_eth=0.02)), done())
    pay = sk.load_skills(data)["pay"]
    bot = asst.Assistant(llm=llm, submit=lambda r: pytest.fail("nothing may reach the gate"), data_dir=data,
                         memory=asst.AssistantMemory(data / "memory"), task="Read my mail.",
                         tools=sk.SAFE_TOOLS[:4])
    out = bot.run()
    offered = {x["function"]["name"] for x in t.requests[0]["body"]["tools"]}
    assert offered == {"list_inbox", "read_email", "list_bills", "recall"}
    assert out["steps"][0]["result"] == {"error": "tool 'send_email' is not part of this skill"}
    assert "pay_invoice" not in offered and pay.tools == ("recall", "list_bills", "pay_invoice")


# ---- always-on passes ---------------------------------------------------------------------

def test_first_pass_handles_the_inbox_and_leaves_a_brief(tmp_path):
    data = seeded(tmp_path)
    p, t, shown = run_pass(data, FIRST, now=datetime(2026, 10, 2, 7, 0))
    assert len(p.new_mail) == 4 and not p.error
    assert sorted(always_on.load_state(data)["seen"]) == ["msg-001", "msg-002", "msg-003", "msg-004"]
    brief = (data / "brief.md").read_text()
    assert brief.startswith("# Brief, 2026-10-02 07:00") and "**4 new emails**" in brief
    assert 'Email Dana Okafor (dana@example.com), "Re: Saturday?": approved by the policy' in brief
    assert "## In the assistant's words" in brief and "> **Replied** to Dana." in brief
    assert len(list((data / "briefs").glob("*.md"))) == 1
    assert shown == [("homestead", "4 new, 1 done, 0 waiting for you")]


def test_nothing_new_means_no_cloud_call(tmp_path):
    data = seeded(tmp_path)
    run_pass(data, FIRST, now=datetime(2026, 10, 2, 7, 0))
    p, t, shown = run_pass(data, [], now=datetime(2026, 10, 2, 7, 15))   # any call would fail: no turns
    assert not p.new_mail and not t.requests and not shown
    brief = (data / "brief.md").read_text()
    assert "Nothing new, so the cloud model was not called." in brief
    assert "since the last run (2026-10-02 07:00)" in brief


def test_second_pass_sees_only_new_mail_and_refuses_the_new_wallet(tmp_path):
    data = seeded(tmp_path)
    run_pass(data, FIRST, now=datetime(2026, 10, 2, 7, 0))
    asst.deliver_later_mail(data)
    turns = [calls(call("read_email", id="msg-001"))] + SECOND
    p, t, shown = run_pass(data, turns, now=datetime(2026, 10, 2, 7, 15))
    assert [m["id"] for m in p.new_mail] == ["msg-005", "msg-006"]
    steps = [json.loads(m["content"]) for m in t.requests[-1]["body"]["messages"] if m["role"] == "tool"]
    assert steps[0] == {"error": "no email 'msg-001'"}                          # old mail is out of reach
    assert [m["id"] for m in steps[1]["messages"]] == ["msg-005", "msg-006"]
    assert "refused before the gate" in steps[3]["error"]
    # the new wallet never became a gate request; the dentist reply was held, not sent
    recs = ledger.read_all(data / "ledger")
    assert asst.NEW_WALLET not in json.dumps(recs)
    held = [r for r in recs if r["action"] == "gate.decision" and r["meta"].get("decided_by") == "human:held"]
    assert len(held) == 1 and recs[-1]["action"] == "gate.expired"
    assert not list((data / "outbox").glob("*dental*")) and len(list((data / "outbox").glob("*.eml"))) == 1
    brief = (data / "brief.md").read_text()
    waiting = brief.split("## Waiting for you")[1].split("##")[0]
    assert f"Pay 0.02 ETH to {asst.NEW_WALLET}: not done, refused before the gate" in waiting
    assert f"The wallet you saved: {asst.SAM_WALLET} (written by you; added by you on 2026-09-22)" in waiting
    assert f'Email {DENTIST}, "Re: Cleaning on Tuesday": held for your yes' in waiting
    assert "## Memory it used" in brief and f"Sam Rivera, wallet: {asst.SAM_WALLET} (written by you; added by you on 2026-09-22)" in brief
    assert shown == [("homestead", "2 new, 0 done, 2 waiting for you")]
    pend = always_on.load_pending(data)
    assert pend[0]["action"]["to"] == DENTIST and pend[0]["task"] == asst.SKILLS["triage"]
    assert any("msg-006" in r["source"] for r in pend[0]["reads"])


def test_notification_carries_counts_only(tmp_path):
    data = seeded(tmp_path)
    inbox = json.loads((data / "inbox.json").read_text())
    inbox[0]["subject"] = "SECRET-SUBJECT"
    (data / "inbox.json").write_text(json.dumps(inbox))
    p, _, shown = run_pass(data, [done("SECRET-SUMMARY")])
    assert "SECRET" not in json.dumps(shown) and "SECRET-SUBJECT" in (data / "brief.md").read_text()


def test_a_failed_pass_leaves_the_mail_for_next_time(tmp_path):
    data = seeded(tmp_path)
    p, _, shown = run_pass(data, [(400, b"bad", {})])
    assert p.error and "seen" not in always_on.load_state(data) or not always_on.load_state(data)["seen"]
    assert "The run did not finish" in (data / "brief.md").read_text()
    assert always_on.new_mail(data) and shown == [("homestead", "a scheduled run failed; see the brief")]


def test_passes_do_not_overlap(tmp_path):
    data = seeded(tmp_path)
    with always_on._Lock(data / always_on.LOCK_FILE) as got:
        assert got
        p, t, _ = run_pass(data, FIRST)
    assert p.skipped and not t.requests and "seen" not in always_on.load_state(data)


def test_hold_approver_never_approves():
    h = always_on.HoldApprover()
    for flagged in (True, False):
        d = h.ask(rid="r", action={"type": "email", "to": "x"}, flagged=flagged, review_reason="", span="")
        assert d.decision == "expired" and d.channel == "held"


def test_daily_cap_replays_on_every_pass(tmp_path):
    data = seeded(tmp_path)
    pay = sk.validate("payday", "Pay Sam the plumber's invoice.", ["recall", "list_bills", "pay_invoice"])
    for i in range(2):
        llm, _ = brain(calls(call("pay_invoice", invoice_id="INV-104", to=asst.SAM_WALLET, value_eth=0.02)), done())
        inbox = json.loads((data / "inbox.json").read_text())
        inbox.append({"id": f"tick-{i}", "from": "x@example.com", "subject": "tick", "date": "", "body": ""})
        (data / "inbox.json").write_text(json.dumps(inbox))
        p = always_on.run_pass(data, pay, llm=llm, reviewer=FakeReviewer(), notify_fn=lambda a, b: None,
                               log=lambda s: None)
    # second payment would take autonomous spend to 0.04 > 0.035: held for you, not auto-paid
    assert len(p.done) == 0 and "held for your yes" in p.waiting[0]


# ---- held items go through the whole gate again -------------------------------------------

def _held(tmp_path):
    data = seeded(tmp_path)
    run_pass(data, FIRST)
    asst.deliver_later_mail(data)
    run_pass(data, SECOND)
    return data


def test_pending_goes_through_the_gate_with_the_terminal_approver(tmp_path):
    data = _held(tmp_path)
    asked = Asked("y")
    approver = TerminalApprover(override_delay_s=0, timeout_s=5, input_fn=asked, out=lambda s: None,
                                sleep=lambda s: None)
    rv = FakeReviewer()
    res = always_on.resolve_pending(data, policy_factory=lambda: asst.load_policy(data), reviewer=rv,
                                    approver=approver, log=lambda s: None)
    assert res[0]["result"]["status"] == "executed" and res[0]["result"]["by"] == "human:terminal"
    assert asked.prompts == ["approve? [y/N] "] and "Cleaning on Tuesday" in rv.prompts[0]
    assert always_on.load_pending(data) == []
    assert not ledger.verify_chain(data / "ledger")


def test_an_edited_queue_item_is_still_judged_by_the_gate(tmp_path):
    data = _held(tmp_path)
    items = always_on.load_pending(data)
    items[0]["action"]["to"] = ATTACKER                     # someone with your files edits the queue
    always_on.save_pending(data, items)
    asked = Asked("n")
    approver = TerminalApprover(override_delay_s=0, timeout_s=5, input_fn=asked, out=lambda s: None,
                                sleep=lambda s: None)
    rv = FakeReviewer()
    res = always_on.resolve_pending(data, policy_factory=lambda: asst.load_policy(data), reviewer=rv,
                                    approver=approver, log=lambda s: None)
    assert res[0]["result"]["status"] == "denied" and res[0]["result"]["review"] == "block"
    assert ATTACKER in rv.prompts[0].split("PROPOSED ACTION:")[-1] and asked.prompts


def test_an_edited_held_payment_to_an_unsaved_wallet_never_reaches_the_gate(tmp_path):
    data = _held(tmp_path)
    items = always_on.load_pending(data)
    items.append({**items[0], "id": "x", "action": {"type": "wallet_tx", "chain_id": 11155111,
                                                   "to": asst.NEW_WALLET, "value_eth": 0.02}})
    always_on.save_pending(data, items)
    before = len(ledger.read_all(data / "ledger"))
    res = always_on.resolve_pending(data, policy_factory=lambda: asst.load_policy(data), reviewer=FakeReviewer(),
                                    approver=always_on.HoldApprover(), log=lambda s: None)
    assert res[1]["result"]["status"] == "refused"
    new = ledger.read_all(data / "ledger")[before:]
    assert asst.NEW_WALLET not in json.dumps(new) and len([r for r in new if r["action"] == "gate.request"]) == 1
    assert [i["action"]["to"] for i in always_on.load_pending(data)] == [DENTIST]   # dropped, not kept


def test_cli_watch_uses_the_notifier_it_finds_at_call_time(tmp_path, monkeypatch, _guards):
    d = tmp_path / "d"
    _cli_brain(monkeypatch, *FIRST)
    assert cli_main(["assistant", "--data", str(d), "--watch", "--once", "--no-model"]) == 0
    assert _guards == [("homestead", "4 new, 0 done, 1 waiting for you")]


def test_unanswered_items_stay_queued(tmp_path):
    data = _held(tmp_path)
    res = always_on.resolve_pending(data, policy_factory=lambda: asst.load_policy(data), reviewer=FakeReviewer(),
                                    approver=always_on.HoldApprover(), log=lambda s: None)
    assert res[0]["result"]["status"] == "expired" and len(always_on.load_pending(data)) == 1


# ---- notifications -------------------------------------------------------------------------

def test_notify_passes_text_as_arguments(monkeypatch):
    ran = []
    monkeypatch.setattr(always_on.subprocess, "run", lambda argv, **kw: ran.append(argv))
    monkeypatch.setattr(always_on.sys, "platform", "darwin")
    monkeypatch.setattr(always_on.shutil, "which", lambda n: "/usr/bin/" + n)
    msg = 'x" & do shell script "echo pwned'
    assert REAL_NOTIFY("homestead", msg) is True
    assert ran[-1][:2] == ["osascript", "-e"] and ran[-1][-1] == msg and msg not in " ".join(ran[-1][:-1])
    monkeypatch.setattr(always_on.sys, "platform", "linux")
    assert REAL_NOTIFY("homestead", "3 new") is True and ran[-1] == ["notify-send", "homestead", "3 new"]
    monkeypatch.setattr(always_on.shutil, "which", lambda n: None)
    assert REAL_NOTIFY("homestead", "3 new") is False and len(ran) == 2


# ---- the CLI ------------------------------------------------------------------------------

def test_memory_and_remember_need_no_api_key(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    d = str(tmp_path / "d")
    assert cli_main(["assistant", "--data", d, "--remember", "Kim Lee", "email", "kim@example.org"]) == 0
    assert cli_main(["assistant", "--data", d, "--memory"]) == 0
    out = capsys.readouterr().out
    assert "Kim Lee, email: kim@example.org" in out and "written by you" in out
    assert "Sam Rivera, wallet: " + asst.SAM_WALLET in out
    assert "kim@example.org" in asst.load_policy(tmp_path / "d").email_allow
    assert cli_main(["assistant", "--data", d, "--skills"]) == 0
    assert "triage (every 15m)" in capsys.readouterr().out


def _cli_brain(monkeypatch, *turns):
    from homestead_gate import llm as llm_mod
    original = REAL_FROM_PRESET
    t = ScriptedLLM(*turns)
    monkeypatch.setattr(llm_mod.ChatClient, "from_preset", classmethod(
        lambda cls, name, **kw: original(name, api_key=KEY, transport=t, sleep=lambda s: None)))
    monkeypatch.setenv("NEBIUS_API_KEY", KEY)
    return t


def test_cli_watch_once_then_pending_then_remember(tmp_path, monkeypatch, capsys):
    d = tmp_path / "d"
    _cli_brain(monkeypatch, *FIRST)
    assert cli_main(["assistant", "--data", str(d), "--watch", "--once", "--no-model"]) == 0
    out = capsys.readouterr().out
    assert "watching: skill triage once" in out and "brief: " + str(d / "brief.md") in out
    # --no-model: every non-self action needs you, so even Dana's reply is held
    assert len(always_on.load_pending(d)) == 1
    assert cli_main(["assistant", "--data", str(d), "--demo-new-mail"]) == 0
    _cli_brain(monkeypatch, *SECOND)
    assert cli_main(["assistant", "--data", str(d), "--watch", "--once", "--no-model"]) == 0
    assert "2 new, 0 done, 3 waiting for you" in capsys.readouterr().out
    # --no-model: no review, which counts as a flag, so each needs the override phrase
    asked = Asked("y", "send anyway", "y", "y", "send anyway", "y")
    monkeypatch.setattr(cli, "TerminalApprover", lambda **kw: TerminalApprover(
        override_delay_s=0, timeout_s=5, input_fn=asked, out=print, sleep=lambda s: None))
    names = iter(["Bright Smile Dental"])          # Dana is already a contact: not offered
    monkeypatch.setattr(cli, "_ask", lambda prompt: next(names))
    assert cli_main(["assistant", "--data", str(d), "--pending", "--no-model"]) == 0
    assert always_on.load_pending(d) == []
    dentist = asst.AssistantMemory(d / "memory").contacts()[DENTIST]
    assert dentist["entity"] == "Bright Smile Dental" and dentist["written_by"] == "user"
    assert dentist["source"].startswith("approved by you on ")
    assert DENTIST in asst.load_policy(d).email_allow          # next time it is a known contact


def test_cli_offers_to_remember_only_what_you_approved(tmp_path, monkeypatch, capsys):
    d = tmp_path / "d"
    new = calls(call("send_email", to="kim@example.org", subject="Hi", body="Hello Kim."))
    to_attacker = calls(call("send_email", cid="c2", to=ATTACKER, subject="x", body="y"))
    _cli_brain(monkeypatch, new, to_attacker, done())
    asked = Asked("y", "send anyway", "y", "n")              # yes to Kim (flag override), no to the attacker
    monkeypatch.setattr(cli, "TerminalApprover", lambda **kw: TerminalApprover(
        override_delay_s=0, timeout_s=5, input_fn=asked, out=print, sleep=lambda s: None))
    offered = []
    monkeypatch.setattr(cli, "_ask", lambda prompt: offered.append(prompt) or "Kim Lee")
    assert cli_main(["assistant", "--data", str(d), "--task", "Say hello to kim@example.org", "--no-model"]) == 0
    assert len(offered) == 1 and "kim@example.org" in offered[0]
    kim = asst.AssistantMemory(d / "memory").contacts()["kim@example.org"]
    assert kim["written_by"] == "user" and kim["source"].startswith("approved by you on ")
    assert ATTACKER not in asst.AssistantMemory(d / "memory").contacts()


def test_cli_unknown_skill_and_task_with_watch(tmp_path, monkeypatch, capsys):
    _cli_brain(monkeypatch, done())
    d = str(tmp_path / "d")
    assert cli_main(["assistant", "--data", d, "--skill", "nope", "--no-model"]) == 2
    assert "no skill 'nope'" in capsys.readouterr().err
    assert cli_main(["assistant", "--data", d, "--watch", "--task", "x", "--no-model"]) == 2


def test_cli_runs_a_skill_you_wrote(tmp_path, monkeypatch, capsys):
    d = tmp_path / "d"
    asst.seed(d, model="fake")
    sk.save_skill(d, sk.validate("bills", "List my open bills.", ["list_bills"]))
    t = _cli_brain(monkeypatch, calls(call("list_bills")), done("One bill."))
    assert cli_main(["assistant", "--data", str(d), "--skill", "bills", "--no-model"]) == 0
    assert {x["function"]["name"] for x in t.requests[0]["body"]["tools"]} == {"list_bills"}
    assert t.requests[0]["body"]["messages"][1]["content"] == "List my open bills."
    assert "[skill bills]" in capsys.readouterr().out
