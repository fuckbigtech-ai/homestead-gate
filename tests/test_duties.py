"""Separation of duties and what the approver saw: who approved, who changed the rules, optional dual
control, and no yes on a card that cut something short until all of it was shown.

Offline: fake reviewer, scripted terminal input, temporary ledgers and policy folders. Nothing here
touches the keychain or the network.
"""
import hashlib
import json
import stat
import sys
import threading
import time
from pathlib import Path

import pytest
from homestead_memory.core import ledger

from homestead_gate import approvers
from homestead_gate.always_on import HoldApprover
from homestead_gate.approval import (BODY_LINES, FIELD_CHARS, HumanDecision, TerminalApprover, approver_identity,
                                     needs_full_view)
from homestead_gate.cli import main as cli_main
from homestead_gate.core import Gate
from homestead_gate.policy import Policy
from homestead_gate.reviewer import Verdict

REPO = Path(__file__).resolve().parents[1]
ME, ZERO = "me@example.com", "0x" + "0" * 40
STRANGER = "someone@example.org"
SECRET = "correct horse battery staple"

POLICY = """[user]
email = "me@example.com"

[evm]
chain_id = 11155111
max_value_eth = 0.05

[approval]
override_delay_s = 0
timeout_s = 5
{extra}
"""


class FakeReviewer:
    def __init__(self, verdict="approve"):
        self.verdict = verdict

    def review(self, prompt):
        return Verdict(self.verdict, "fake", "", "fake", 0.0)


def terminal(*answers, secrets=(), seen=None):
    it, sec = iter(answers), iter(secrets)
    asked = [] if seen is None else seen

    def inp(prompt, t):
        asked.append(prompt)
        return next(it)

    def secret(prompt, t):
        asked.append(prompt)
        return next(sec)
    return TerminalApprover(override_delay_s=0, timeout_s=5, input_fn=inp, secret_fn=secret,
                            out=asked.append, sleep=lambda s: None)


def write_policy(folder: Path, extra: str = "") -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    p = folder / "policy.toml"
    p.write_text(POLICY.format(extra=extra))
    return p


def gate(tmp_path, approver, policy=None, verdict="approve", task="email the summary"):
    policy = policy or Policy.load(write_policy(tmp_path / "pol"))
    return Gate(policy=policy, reviewer=FakeReviewer(verdict), approver=approver, ledger_dir=tmp_path / "l",
                task=task, session="t", outbox=tmp_path / "out")


def recs(tmp_path):
    return ledger.read_all(tmp_path / "l")


def decision(tmp_path):
    return [r for r in recs(tmp_path) if r["action"] == "gate.decision"][-1]


def email(body="hello", **kw):
    return {"type": "email", "to": STRANGER, "subject": "s", "body": body, **kw}


def tx(**kw):
    return {"type": "wallet_tx", "chain_id": 11155111, "to": ZERO, "value_eth": 0.01, **kw}


# ---- 1. who approved ------------------------------------------------------------------------

def test_human_decision_receipt_names_the_approving_account(tmp_path):
    g = gate(tmp_path, terminal("y"))
    assert g.submit({"action": email()})["status"] == "executed"
    who = decision(tmp_path)["meta"]["approver"]
    assert who["channel"] == "terminal"
    assert who["os_user"] and who["host"] and isinstance(who["uid"], int)
    assert "tty" in who                    # None under pytest (stdin is not a terminal), a path in `up`
    assert decision(tmp_path)["meta"]["decided_by"] == "human:terminal"


def test_identity_comes_from_the_approving_process():
    who = approver_identity("terminal")
    import os
    import socket
    assert who["uid"] == os.getuid() and who["host"] == socket.gethostname()


def test_a_deny_records_who_said_no_and_a_held_item_records_nobody(tmp_path):
    g = gate(tmp_path, terminal("n"))
    g.submit({"action": email()})
    assert decision(tmp_path)["meta"]["approver"]["channel"] == "terminal"
    g2 = gate(tmp_path / "h", HoldApprover())
    assert g2.submit({"action": email()})["status"] == "expired"
    held = decision(tmp_path / "h")["meta"]["approver"]
    assert held == {"channel": "held", "identified": False}


# ---- 2. who changed the rules -----------------------------------------------------------------

def test_policy_loaded_receipt_pins_file_hash_and_version(tmp_path):
    path = write_policy(tmp_path / "pol")
    policy = Policy.load(path)
    g = gate(tmp_path, terminal("n"), policy=policy)
    g.submit({"action": email()})
    first = recs(tmp_path)[0]
    assert first["action"] == "policy.loaded"
    assert first["meta"]["policy_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert first["meta"]["policy_version"] == policy.version
    assert first["meta"]["policy_path"] == str(path.resolve())
    # the policy hash is on the decision itself, next to the version that was already there
    d = decision(tmp_path)["meta"]
    assert d["policy_sha256"] == first["meta"]["policy_sha256"] and d["policy_version"] == policy.version


def test_same_policy_next_start_is_loaded_not_changed(tmp_path):
    path = write_policy(tmp_path / "pol")
    for _ in range(2):
        gate(tmp_path, terminal("n"), policy=Policy.load(path)).submit({"action": email()})
    kinds = [r["action"] for r in recs(tmp_path) if r["action"].startswith("policy.")]
    assert kinds == ["policy.loaded", "policy.loaded"]


def test_an_edited_policy_is_recorded_old_hash_to_new(tmp_path):
    path = write_policy(tmp_path / "pol")
    old = Policy.load(path)
    gate(tmp_path, terminal("n"), policy=old).submit({"action": email()})
    path.write_text(path.read_text().replace("max_value_eth = 0.05", "max_value_eth = 0.04"))
    new = Policy.load(path)
    gate(tmp_path, terminal("n"), policy=new).submit({"action": email()})
    ch = [r for r in recs(tmp_path) if r["action"] == "policy.changed"]
    assert len(ch) == 1
    m = ch[0]["meta"]
    assert m["previous"]["policy_sha256"] == old.file_sha256 and m["policy_sha256"] == new.file_sha256
    assert m["previous"]["policy_version"] == old.version and m["policy_version"] == new.version
    assert set(m["changed"]) == {"policy_sha256", "policy_version"}


def test_a_comment_only_edit_still_changes_the_file_hash(tmp_path):
    path = write_policy(tmp_path / "pol")
    gate(tmp_path, terminal("n"), policy=Policy.load(path)).submit({"action": email()})
    path.write_text(path.read_text() + "# just a note\n")
    gate(tmp_path, terminal("n"), policy=Policy.load(path)).submit({"action": email()})
    ch = [r for r in recs(tmp_path) if r["action"] == "policy.changed"][0]["meta"]
    assert ch["changed"] == ["policy_sha256"]            # the rules are the same; the file is not


def test_editing_the_file_under_a_running_gate_leaves_a_receipt(tmp_path):
    path = write_policy(tmp_path / "pol")
    g = gate(tmp_path, terminal("n", "n"), policy=Policy.load(path))
    g.submit({"action": email()})
    path.write_text(path.read_text().replace("max_value_eth = 0.05", "max_value_eth = 0.05\n# edited"))
    g.submit({"action": email(body="again")})
    ed = [r for r in recs(tmp_path) if r["action"] == "policy.edited"]
    assert len(ed) == 1
    assert ed[0]["meta"]["on_disk_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert ed[0]["meta"]["in_force_sha256"] == g.policy.file_sha256 != ed[0]["meta"]["on_disk_sha256"]


def test_rules_changed_in_memory_are_recorded_before_the_next_request(tmp_path):
    g = gate(tmp_path, terminal("n", "n"))
    g.submit({"action": email()})
    g.policy.email_allow.append(STRANGER)               # e.g. the demo, or a remembered contact
    g.submit({"action": email(body="again")})
    ch = [r for r in recs(tmp_path) if r["action"] == "policy.changed"]
    assert len(ch) == 1 and ch[0]["meta"]["changed"] == ["policy_version"]


def test_up_writes_the_policy_receipt_at_startup(tmp_path):
    g = gate(tmp_path, terminal())
    g.record_policy()
    g.record_policy()                                    # idempotent
    assert [r["action"] for r in recs(tmp_path)] == ["policy.loaded"]


def test_an_idle_pass_writes_nothing(tmp_path):
    gate(tmp_path, terminal())
    assert not (tmp_path / "l").exists()


def test_policy_built_in_code_has_no_file_hash(tmp_path):
    g = gate(tmp_path, terminal("n"), policy=Policy(user_email=ME))
    g.submit({"action": email()})
    assert recs(tmp_path)[0]["meta"]["policy_sha256"] is None


def test_policy_version_is_unchanged_when_dual_control_is_off():
    # policies written before dual control keep their rule hash, so old receipts still match
    p = Policy(user_email=ME)
    rules = {k: v for k, v in sorted(vars(p).items()) if not k.startswith("_") and k != "dual_control"}
    want = hashlib.sha256(json.dumps(rules, sort_keys=True, default=str).encode()).hexdigest()[:16]
    assert p.version == want
    assert Policy(user_email=ME, dual_control=["wallet_tx"]).version != p.version


# ---- 3. dual control --------------------------------------------------------------------------

def dual(tmp_path, extra='dual_control = ["wallet_tx"]', register=True):
    path = write_policy(tmp_path / "pol", extra)
    if register:
        approvers.add(tmp_path / "pol", "alice", SECRET)
    return Policy.load(path)


def test_dual_control_parses_both_forms(tmp_path):
    assert dual(tmp_path / "a", register=False).dual_control == ["wallet_tx"]
    assert dual(tmp_path / "b", "second_approver = true", register=False).dual_control == ["*"]
    assert dual(tmp_path / "c", "", register=False).dual_control == []
    with pytest.raises(ValueError):
        dual(tmp_path / "d", 'dual_control = "wallet_tx"', register=False)


def test_dual_control_with_the_right_passphrase_executes_and_names_the_second_approver(tmp_path):
    seen = []
    g = gate(tmp_path, terminal("y", "alice", secrets=[SECRET], seen=seen), policy=dual(tmp_path))
    r = g.submit({"action": tx()})
    assert r["status"] == "executed"
    m = decision(tmp_path)["meta"]
    assert m["dual_control"] == {"required": True, "satisfied": True, "second_approver": "alice"}
    assert "confirmed by alice" in decision(tmp_path)["summary"]
    assert any("second approver name" in s for s in seen)


def test_wrong_passphrase_denies_and_fails_closed(tmp_path):
    g = gate(tmp_path, terminal("y", "alice", secrets=["guess-guess"]), policy=dual(tmp_path))
    r = g.submit({"action": tx()})
    assert r["status"] == "denied"
    m = decision(tmp_path)["meta"]
    assert m["decision"] == "deny" and m["dual_control"] == {"required": True, "satisfied": False,
                                                             "second_approver": None}
    assert not (tmp_path / "out").exists()
    assert not any(x["action"] == "gate.executed" for x in recs(tmp_path))


def test_an_unknown_name_denies_and_is_not_logged(tmp_path):
    g = gate(tmp_path, terminal("y", "mallory-typed-something", secrets=[SECRET]), policy=dual(tmp_path))
    assert g.submit({"action": tx()})["status"] == "denied"
    assert "mallory-typed-something" not in (tmp_path / "l" / ".hsm" / "ledger.jsonl").read_text()


def test_the_first_person_saying_no_never_reaches_the_second(tmp_path):
    seen = []
    g = gate(tmp_path, terminal("n", seen=seen), policy=dual(tmp_path))
    assert g.submit({"action": tx()})["status"] == "denied"
    assert not any("passphrase" in s for s in seen)


def test_no_second_approver_registered_is_a_policy_deny_without_asking(tmp_path):
    seen = []
    g = gate(tmp_path, terminal(seen=seen), policy=dual(tmp_path, register=False))
    r = g.submit({"action": tx()})
    assert r["status"] == "denied" and r["by"] == "policy" and "approver add" in r["reason"]
    assert not any("approve?" in s for s in seen)


def test_a_silent_second_approver_is_expired(tmp_path):
    g = gate(tmp_path, terminal("y", "alice", secrets=[None]), policy=dual(tmp_path))
    assert g.submit({"action": tx()})["status"] == "expired"


def test_dual_control_applies_only_to_the_named_types(tmp_path):
    g = gate(tmp_path, terminal("y"), policy=dual(tmp_path))
    assert g.submit({"action": email()})["status"] == "executed"
    assert "dual_control" not in decision(tmp_path)["meta"]


def test_dual_control_overrides_the_allowlist_auto_path(tmp_path):
    p = dual(tmp_path)
    p.evm_allow.append(ZERO)
    seen = []
    g = gate(tmp_path, terminal("y", "alice", secrets=[SECRET], seen=seen), policy=p,
             task="pay 0.01 ETH to my contractor")
    assert g.submit({"action": tx()})["status"] == "executed"
    assert decision(tmp_path)["meta"]["decided_by"] == "human:terminal"   # never the policy alone


def test_an_approver_that_cannot_collect_a_second_approval_is_refused(tmp_path):
    class OneClick:
        def ask(self, *, rid, action, flagged, review_reason, span):
            return HumanDecision("approve", "web-demo", 0.0)
    g = gate(tmp_path, OneClick(), policy=dual(tmp_path))
    r = g.submit({"action": tx()})
    assert r["status"] == "denied" and "cannot collect a second approver" in r["reason"]


def test_a_fake_approver_cannot_claim_dual_control(tmp_path):
    class Liar:
        collects_second = True

        def ask(self, *, rid, action, flagged, review_reason, span, second=None):
            return HumanDecision("approve", "terminal", 0.0, second_name="alice", second_secret="not-it")
    g = gate(tmp_path, Liar(), policy=dual(tmp_path))
    assert g.submit({"action": tx()})["status"] == "denied"


def test_the_passphrase_is_never_stored_in_plaintext_or_receipts(tmp_path, capsys):
    out = []
    g = gate(tmp_path, terminal("y", "alice", secrets=[SECRET], seen=out), policy=dual(tmp_path))
    g.submit({"action": tx()})
    stored = approvers.path(tmp_path / "pol").read_text()
    assert SECRET not in stored and SECRET.encode().hex() not in stored
    rec = json.loads(stored)["alice"]
    assert rec["kdf"] == "scrypt" and len(bytes.fromhex(rec["salt"])) == 16
    assert SECRET not in (tmp_path / "l" / ".hsm" / "ledger.jsonl").read_text()
    assert SECRET not in "\n".join(out) and SECRET not in capsys.readouterr().out
    assert stat.S_IMODE(approvers.path(tmp_path / "pol").stat().st_mode) == 0o600


def test_salts_differ_and_verify_rejects_tampering(tmp_path):
    approvers.add(tmp_path, "alice", SECRET)
    approvers.add(tmp_path, "bob", SECRET)
    reg = approvers.load(tmp_path)
    assert reg["alice"]["salt"] != reg["bob"]["salt"] and reg["alice"]["hash"] != reg["bob"]["hash"]
    assert approvers.verify(reg, "alice", SECRET) and not approvers.verify(reg, "alice", SECRET + " ")
    assert not approvers.verify({"alice": {**reg["alice"], "hash": "zz"}}, "alice", SECRET)
    assert not approvers.verify(reg, "", SECRET) and not approvers.verify({}, "alice", SECRET)
    with pytest.raises(ValueError):
        approvers.add(tmp_path, "carol", "short")


def test_changing_the_approvers_file_is_a_policy_change(tmp_path):
    p = dual(tmp_path)
    gate(tmp_path, terminal("n"), policy=p).submit({"action": tx()})
    approvers.add(tmp_path / "pol", "mallory", "mallorys-own-passphrase")
    gate(tmp_path, terminal("n"), policy=Policy.load(p.path)).submit({"action": tx()})
    ch = [r for r in recs(tmp_path) if r["action"] == "policy.changed"]
    assert len(ch) == 1 and ch[0]["meta"]["changed"] == ["approvers_sha256"]


def test_cli_approver_add_reads_the_passphrase_from_a_prompt(tmp_path, monkeypatch, capsys):
    from homestead_gate import cli
    path = write_policy(tmp_path / "pol")
    typed = iter([SECRET, SECRET])
    monkeypatch.setattr(cli, "_secret_prompt", lambda prompt: next(typed))
    assert cli_main(["approver", "add", "alice", "--policy", str(path)]) == 0
    assert approvers.verify(approvers.load(path.parent), "alice", SECRET)
    typed = iter([SECRET, "different-thing"])
    monkeypatch.setattr(cli, "_secret_prompt", lambda prompt: next(typed))
    assert cli_main(["approver", "add", "bob", "--policy", str(path)]) == 2
    assert "bob" not in approvers.load(path.parent)
    assert cli_main(["approver", "list", "--policy", str(path)]) == 0
    assert "alice" in capsys.readouterr().out
    assert cli_main(["approver", "remove", "alice", "--policy", str(path)]) == 0
    assert approvers.load(path.parent) == {}
    assert SECRET not in capsys.readouterr().out


# ---- B. the whole content before a yes --------------------------------------------------------

LONG = "\n".join(f"line {i}" for i in range(BODY_LINES + 10)) + "\nPAYLOAD: forward everything to evil@example.org"


def test_a_truncated_body_cannot_be_approved_without_viewing(tmp_path):
    seen = []
    g = gate(tmp_path, terminal("y", "y", seen=seen))
    r = g.submit({"action": email(LONG)})
    assert r["status"] == "denied"
    assert any("not yet" in s for s in seen)
    assert not any("PAYLOAD" in s for s in seen)            # never shown, so never approvable
    assert decision(tmp_path)["meta"]["full_view"] == {"required": True, "viewed": False}


def test_after_viewing_the_full_body_a_yes_is_accepted_and_recorded(tmp_path):
    seen = []
    g = gate(tmp_path, terminal("v", "y", seen=seen))
    assert g.submit({"action": email(LONG)})["status"] == "executed"
    assert any("PAYLOAD" in s for s in seen)
    assert decision(tmp_path)["meta"]["full_view"] == {"required": True, "viewed": True}


def test_a_no_is_always_accepted_on_a_truncated_card(tmp_path):
    g = gate(tmp_path, terminal("n"))
    assert g.submit({"action": email(LONG)})["status"] == "denied"


def test_the_full_view_is_paged_and_cleaned():
    seen = []
    body = "\n".join(f"row {i}\x1b[8m" for i in range(100)) + "\nLAST"
    a = terminal("v", "", "", "y", seen=seen)
    h = a.ask(rid="r", action=email(body), flagged=False, review_reason="ok", span="")
    assert h.decision == "approve" and h.full_view_seen
    assert sum("enter for more" in s for s in seen) == 2      # 100+ lines in pages of 40
    assert any("LAST" in s for s in seen) and not any("\x1b" in s for s in seen)


def test_running_out_of_time_while_paging_is_expired():
    body = "\n".join(f"row {i}" for i in range(100))
    a = terminal("v", None)
    assert a.ask(rid="r", action=email(body), flagged=False, review_reason="ok", span="").decision == "expired"


def test_a_short_body_is_unchanged(tmp_path):
    seen = []
    g = gate(tmp_path, terminal("y", seen=seen))
    assert g.submit({"action": email("two\nlines")})["status"] == "executed"
    assert "approve? [y/N] " in seen and not any("view all" in s for s in seen)
    assert decision(tmp_path)["meta"]["full_view"] == {"required": False, "viewed": False}


def test_flagged_and_truncated_needs_view_then_the_override(tmp_path):
    g = gate(tmp_path, terminal("v", "y", "send anyway", "y"), verdict="block")
    assert g.submit({"action": email(LONG)})["status"] == "executed"
    m = decision(tmp_path)["meta"]
    assert m["overrode_flag"] and m["full_view"]["viewed"]


def test_long_attachments_and_calldata_get_the_same_treatment():
    att = [{"filename": "a.txt", "content": "x" * (FIELD_CHARS + 50)}]
    assert needs_full_view(email(attachments=att)) == ["attachments"]
    assert needs_full_view(email(bcc=",".join(f"p{i}@example.org" for i in range(60)))) == ["bcc"]
    assert needs_full_view(tx(data="0x" + "ab" * 256)) == []          # the default calldata cap shows whole
    assert needs_full_view(tx(data="0x" + "ab" * 400)) == ["data"]
    seen = []
    a = terminal("y", "y", seen=seen)
    assert a.ask(rid="r", action=email(attachments=att), flagged=False, review_reason="ok",
                 span="").decision == "deny"
    assert any("characters not shown" in s for s in seen)


def test_cc_bcc_and_attachments_are_on_the_card_now():
    seen = []
    terminal("n", seen=seen).ask(rid="r", action=email(cc="c@example.org", bcc="b@example.org",
                                                       attachments=["invoice.pdf"]),
                                 flagged=False, review_reason="ok", span="")
    text = "\n".join(seen)
    assert "c@example.org" in text and "b@example.org" in text and "invoice.pdf" in text


# ---- B. the web demo card ---------------------------------------------------------------------

def _web():
    sys.path.insert(0, str(REPO))
    from demo.web.approver import WebApprover
    return WebApprover


def test_web_approver_refuses_approve_until_the_full_body_was_shown():
    WebApprover = _web()
    seen, out = {}, {}
    ap = WebApprover(timeout_s=5, on_ask=seen.update)
    th = threading.Thread(target=lambda: out.update(h=ap.ask(rid="r1", action=email(LONG), flagged=False,
                                                             review_reason="", span="")))
    th.start()
    while "rid" not in seen:
        time.sleep(0.01)
    assert seen["must_expand"] == ["body"]
    ok, msg = ap.decide("r1", "approve")
    assert not ok and "show all of it" in msg
    assert ap.decide("r1", "approve", viewed="yes")[0] is False          # only a real true counts
    assert ap.decide("r1", "approve", viewed=True) == (True, "approved")
    th.join(2)
    h = out["h"]
    assert h.decision == "approve" and h.full_view_required and h.full_view_seen
    assert h.approver["identified"] is False and h.approver["channel"] == "web-demo"


def test_web_approver_deny_needs_no_viewing_and_short_bodies_are_unchanged():
    WebApprover = _web()
    for body, decision_, viewed in ((LONG, "deny", False), ("short", "approve", False)):
        seen, out = {}, {}
        ap = WebApprover(timeout_s=5, on_ask=seen.update)
        th = threading.Thread(target=lambda: out.update(h=ap.ask(rid="r1", action=email(body), flagged=False,
                                                                 review_reason="", span="")))
        th.start()
        while "rid" not in seen:
            time.sleep(0.01)
        assert ap.decide("r1", decision_, viewed=viewed)[0]
        th.join(2)
        assert out["h"].decision == decision_


def test_web_card_disables_approve_until_expanded():
    js = (REPO / "demo" / "web" / "static" / "app.js").read_text()
    on_approval = js[js.index("function onApproval"):js.index("function outcomeText")]
    # the server's list of cut fields drives it; Approve starts disabled and only the expand handler enables it
    assert "let viewed = !(d.must_expand && d.must_expand.length);" in on_approval
    assert "approve.disabled = true;" in on_approval
    expand_handler = on_approval[on_approval.index('expand.addEventListener("click"'):]
    assert "approve.disabled = false;" in expand_handler
    assert on_approval.count("approve.disabled = false;") == 1
    assert "if (!viewed) return;" in on_approval                    # a click on a disabled-looking button does nothing
    assert "viewed });" in on_approval                              # the decision tells the server it was shown
    assert "actionList(d.action, d.to_label, d.must_expand)" in on_approval
    for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML"):
        assert bad not in js
