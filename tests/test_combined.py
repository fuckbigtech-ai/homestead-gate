"""The four feature sets on one request: web lookup (master), full view + dual control + policy
receipts (duties), keyed record MACs (receipts), reviewer pin (reviewer-pin).

Offline: Tavily is an injected transport, Ollama is tests/fake_ollama.py, the ledger key is the
conftest fake store. No model runs, no network, no real keychain.
"""

from homestead_memory.core import ledger

from homestead_gate import approvers, lookup, pin, receipts
from homestead_gate.approval import TerminalApprover
from homestead_gate.core import Gate
from homestead_gate.policy import Policy
from homestead_gate.reviewer import Verdict
from fake_ollama import QWEN_9B, FakeOllama, manifest_of
from test_lookup import KEY, MARKER, STRANGER, FakeTavily

SECRET = "correct horse battery staple"
POLICY = f"""[user]
email = "me@example.com"

[review]
model = "qwen3.5:9b"
digest = "sha256:{QWEN_9B}"
manifest_digest = "sha256:{manifest_of(QWEN_9B)}"

[approval]
override_delay_s = 0
timeout_s = 5
second_approver = true

[lookup]
tavily = true
"""


class Inner:
    """Stands in for OllamaReviewer behind the pin; records every prompt it is shown."""
    model, url = "qwen3.5:9b", "http://127.0.0.1:11434"

    def __init__(self):
        self.prompts = []

    def receipt_meta(self):
        return {"prompt_version": "v1", "prompt_sha256": "p" * 64, "think": False}

    def review(self, prompt):
        self.prompts.append(prompt)
        return Verdict("approve", "matches the request", "", self.model, 0.0)


def setup(tmp_path, answers, secrets=(SECRET,)):
    folder = tmp_path / "pol"
    folder.mkdir()
    (folder / "policy.toml").write_text(POLICY)
    policy = Policy.load(folder / "policy.toml")
    approvers.add(folder, "alice", SECRET)
    screen, it, sec = [], iter(answers), iter(secrets)       # the screen holds output lines and prompts

    def ask(p, t):
        screen.append(p)
        return next(it)

    def secret(p, t):
        screen.append(p)
        return next(sec)
    term = TerminalApprover(override_delay_s=0, timeout_s=5, input_fn=ask, secret_fn=secret,
                            out=screen.append, sleep=lambda s: None)
    inner, tavily = Inner(), FakeTavily()
    keys = receipts.ledger_keys()
    g = Gate(policy=policy, reviewer=pin.PinnedReviewer(inner, policy, opener=FakeOllama(tags=["qwen3.5:9b"],
                                                                                         blobs={"qwen3.5:9b": QWEN_9B})),
             approver=term, ledger_dir=tmp_path / "l", task="email the quarterly numbers", session="c",
             outbox=tmp_path / "out", lookup=lookup.TavilyLookup(KEY, transport=tavily), mac_key=keys.mac_key)
    return g, screen, inner, tavily, keys


def long_email():
    return {"type": "email", "to": STRANGER, "subject": "numbers",
            "body": "\n".join(f"line {i}" for i in range(30))}


def test_one_request_through_every_feature(tmp_path):
    # y before viewing is refused once, v pages it all, y, then the second approver confirms
    g, screen, inner, tavily, keys = setup(tmp_path, answers=("y", "v", "y", "alice"))
    res = g.submit({"action": long_email()})
    assert res["status"] == "executed"
    assert MARKER not in str(res)                                  # the agent never sees the web text

    text = "\n".join(screen)
    assert MARKER in text and "web:" in text                       # the human saw the lookup...
    assert text.index("web:") < text.index("reviewer: ok")         # ...above the reviewer's verdict
    assert "not yet: part of this was not shown" in text and "== end of content ==" in text
    assert all(MARKER not in p for p in inner.prompts) and len(inner.prompts) == 1   # reviewer never saw it
    assert len(tavily.requests) == 1

    recs = ledger.read_all(tmp_path / "l")
    assert MARKER not in (tmp_path / "l").joinpath(ledger.LEDGER_REL).read_text()
    assert recs[0]["action"] == "policy.loaded" and recs[0]["meta"]["dual_control"] == ["*"]
    acts = [r["action"] for r in recs]
    assert acts.index("gate.review") < acts.index("gate.lookup") < acts.index("gate.decision")
    review = next(r for r in recs if r["action"] == "gate.review")["meta"]
    assert review["pin_state"] == "ok" and review["digest"] == "sha256:" + QWEN_9B
    assert review["pinned_digest"] == "sha256:" + QWEN_9B and review["prompt_version"] == "v1"
    d = next(r for r in recs if r["action"] == "gate.decision")["meta"]
    assert d["decision"] == "approve" and d["approver"]["channel"] == "terminal"
    assert d["full_view"] == {"required": True, "viewed": True}
    assert d["dual_control"] == {"required": True, "satisfied": True, "second_approver": "alice"}
    assert d["policy_sha256"] == g.policy.file_sha256
    assert SECRET not in (tmp_path / "l").joinpath(ledger.LEDGER_REL).read_text()

    m = receipts.verify_macs(recs, keys.mac_key)                  # every record, policy receipt included
    assert m.ok and m.checked == len(recs)


def test_a_swapped_reviewer_still_reaches_the_human_with_the_lookup_and_dual_control(tmp_path):
    # the model file is not the pinned one: no review (invalid, so flagged); the human sees the lookup,
    # pages the full content, types the override phrase and confirms; the second approver then types
    # the wrong passphrase, which denies
    g, screen, inner, tavily, keys = setup(tmp_path, answers=("v", "y", "send anyway", "y", "alice"),
                                           secrets=("wrong",))
    g.reviewer.opener = FakeOllama(tags=["qwen3.5:9b"], blobs={"qwen3.5:9b": "ab" * 32})   # not the pinned file
    res = g.submit({"action": long_email()})
    assert res["status"] == "denied"
    assert "dual control not satisfied" in res["reason"]
    assert inner.prompts == []                                     # the unpinned file never reviewed
    text = "\n".join(screen)
    assert MARKER in text                                          # the human still got the lookup
    assert "type 'send anyway'" in text and "still send it?" in text      # override friction was applied
    assert "their passphrase (not shown): " in screen              # and the second approver was asked
    assert "wrong" not in text
    recs = ledger.read_all(tmp_path / "l")
    review = next(r for r in recs if r["action"] == "gate.review")["meta"]
    assert review["pin_state"] == "mismatch" and review["verdict"] == "invalid"
    d = next(r for r in recs if r["action"] == "gate.decision")["meta"]
    assert d["decision"] == "deny" and d["overrode_flag"] is False
    assert d["full_view"] == {"required": True, "viewed": True}
    assert d["dual_control"] == {"required": True, "satisfied": False, "second_approver": None}
    assert receipts.verify_macs(recs, keys.mac_key).ok
