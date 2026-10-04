"""Reviewer model risk: the digest pin, the override, receipts, the drift canary, doctor's measured-file
note. Offline: a fake Ollama answers /api/tags and /api/show only, and every reviewer is a fake.
No test loads, pulls or runs a model."""
import hashlib
import json
import os
import re
import stat
import urllib.request
from pathlib import Path

import pytest
from homestead_memory.core import ledger

from fake_ollama import NANO_GGUF, OTHER, QWEN_9B, FakeOllama
from homestead_gate import canary, cli, pin, reviewer
from homestead_gate.cli import main as cli_main
from homestead_gate.core import Gate
from homestead_gate.policy import Policy
from homestead_gate.reviewer import Verdict
from test_gate import scripted
from test_mailbox import answers, store  # noqa: F401  (fixture)
from test_up import env, write_pinned  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parents[1]
URL = "http://127.0.0.1:11434"
ME = "me@example.com"


def gate_records(d):
    return [r for r in ledger.read_all(d) if r["action"] == "gate.review"]


class LabelReviewer:
    """Answers the canary cases from a table {case id: verdict}; counts calls."""
    def __init__(self, verdicts):
        self.by_prompt = {canary.prompt_for(c): c["id"] for c in canary.load_cases()}
        self.verdicts, self.calls = dict(verdicts), 0

    def review(self, prompt):
        self.calls += 1
        return Verdict(self.verdicts[self.by_prompt[prompt]], "fake", "", "fake", 0.0)


def truth():
    """A reviewer that is right on every canary case."""
    return {c["id"]: ("block" if c["label"] == "malicious" else "approve") for c in canary.load_cases()}


# ---- reading the identity --------------------------------------------------------------------

def test_identity_is_the_weights_blob_and_the_manifest(monkeypatch):
    fake = FakeOllama(["nemotron-3-nano:4b"], blobs={"nemotron-3-nano:4b": NANO_GGUF})
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    ident = pin.read_identity(URL, "nemotron-3-nano:4b")
    assert ident.digest == "sha256:" + NANO_GGUF
    assert ident.manifest_digest == "sha256:" + fake.manifest("nemotron-3-nano:4b")
    assert ident.size == 2837597147
    assert [u.rsplit("/", 1)[1] for u in fake.urls] == ["tags", "show"]       # nothing that loads


@pytest.mark.parametrize("fake,kind", [
    (FakeOllama(up=False), "unreachable"),
    (FakeOllama(["other:1b"]), "absent"),
    (FakeOllama(["qwen3.5:9b"], no_digest=True), "unreadable"),
])
def test_identity_failures_are_typed(monkeypatch, fake, kind):
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    with pytest.raises(pin.PinError) as e:
        pin.read_identity(URL, "qwen3.5:9b")
    assert e.value.kind == kind


def test_policy_validates_digests_and_versions_them(tmp_path):
    p = tmp_path / "policy.toml"
    p.write_text('[review]\nmodel = "qwen3.5:9b"\ndigest = "dec52a"\n')
    with pytest.raises(ValueError, match="sha256:<64 hex>"):
        Policy.load(p)
    a, b = Policy(review_digest="sha256:" + QWEN_9B), Policy(review_digest="sha256:" + OTHER)
    assert a.version != b.version          # an approval under one model file is not one under another


# ---- writing the pin ---------------------------------------------------------------------------

def test_write_pin_touches_only_review_and_keeps_permissions(tmp_path):
    p = tmp_path / "policy.toml"
    p.write_text('# mine\n[user]\nemail = "me@example.com"\n\n[review]\nmodel = "qwen3.5:9b"\nthink = true\n\n'
                 '[approval]\ntimeout_s = 300\n')
    os.chmod(p, 0o600)
    ident = pin.Identity("qwen3.5:9b", "sha256:" + QWEN_9B, "sha256:" + OTHER, 6_600_000_000)
    pol = pin.write_pin(p, ident)
    assert (pol.review_digest, pol.review_manifest_digest, pol.review_think) == (ident.digest, ident.manifest_digest, True)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    text = p.read_text()
    assert text.startswith("# mine\n") and "[approval]\ntimeout_s = 300" in text
    review = text.split("[review]")[1].split("[approval]")[0]
    assert review.index("\ndigest =") < review.index("\nmanifest_digest =") < review.index("\nthink")
    assert text.count("\ndigest =") == 1
    pin.write_pin(p, pin.Identity("qwen3.5:9b", "sha256:" + NANO_GGUF, "sha256:" + OTHER, 1))   # re-pin replaces
    assert Policy.load(p).review_digest == "sha256:" + NANO_GGUF and p.read_text().count("\ndigest =") == 1


def test_write_pin_adds_a_review_table_when_missing(tmp_path):
    p = tmp_path / "policy.toml"
    p.write_text('[user]\nemail = "me@example.com"\n')
    pol = pin.write_pin(p, pin.Identity("qwen3.5:9b", "sha256:" + QWEN_9B, "sha256:" + OTHER, 1))
    assert pol.review_digest == "sha256:" + QWEN_9B and pol.user_email == ME


# ---- refusing to start -------------------------------------------------------------------------

def test_up_refuses_a_changed_model_file(env, capsys):
    write_pinned(env, "qwen3.5:9b")
    env.ollama.blobs["qwen3.5:9b"] = OTHER                         # re-pulled tag, different weights
    assert cli_main(["up", "--task", "x", *env.args]) == 2
    err = capsys.readouterr().err
    assert env.served == []
    assert "not the pinned model file" in err and f"homestead-gate reviewer pin --policy {env.pol}" in err
    assert pin.OVERRIDE_FLAG in err


def test_up_refuses_a_changed_template_with_the_same_weights(env, capsys):
    write_pinned(env, "qwen3.5:9b")
    env.ollama.manifests["qwen3.5:9b"] = OTHER                     # same blob, new manifest
    assert cli_main(["up", "--task", "x", *env.args]) == 2
    assert "manifest" in capsys.readouterr().err and env.served == []


def test_up_refuses_an_existing_unpinned_policy(env, capsys):
    from homestead_gate import installer
    installer.write_policy(env.pol, ME, "", "qwen3.5:9b")
    env.ollama.tags = ["qwen3.5:9b"]
    assert cli_main(["up", "--task", "x", *env.args]) == 2
    assert "not pinned" in capsys.readouterr().err and env.served == []
    assert Policy.load(env.pol).review_digest == ""                 # never pinned silently on later runs


def test_up_first_setup_pins_without_loading_anything(env, capsys):
    env.ollama.tags = ["qwen3.5:9b"]
    env.ollama.blobs["qwen3.5:9b"] = QWEN_9B
    assert cli_main(["up", "--yes", "--email", "t@example.com", "--task", "x", *env.args]) == 0
    p = Policy.load(env.pol)
    assert p.review_digest == "sha256:" + QWEN_9B and p.review_manifest_digest
    out = capsys.readouterr().out
    assert "pinned the reviewer" in out and "the exact file our published numbers were measured on" in out
    assert all(u.endswith(("/api/version", "/api/tags", "/api/show")) for u in env.ollama.urls)


def test_up_with_ollama_down_starts_fail_closed_and_says_how_to_pin(env, capsys):
    env.ollama.up = False
    assert cli_main(["up", "--yes", "--email", "t@example.com", "--task", "x", *env.args]) == 0
    out = capsys.readouterr().out
    assert env.served and "Every review goes to you" in out and "homestead-gate reviewer pin" in out


def test_override_starts_and_is_passed_to_the_reviewer(env, capsys):
    write_pinned(env, "qwen3.5:9b")
    env.ollama.blobs["qwen3.5:9b"] = OTHER
    made = []
    env.mp.setattr(cli, "_serve", lambda policy, a, task, smtp=None: made.append(
        cli._make_reviewer(policy, a.allow_unpinned_reviewer)) or 0)
    assert cli_main(["up", "--task", "x", pin.OVERRIDE_FLAG, *env.args]) == 0
    assert "OVERRIDDEN" in capsys.readouterr().err
    assert made and made[0].override is True


def test_assistant_refuses_a_changed_model_file(tmp_path, monkeypatch, capsys):
    from homestead_gate import llm as llm_mod
    from test_assistant import KEY, ScriptedLLM, done
    original = llm_mod.ChatClient.from_preset
    monkeypatch.setattr(llm_mod.ChatClient, "from_preset", classmethod(
        lambda cls, name, **kw: original(name, api_key=KEY, transport=ScriptedLLM(done()))))
    monkeypatch.setattr(cli, "_fits", lambda *a, **k: True)
    monkeypatch.setenv("NEBIUS_API_KEY", KEY)
    fake = FakeOllama(["nemotron-3-nano:4b"], blobs={"nemotron-3-nano:4b": NANO_GGUF})
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    d = tmp_path / "d"
    assert cli_main(["assistant", "--skill", "pay", "--data", str(d)]) == 0       # seeds and pins
    fake.blobs["nemotron-3-nano:4b"] = OTHER
    assert cli_main(["assistant", "--skill", "pay", "--data", str(d)]) == 1
    assert f"homestead-gate reviewer pin --data {d}" in capsys.readouterr().err


def test_imap_setup_pins_on_first_setup(tmp_path, monkeypatch, store, capsys):  # noqa: F811
    monkeypatch.setattr(urllib.request, "urlopen",
                        FakeOllama(["nemotron-3-nano:4b"], blobs={"nemotron-3-nano:4b": NANO_GGUF}))
    data = tmp_path / "mail"
    answers(monkeypatch, "", "owner@gmail.com")
    assert cli_main(["assistant", "--data", str(data), "--imap-setup"]) == 0
    p = Policy.load(data / "policy.toml")
    assert p.review_digest == "sha256:" + NANO_GGUF and p.review_think is True
    assert stat.S_IMODE(os.stat(data / "policy.toml").st_mode) == 0o600      # still private


# ---- the reviewer wrapper and receipts --------------------------------------------------------

class Inner:
    """Stands in for OllamaReviewer: same receipt_meta, a scripted verdict, no network."""
    model, url = "qwen3.5:9b", URL

    def __init__(self, verdict="approve"):
        self.verdict, self.calls = verdict, 0

    def receipt_meta(self):
        return reviewer.OllamaReviewer(self.model).receipt_meta()

    def review(self, prompt):
        self.calls += 1
        return Verdict(self.verdict, "fake", "", self.model, 0.1, meta=self.receipt_meta())


def pinned_gate(tmp_path, monkeypatch, blob_now, override=False, verdict="approve", answer="n"):
    fake = FakeOllama(["qwen3.5:9b"], blobs={"qwen3.5:9b": QWEN_9B})
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    ident = pin.read_identity(URL, "qwen3.5:9b")
    policy = Policy(user_email=ME, review_digest=ident.digest, review_manifest_digest=ident.manifest_digest)
    fake.blobs["qwen3.5:9b"] = blob_now
    inner = Inner(verdict)
    g = Gate(policy=policy, reviewer=pin.PinnedReviewer(inner, policy, override=override),
             approver=scripted(answer, answer), ledger_dir=tmp_path / "l", task="email a@x.example hello",
             session="t", outbox=tmp_path / "o")
    return g, inner, ident


ACT = {"type": "email", "to": "a@x.example", "subject": "s", "body": "hello"}


def test_receipts_carry_model_digest_and_prompt_sha(tmp_path, monkeypatch):
    g, inner, ident = pinned_gate(tmp_path, monkeypatch, QWEN_9B)
    g.submit({"action": ACT})
    m = gate_records(tmp_path / "l")[-1]["meta"]
    assert inner.calls == 1
    assert (m["model"], m["digest"], m["manifest_digest"]) == ("qwen3.5:9b", ident.digest, ident.manifest_digest)
    assert m["prompt_version"] == "v1"
    assert m["prompt_sha256"] == hashlib.sha256(reviewer.SYSTEM.encode()).hexdigest() == reviewer.PROMPT_SHA256
    assert m["pin_state"] == "ok" and m["think"] is False and "pin_override" not in m


def test_a_model_changed_mid_session_is_not_asked(tmp_path, monkeypatch):
    g, inner, ident = pinned_gate(tmp_path, monkeypatch, OTHER, verdict="approve")
    res = g.submit({"action": ACT})
    m = gate_records(tmp_path / "l")[-1]["meta"]
    assert inner.calls == 0                                  # the swapped model never reviewed
    assert m["verdict"] == "invalid" and m["pin_state"] == "mismatch"
    assert m["digest"] == "sha256:" + OTHER and m["pinned_digest"] == ident.digest
    assert res["by"].startswith("human:")                    # fail-to-human, never fail-open


def test_override_is_recorded_in_every_review_receipt(tmp_path, monkeypatch):
    g, inner, ident = pinned_gate(tmp_path, monkeypatch, OTHER, override=True)
    g.submit({"action": ACT})
    g.submit({"action": {**ACT, "body": "second"}})
    recs = gate_records(tmp_path / "l")
    assert inner.calls == 2 and len(recs) == 2
    for r in recs:
        m = r["meta"]
        assert m["pin_override"] is True and m["digest"] == "sha256:" + OTHER and m["pinned_digest"] == ident.digest
        assert m["prompt_sha256"] == reviewer.PROMPT_SHA256


def test_no_model_receipts_say_no_model_file(tmp_path):
    g = Gate(policy=Policy(user_email=ME), reviewer=cli._NoModelReviewer(), approver=scripted("n"),
             ledger_dir=tmp_path / "l", task="t", session="t", outbox=tmp_path / "o")
    g.submit({"action": ACT})
    m = gate_records(tmp_path / "l")[-1]["meta"]
    assert m["digest"] is None and m["prompt_sha256"] is None and m["model"] == "none (--no-model)"


# ---- the canary --------------------------------------------------------------------------------

def test_canary_cases_are_the_frozen_bench_cases():
    raw = (ROOT / "src" / "homestead_gate" / canary.CASES_FILE).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == canary.CASES_SHA256
    bench = {json.loads(l)["id"]: l for l in (ROOT / "bench" / "cases_v01.jsonl").read_text().splitlines() if l.strip()}
    lines = [l for l in raw.decode().splitlines() if l.strip()]
    cases = canary.load_cases()
    assert [c["id"] for c in cases] == [f"t{i:02d}" for i in range(1, 21)]
    assert sum(c["label"] == "malicious" for c in cases) == 10 and all(c["split"] == "test" for c in cases)
    assert all(line == bench[json.loads(line)["id"]] for line in lines)        # byte for byte
    with pytest.raises(canary.CanaryError):
        canary.load_cases(raw + b"\n{}")


def test_canary_renders_like_the_gate():
    c = canary.load_cases()[0]
    p = canary.prompt_for(c)
    assert p.startswith(f"USER (the person you work for): {c['user_identity']}\nUSER REQUEST: {c['user_intent']}")
    assert p.endswith("PROPOSED ACTION: " + json.dumps(c["proposed_action"]))


def test_baseline_refuses_invalid_verdicts(tmp_path):
    v = truth()
    v["t03"] = "invalid"
    with pytest.raises(canary.CanaryError, match="t03"):
        canary.record(tmp_path / "b.json", {}, v, canary.load_cases())


def test_compare_threshold_and_safety_flip():
    cases, base = canary.load_cases(), {"verdicts": truth()}
    assert canary.compare(base, truth(), cases).ok
    two_legit = {**truth(), "t02": "block", "t04": "block"}                      # 90%: at the threshold
    assert canary.compare(base, two_legit, cases).ok
    three = {**two_legit, "t06": "invalid"}                                       # invalid counts as a change
    r = canary.compare(base, three, cases)
    assert not r.ok and abs(r.agreement - 0.85) < 1e-9
    flip = {**truth(), "t01": "approve"}                                          # 95%, but an attack now passes
    r = canary.compare(base, flip, cases)
    assert not r.ok and r.unsafe == ["t01"] and r.agreement == 0.95


@pytest.fixture
def pinned(env):  # noqa: F811
    write_pinned(env, "qwen3.5:9b")
    env.ollama.blobs["qwen3.5:9b"] = env.ollama.blob("qwen3.5:9b")     # freeze the made-up blob
    return env


def use_reviewer(env, verdicts):
    rv = LabelReviewer(verdicts)
    env.mp.setattr(cli, "_make_reviewer", lambda policy, override=False: rv)
    return rv


def test_reviewer_pin_writes_digest_prints_it_and_records_a_baseline(env, capsys):  # noqa: F811
    from homestead_gate import installer
    installer.write_policy(env.pol, ME, "", "qwen3.5:9b")
    env.ollama.tags, env.ollama.blobs["qwen3.5:9b"] = ["qwen3.5:9b"], QWEN_9B
    rv = use_reviewer(env, truth())
    assert cli_main(["reviewer", "pin", "--policy", str(env.pol)]) == 0
    out = capsys.readouterr().out
    assert Policy.load(env.pol).review_digest == "sha256:" + QWEN_9B
    assert "model:    qwen3.5:9b  (2.8GB)" in out and f"digest:   sha256:{QWEN_9B}" in out
    base = json.loads((env.pol.parent / canary.BASELINE_FILE).read_text())
    assert rv.calls == 20 and base["digest"] == "sha256:" + QWEN_9B and base["verdicts"] == truth()
    assert base["prompt_sha256"] == reviewer.PROMPT_SHA256 and base["cases_sha256"] == canary.CASES_SHA256


def test_reviewer_pin_no_baseline_runs_nothing(env, capsys):  # noqa: F811
    from homestead_gate import installer
    installer.write_policy(env.pol, ME, "", "qwen3.5:9b")
    env.ollama.tags = ["qwen3.5:9b"]
    env.mp.setattr(cli, "_make_reviewer", lambda *a, **k: pytest.fail("ran the model"))
    assert cli_main(["reviewer", "pin", "--no-baseline", "--policy", str(env.pol)]) == 0
    assert Policy.load(env.pol).review_digest and not (env.pol.parent / canary.BASELINE_FILE).exists()


def test_canary_agrees_then_detects_drift(pinned, capsys):
    env = pinned
    use_reviewer(env, truth())
    assert cli_main(["reviewer", "canary", "--record", "--policy", str(env.pol)]) == canary.EXIT_OK
    assert cli_main(["reviewer", "canary", "--policy", str(env.pol)]) == canary.EXIT_OK
    drifted = {**truth(), "t02": "block", "t04": "block", "t06": "block"}
    use_reviewer(env, drifted)
    assert cli_main(["reviewer", "canary", "--policy", str(env.pol)]) == canary.EXIT_DRIFT
    out = capsys.readouterr().out
    assert "DRIFT" in out and "changed: t06 (benign) approve -> block" in out
    hist = [json.loads(l) for l in (env.pol.parent / canary.HISTORY_FILE).read_text().splitlines()]
    assert [h["result"] for h in hist] == ["recorded", "ok", "drift"]


def test_canary_fails_on_one_safety_flip(pinned, capsys):
    env = pinned
    use_reviewer(env, truth())
    cli_main(["reviewer", "canary", "--record", "--policy", str(env.pol)])
    use_reviewer(env, {**truth(), "t05": "approve"})
    assert cli_main(["reviewer", "canary", "--policy", str(env.pol)]) == canary.EXIT_DRIFT
    assert "SAFETY FLIP" in capsys.readouterr().out


def test_canary_refuses_a_changed_model_before_running_it(pinned, capsys):
    env = pinned
    use_reviewer(env, truth())
    cli_main(["reviewer", "canary", "--record", "--policy", str(env.pol)])
    env.ollama.blobs["qwen3.5:9b"] = OTHER
    rv = use_reviewer(env, truth())
    assert cli_main(["reviewer", "canary", "--policy", str(env.pol)]) == canary.EXIT_PIN
    assert rv.calls == 0


def test_canary_needs_a_fresh_baseline(pinned, capsys):
    env = pinned
    rv = use_reviewer(env, truth())
    assert cli_main(["reviewer", "canary", "--policy", str(env.pol)]) == canary.EXIT_BASELINE     # none yet
    cli_main(["reviewer", "canary", "--record", "--policy", str(env.pol)])
    env.ollama.blobs["qwen3.5:9b"] = OTHER                       # deliberately re-pinned, baseline not re-recorded
    pin.write_pin(env.pol, pin.read_identity(URL, "qwen3.5:9b"))
    rv.calls = 0
    assert cli_main(["reviewer", "canary", "--policy", str(env.pol)]) == canary.EXIT_BASELINE
    assert rv.calls == 0 and "digest: baseline" in capsys.readouterr().err


def test_canary_does_not_record_a_baseline_of_failures(pinned, capsys):
    env = pinned
    use_reviewer(env, {**truth(), "t07": "invalid"})
    assert cli_main(["reviewer", "canary", "--record", "--policy", str(env.pol)]) == canary.EXIT_DRIFT
    assert not (env.pol.parent / canary.BASELINE_FILE).exists()


# ---- doctor -------------------------------------------------------------------------------------

@pytest.mark.parametrize("blob,note", [
    (NANO_GGUF, "the exact file our published numbers were measured on"),
    (QWEN_9B, "the exact file our published numbers were measured on"),
    (OTHER, "not a measured file"),
])
def test_doctor_recognizes_measured_files(env, capsys, blob, note):  # noqa: F811
    env.ollama.blobs["nemotron-3-nano:4b"] = blob
    write_pinned(env, "nemotron-3-nano:4b")
    rc = cli_main(["doctor", *env.args])
    out = capsys.readouterr().out
    assert rc == 0 and note in out
    assert re.search(r"ok\s+pin\s+nemotron-3-nano:4b is the pinned file", out)


def test_doctor_fails_a_changed_or_unpinned_reviewer(env, capsys):  # noqa: F811
    write_pinned(env, "nemotron-3-nano:4b")
    env.ollama.blobs["nemotron-3-nano:4b"] = OTHER
    assert cli_main(["doctor", *env.args]) == 1
    assert re.search(r"FAIL\s+pin\s+.*not the pinned model file", capsys.readouterr().out)
    from homestead_gate import installer
    installer.write_policy(env.pol, ME, "", "nemotron-3-nano:4b")
    assert cli_main(["doctor", *env.args]) == 1
    assert re.search(r"FAIL\s+pin\s+.*not pinned", capsys.readouterr().out)


def test_measured_table_holds_only_sourced_full_digests():
    for d in pin.MEASURED:
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", d)
    assert not any(d.startswith("sha256:527db2") for d in pin.MEASURED)      # no run log records it


def test_model_risk_doc_states_the_shipped_prompt_and_measured_files():
    doc = (ROOT / "MODEL_RISK.md").read_text()
    assert f"sha256 `{reviewer.PROMPT_SHA256}`" in doc            # the doc names the prompt that ships
    assert set(re.findall(r"`(sha256:[0-9a-f]{64})`", doc)) == set(pin.MEASURED)
    assert "--allow-unpinned-reviewer" in doc and pin.OVERRIDE_FLAG == "--allow-unpinned-reviewer"
