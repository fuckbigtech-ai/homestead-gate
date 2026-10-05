"""docs/receipts-spec.md against the code: the committed vectors reproduce, the independent verifier
(tools/receipts_vectors.py) and the gate's own checks agree, the meta fields in the vectors are the ones
the real Gate writes, and the threat-model table states what is and is not caught. Offline, no keychain."""
import json
import shutil
import sys
import urllib.request
from pathlib import Path

import pytest
from homestead_memory.core import ledger

from homestead_gate import lookup, pin, receipts
from homestead_gate.core import Gate
from homestead_gate.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import receipts_vectors as rv  # noqa: E402

from fake_ollama import QWEN_9B, FakeOllama  # noqa: E402
from test_gate import scripted  # noqa: E402
from test_lookup import FakeTavily  # noqa: E402
from test_pin import Inner  # noqa: E402

VEC = ROOT / "docs" / "receipts-vectors"
KEYS = receipts.Keys.from_master(rv.TEST_MASTER_KEY)


def lines(text):
    return [json.loads(x) for x in text.splitlines() if x.strip()]


def as_ledger(tmp_path, text=None) -> Path:
    """The vector ledger laid out as a homestead-memory ledger dir."""
    d = tmp_path / "ledger"
    (d / ".hsm").mkdir(parents=True, exist_ok=True)
    (d / ledger.LEDGER_REL).write_text(text if text is not None else (VEC / "ledger.jsonl").read_text())
    return d


def checkpoints():
    return lines((VEC / "checkpoints.jsonl").read_text())


def rebuild(recs):
    """Someone with the files and no key: recompute seq, prev_hash and hash for every record."""
    prev = ledger.GENESIS_HASH
    for i, r in enumerate(recs):
        r["seq"], r["prev_hash"] = i, prev
        r["hash"] = ledger.record_hash(r)
        prev = r["hash"]
    return "".join(json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n" for r in recs)


# ---- the vectors ---------------------------------------------------------------------------------

def test_vectors_are_byte_for_byte_reproducible(tmp_path):
    out = rv.generate(tmp_path / "v")
    for p in sorted(VEC.rglob("*")):
        if p.is_file():
            assert (out / p.relative_to(VEC)).read_bytes() == p.read_bytes(), p.name
    assert sorted(x.relative_to(out) for x in out.rglob("*")) == sorted(x.relative_to(VEC) for x in VEC.rglob("*"))


def test_independent_verifier_passes_on_the_vectors():
    assert rv.verify(VEC) == []
    assert rv.main(["verify", str(VEC)]) == 0


def test_the_gates_own_checks_agree(tmp_path):
    led = as_ledger(tmp_path)
    recs = ledger.read_all(led)
    assert ledger.verify_chain(led) == []
    rep = receipts.verify_macs(recs, KEYS.mac_key)
    assert rep.ok and rep.checked == len(recs) == 23
    first, last = checkpoints()
    for cp in (first, last):
        assert receipts.check_signatures(cp) is None
        assert receipts._extends(recs, cp) is None
    assert ledger.verify_attestation(last["attestation"], led) == (True, f"verified: 23 records, head {last['head_hash'][:12]}…")
    ok, why = ledger.verify_attestation(first["attestation"], led)
    assert ok and why.startswith("valid as of 13 records; 10 appended since")
    a = receipts.verify_anchors(led, VEC / "anchors", signer=KEYS.pubkey)
    assert a.ok, a.lines


def test_vector_checkpoint_is_what_seal_writes(tmp_path, monkeypatch):
    led = as_ledger(tmp_path)
    policy = Policy.load(_policy_file(tmp_path))
    r = receipts.seal(led, policy=policy, reviewer_model=policy.model, reason="session-end", keys=KEYS,
                      log=lambda s: None)
    assert r.status == "written", r.problems
    want = checkpoints()[-1]
    got = r.checkpoint
    assert set(got) == set(want)
    skip = {"ledger", "ts", "gate_signature", "attestation"}
    assert {k: v for k, v in got.items() if k not in skip} == {k: v for k, v in want.items() if k not in skip}
    assert got["ledger"] == str(led.resolve())        # the only field the vectors replace with a fixed path


def _policy_file(tmp_path):
    p = tmp_path / "policy.toml"
    p.write_text(rv.POLICY_TOML)
    return p


def test_vector_payload_hashes_match_the_published_actions():
    from homestead_gate.core import payload_hash
    meta = json.loads((VEC / "vectors.json").read_text())
    by_rid = {r["request_id"]: r["action"] for r in meta["requests"]}
    for r in lines((VEC / "ledger.jsonl").read_text()):
        m = r["meta"]
        if "request_id" in m:
            assert m["payload_sha256"] == payload_hash(by_rid[m["request_id"]], m["policy_version"])
    seqs = {r["meta"]["request_id"]: r["meta"]["payload_sha256"] for r in lines((VEC / "ledger.jsonl").read_text())
            if "request_id" in r["meta"]}
    assert seqs["a000000003"] == seqs["a000000006"]      # the retry is the same fingerprint, so it was refused


# ---- the vector meta is what the real Gate writes ----------------------------------------------------

def _kind(r):
    m = r.get("meta") or {}
    return (r["action"], r.get("phase"), str(m.get("decided_by", "")).split(":")[0] or None)


def _keysets(recs):
    out = {}
    for r in recs:
        out.setdefault(_kind(r), set()).update(r.get("meta", {}).keys())
    return out


class ScriptedInner(Inner):
    def __init__(self, verdicts):
        super().__init__()
        self.verdicts = iter(verdicts)

    def review(self, prompt):
        self.verdict = next(self.verdicts)
        return super().review(prompt)


def test_vector_records_have_exactly_the_fields_the_gate_writes(tmp_path, monkeypatch):
    fake = FakeOllama(["qwen3.5:9b"], blobs={"qwen3.5:9b": QWEN_9B})
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    ident = pin.read_identity("http://127.0.0.1:11434", "qwen3.5:9b")
    policy = Policy(user_email=rv.ME, user_wallet=rv.WALLET, email_allow=[rv.FRIEND],
                    review_digest=ident.digest, review_manifest_digest=ident.manifest_digest)
    reviewer = pin.PinnedReviewer(ScriptedInner(["approve", "block", "block"]), policy)
    g = Gate(policy=policy, reviewer=reviewer, approver=scripted("n", "y", "send anyway", "y"),
             ledger_dir=tmp_path / "l", task="email my friend", session="t", outbox=tmp_path / "o",
             lookup=lookup.TavilyLookup("k", transport=FakeTavily()), mac_key=KEYS.mac_key)
    for r in rv._requests():
        g.submit({"action": r["action"], "read": r.get("read", [])})
    code = ledger.read_all(tmp_path / "l")
    assert [x["action"] for x in code] == [x["action"] for x in lines((VEC / "ledger.jsonl").read_text())]
    assert _keysets(code) == _keysets(lines((VEC / "ledger.jsonl").read_text()))


# ---- threat model: what is caught, by what --------------------------------------------------------

def vec_recs():
    return lines((VEC / "ledger.jsonl").read_text())


def macs(text):
    return receipts.verify_macs(lines(text), KEYS.mac_key)


def test_single_record_edit_breaks_the_chain(tmp_path):
    recs = vec_recs()
    recs[10]["summary"] = "human:approve"
    text = "".join(json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n" for r in recs)
    breaks = ledger.verify_chain(as_ledger(tmp_path, text))
    assert [(b.index, b.kind) for b in breaks] == [(10, "hash_mismatch")]
    assert any("hash_mismatch" in p for p in rv.verify(VEC, ledger_text=text))


def test_rebuild_without_the_key_fails_the_mac(tmp_path):
    recs = vec_recs()
    recs[10]["summary"] = "human:approve"
    text = rebuild(recs)
    assert ledger.verify_chain(as_ledger(tmp_path, text)) == []
    assert macs(text).bad and not macs(text).ok
    assert any("MAC does not verify" in p for p in rv.verify(VEC, ledger_text=text))


def test_rebuild_that_strips_every_mac_is_caught_only_by_checkpoints(tmp_path):
    recs = vec_recs()
    for r in recs:
        r["meta"].pop("hg_mac")
    recs[10]["summary"] = "human:approve"
    text = rebuild(recs)
    assert ledger.verify_chain(as_ledger(tmp_path, text)) == []
    assert macs(text).ok                                   # nothing to check: no record has a MAC
    rep = receipts.verify_anchors(as_ledger(tmp_path, text), VEC / "anchors")
    # stripping the MACs changes record 0, so no anchor recognises this ledger at all: a failure, not a pass
    assert not rep.ok and any("none for this ledger" in x for x in rep.lines)


def test_deleting_from_the_middle_leaves_a_counter_gap(tmp_path):
    recs = vec_recs()
    del recs[5]
    text = rebuild(recs)
    assert ledger.verify_chain(as_ledger(tmp_path, text)) == []
    assert any("records removed" in g for g in macs(text).gaps)


def test_reordering_in_one_session_leaves_a_counter_gap_and_breaks_ordering():
    recs = vec_recs()
    recs[2], recs[3] = recs[3], recs[2]              # gate.executed before its gate.decision
    text = rebuild(recs)
    assert any("reordered" in g for g in macs(text).gaps)
    problems = rv.verify(VEC, ledger_text=text, checkpoints=[])
    assert any("(O4)" in p for p in problems)


def test_tail_truncation_passes_chain_and_macs_and_is_caught_only_by_a_later_checkpoint(tmp_path):
    text = "".join(x + "\n" for x in (VEC / "ledger.jsonl").read_text().splitlines()[:-2])
    led = as_ledger(tmp_path, text)
    assert ledger.verify_chain(led) == [] and macs(text).ok
    assert not receipts.verify_anchors(led, VEC / "anchors").ok          # the 23-record anchor catches it
    only_first = tmp_path / "a1"
    only_first.mkdir()
    shutil.copy(sorted((VEC / "anchors").glob("*.json"))[0], only_first)
    assert receipts.verify_anchors(led, only_first).ok                   # NOT caught: no anchor saw the tail


def test_reordering_across_sessions_is_not_caught_without_an_anchor(tmp_path):
    led = tmp_path / "x"
    for i in range(2):
        for s in ("s1", "s2"):
            receipts.append(KEYS.mac_key, "gate.request", target="gate:email", summary=f"{s} {i}",
                            meta={"request_id": f"{s}{i}"}, vault=led, agent="homestead-gate", session=s,
                            phase=ledger.PHASE_PRE)
    recs = ledger.read_all(led)
    recs[1], recs[2] = recs[2], recs[1]               # s2's first record and s1's second swap places
    text = rebuild(recs)
    assert ledger.verify_chain(as_ledger(tmp_path, text)) == [] and macs(text).ok


def test_a_forged_unkeyed_policy_record_is_not_flagged_but_a_forged_gate_record_is():
    for action, flagged in (("policy.changed", False), ("gate.decision", True)):
        recs = vec_recs()
        recs.insert(5, {"v": 1, "action": action, "agent": "homestead-gate", "session": "vectors",
                        "target": "gate:policy", "summary": "forged", "meta": {}, "ts": recs[4]["ts"]})
        text = rebuild(recs)
        assert bool(macs(text).stripped) is flagged, action


def test_mac_is_unchecked_without_the_key():
    rep = receipts.verify_macs(vec_recs(), b"\0" * 32)
    assert len(rep.bad) == 23                         # a wrong key fails every record; no key checks none


# ---- what never goes in a receipt ----------------------------------------------------------------

def test_bodies_and_reviewer_reasons_never_reach_the_ledger(tmp_path):
    text = (VEC / "ledger.jsonl").read_text()
    for r in rv._requests():
        assert r["action"].get("body", "\0") not in text
    assert "menu for café night" not in text
    g = Gate(policy=Policy(user_email=rv.ME), reviewer=type("R", (), {"review": lambda self, p: __import__(
        "homestead_gate.reviewer", fromlist=["Verdict"]).Verdict("block", "REASON-QUOTES-BODY", "SPAN", "m", 0.0)})(),
        approver=scripted("n"), ledger_dir=tmp_path / "l", task="t", session="t", outbox=tmp_path / "o")
    g.submit({"action": {"type": "email", "to": "x@y.example", "subject": "SUBJ", "body": "BODY"},
              "read": [{"source": "web", "content": "UNTRUSTED-CONTENT"}]})
    written = (tmp_path / "l" / ledger.LEDGER_REL).read_text()
    for secret in ("REASON-QUOTES-BODY", "SPAN", "SUBJ", "BODY", "UNTRUSTED-CONTENT"):
        assert secret not in written


@pytest.mark.parametrize("path", ["docs/receipts-spec.md", "tools/receipts_vectors.py", "tests/test_receipts_spec.py"])
def test_no_long_dashes(path):
    text = (ROOT / path).read_text(encoding="utf-8")
    assert chr(0x2014) not in text and chr(0x2013) not in text
