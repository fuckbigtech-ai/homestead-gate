"""Receipts as audit evidence: signed checkpoints, anchors off the machine, keyed records.
Offline. The ledger key lives in conftest's in-memory store, or in a fake `security`/`secret-tool`."""
import argparse
import json
import shlex
import threading
import types
from datetime import datetime
from pathlib import Path

import pytest
from homestead_memory.core import ledger

from homestead_gate import always_on, cli, credstore, receipts
from homestead_gate import assistant as asst
from homestead_gate.cli import main as cli_main
from homestead_gate.core import Gate
from homestead_gate.policy import Policy
from test_always_on import FIRST, SECOND, _guards, run_pass, seeded  # noqa: F401  (_guards: autouse)
from test_assistant import call, calls
from test_gate import ME, WALLET, FakeReviewer, scripted, tx

LEDGER_FILE = Path(".hsm") / "ledger.jsonl"
REAL_STORE_HEAD, REAL_LOAD_HEAD = credstore.store_ledger_head, credstore.load_ledger_head   # before conftest


def keys():
    return receipts.ledger_keys()


def gate(tmp_path, *, mac=True, session="s1", policy=None, ledger_dir=None, answers=("n",) * 20):
    k = keys() if mac else None
    return Gate(policy=policy or Policy(user_email=ME, user_wallet=WALLET), reviewer=FakeReviewer("block"),
                approver=scripted(*answers), ledger_dir=ledger_dir or tmp_path / "l", task="email me the summary",
                session=session, outbox=tmp_path / "out", mac_key=k.mac_key if k else None)


def fill(g, n=3):
    for i in range(n):
        g.submit({"action": {"type": "email", "to": ME, "subject": f"s{i}", "body": "b"}})   # to self: auto


def rebuild(led: Path, edit=None, drop=None):
    """What someone with your files can do: change records, then recompute every hash so the plain
    chain verifies again. Also deletes the local checkpoints, which are just files."""
    f = led / LEDGER_FILE
    recs = [json.loads(line) for line in f.read_text().splitlines() if line.strip()]
    if drop is not None:
        del recs[drop]
    if edit is not None:
        recs[edit]["summary"] = "human:approve (forged)"
    prev = ledger.GENESIS_HASH
    for i, r in enumerate(recs):
        r["seq"], r["prev_hash"] = i, prev
        r["hash"] = ledger.record_hash(r)
        prev = r["hash"]
    f.write_text("".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in recs))
    (led / ledger.CHECKPOINT_REL).unlink(missing_ok=True)
    (led / receipts.CHECKPOINTS_FILE).unlink(missing_ok=True)
    assert ledger.verify_chain(led) == []


def anchored(d: Path):
    return sorted(d.glob(f"{receipts.ANCHOR_PREFIX}*.json"))


# ---- policy ------------------------------------------------------------------------------

def test_receipts_section_parses_and_never_changes_the_policy_version(tmp_path):
    assert Policy(user_email=ME).version == "4088984b870d45c8"           # the value before [receipts] existed
    assert Policy(user_email=ME, anchor_dir="/x", anchor_command="cat").version == "4088984b870d45c8"
    p = tmp_path / "policy.toml"
    p.write_text('[user]\nemail = "me@example.com"\n[receipts]\nanchor_dir = "~/anchors"\n'
                 'anchor_command = "cat > /dev/null"\n')
    pol = Policy.load(p)
    assert (pol.anchor_dir, pol.anchor_command) == ("~/anchors", "cat > /dev/null")


# ---- checkpoints -------------------------------------------------------------------------

def test_checkpoint_is_signed_compatible_with_hsm_and_carries_the_context(tmp_path):
    g = gate(tmp_path)
    fill(g)
    r = receipts.seal(tmp_path / "l", policy=g.policy, reviewer_model="qwen3.5:9b", reason="t", keys=keys())
    cp = r.checkpoint
    assert r.status == "written" and cp["signed"] and cp["records"] == len(ledger.read_all(tmp_path / "l"))
    assert cp["head_hash"] == ledger.head_hash(tmp_path / "l")
    assert cp["policy_version"] == g.policy.version and cp["reviewer_model"] == "qwen3.5:9b" and cp["ts"]
    assert receipts.check_signatures(cp) is None
    assert ledger.verify_checkpoint(tmp_path / "l") == (True, f"verified: {cp['records']} records, "
                                                              f"head {cp['head_hash'][:12]}…")
    assert ledger.verify_attestation(cp["attestation"], tmp_path / "l")[0]     # `hsm checkpoint --verify`
    forged = dict(cp, reviewer_model="something else")                       # the gate signature covers it
    assert receipts.check_signatures(forged) == "signature does not verify"
    again = receipts.seal(tmp_path / "l", policy=g.policy, keys=keys())
    assert again.status == "unchanged"
    assert len((tmp_path / "l" / receipts.CHECKPOINTS_FILE).read_text().splitlines()) == 1


def test_a_checkpoint_is_written_after_every_scheduled_pass(tmp_path):
    data = seeded(tmp_path)
    p, _, _ = run_pass(data, FIRST, now=datetime(2026, 10, 2, 7, 0))
    # (plus one "executed" checkpoint per action the pass ran, written as each one ran)
    cps = [json.loads(x) for x in (data / "ledger" / receipts.CHECKPOINTS_FILE).read_text().splitlines()]
    passes = [c for c in cps if c["reason"] == "scheduled-pass"]
    assert len(passes) == 1 and not p.receipts_refused and cps[-1] is passes[0]
    assert {c["reason"] for c in cps} <= {"scheduled-pass", "executed"}
    first = passes[0]
    assert first["signed"] and first["reviewer_model"] == "fake"
    assert first["records"] == len(ledger.read_all(data / "ledger"))
    asst.deliver_later_mail(data)
    run_pass(data, [calls(call("read_email", id="msg-001"))] + SECOND, now=datetime(2026, 10, 2, 7, 15))
    cps = [json.loads(x) for x in (data / "ledger" / receipts.CHECKPOINTS_FILE).read_text().splitlines()]
    passes = [c for c in cps if c["reason"] == "scheduled-pass"]
    assert len(passes) == 2 and passes[1]["records"] == len(ledger.read_all(data / "ledger"))
    m = receipts.verify_macs(ledger.read_all(data / "ledger"), keys().mac_key)
    assert m.ok and m.checked == len(ledger.read_all(data / "ledger"))   # every record of every pass is keyed


def test_a_checkpoint_is_written_when_a_gate_session_ends(tmp_path, monkeypatch):
    led = tmp_path / "ledger"
    anchors = tmp_path / "anchors"
    policy = Policy(user_email=ME, anchor_dir=str(anchors))

    class Server:                            # stands in for the daemon: two requests arrive, then Ctrl-C
        def __init__(self, g, port):
            self.g = g

        def serve_forever(self):
            fill(self.g, 2)
            raise KeyboardInterrupt
    monkeypatch.setattr("homestead_gate.daemon.make_server", lambda g, port: Server(g, port))
    monkeypatch.setattr(cli, "HOME", tmp_path / "home")
    assert cli._serve(policy, argparse.Namespace(ledger=str(led), port=0), "email me", None) == 0
    cps = [json.loads(x) for x in (led / receipts.CHECKPOINTS_FILE).read_text().splitlines()]
    # one checkpoint as each request executed (4 and 7 records), then the session's own at the end:
    # 7 = the policy.loaded receipt (written at startup, MAC'd like the rest) + 3 per request
    assert [(c["reason"], c["records"]) for c in cps] == [("executed", 4), ("executed", 7), ("session-end", 7)]
    assert all(c["signed"] for c in cps)
    assert len(anchored(anchors)) == 2               # anchor_dir file names are per head: 4 and 7
    assert receipts.verify_macs(ledger.read_all(led), keys().mac_key).checked == 7


def test_watch_checkpoints_only_after_everything_verifies(tmp_path):
    g = gate(tmp_path)
    fill(g)
    assert cli_main(["watch", "--ledger", str(tmp_path / "l"), "--no-checkpoint"]) == 0
    assert not (tmp_path / "l" / receipts.CHECKPOINTS_FILE).exists()
    assert cli_main(["watch", "--ledger", str(tmp_path / "l")]) == 0
    assert json.loads((tmp_path / "l" / receipts.CHECKPOINTS_FILE).read_text())["reason"] == "watch"


# ---- anchors -----------------------------------------------------------------------------

def test_anchors_get_a_new_file_per_checkpoint_and_the_command_gets_the_json(tmp_path):
    out = tmp_path / "cmd-out"
    out.mkdir()
    policy = Policy(user_email=ME, anchor_dir=str(tmp_path / "anchors"),
                    anchor_command=f'cat > {shlex.quote(str(out))}/"$HG_CHECKPOINT_NAME".json && '
                                   f'cmp -s "$HG_CHECKPOINT" {shlex.quote(str(out))}/"$HG_CHECKPOINT_NAME".json')
    g = gate(tmp_path, policy=policy)
    fill(g, 2)
    r1 = receipts.seal(tmp_path / "l", policy=policy, keys=keys())
    assert "anchor_command" in r1.anchored and not r1.warnings
    [a1] = anchored(tmp_path / "anchors")
    before = a1.read_bytes()
    assert json.loads(before) == r1.checkpoint == json.loads((out / a1.name).read_text())
    assert receipts.seal(tmp_path / "l", policy=policy, keys=keys()).status == "unchanged"
    assert len(anchored(tmp_path / "anchors")) == 1
    fill(g, 1)
    receipts.seal(tmp_path / "l", policy=policy, keys=keys())
    assert len(anchored(tmp_path / "anchors")) == 2 and a1.read_bytes() == before     # append-only
    assert len(list(out.glob("*.json"))) == 2


def test_a_failing_anchor_command_warns_and_the_local_checkpoint_stands(tmp_path):
    policy = Policy(user_email=ME, anchor_command="echo the timestamp authority is down >&2; exit 7")
    g = gate(tmp_path, policy=policy)
    fill(g, 1)
    said = []
    r = receipts.seal(tmp_path / "l", policy=policy, keys=keys(), log=said.append)
    assert r.status == "written" and r.anchored == []
    assert any("exited 7" in s and "timestamp authority is down" in s for s in said)


@pytest.mark.parametrize("edit", [0, 8], ids=["first-record", "middle-record"])
def test_a_fully_rebuilt_chain_passes_plain_verify_but_fails_against_anchors(tmp_path, edit, capsys,
                                                                            ledger_key_store):
    anchors = tmp_path / "anchors"
    policy = Policy(user_email=ME, anchor_dir=str(anchors))
    g = gate(tmp_path, mac=False, policy=policy)                  # no MACs: the anchors alone must catch it
    fill(g, 2)
    receipts.seal(tmp_path / "l", policy=policy, keys=keys())    # anchored at 7 records (policy.loaded + 3 per request)
    fill(g, 2)
    receipts.seal(tmp_path / "l", policy=policy, keys=keys())    # anchored at 13 records
    led = tmp_path / "l"
    rebuild(led, edit=edit)

    assert cli._watch(led) == 0                                   # plain verify (`hsm watch`): fooled
    assert cli_main(["watch", "--ledger", str(led), "--no-checkpoint"]) == 1   # this machine's sealed head
    assert "no longer extends the head this machine last sealed" in capsys.readouterr().err
    ledger_key_store.heads.clear()                                # say that mark is gone too (another machine)
    assert cli_main(["watch", "--ledger", str(led), "--no-checkpoint"]) == 0
    capsys.readouterr()
    assert cli_main(["watch", "--ledger", str(led), "--anchors", str(anchors), "--no-checkpoint"]) == 1
    err = capsys.readouterr().err
    assert "FIRST DIVERGENCE" in err
    rep = receipts.verify_anchors(led, anchors)
    assert not rep.ok
    if edit == 0:
        assert rep.last_good is None and rep.first_bad["records"] == 7
    else:
        assert rep.last_good["records"] == 7 and rep.first_bad["records"] == 13
        assert "between record 7 and record 12" in "\n".join(rep.lines)

    # A pass (or watch) on the rebuilt chain must not launder it with a fresh signature or anchor.
    said = []
    r = receipts.seal(led, policy=policy, keys=keys(), log=said.append)
    assert r.status == "refused" and any("REFUSED" in s for s in said)
    assert len(anchored(anchors)) == 2 and not (led / receipts.CHECKPOINTS_FILE).exists()
    assert cli_main(["watch", "--ledger", str(led), "--policy", str(_write_policy(tmp_path, anchors))]) == 1
    assert len(anchored(anchors)) == 2


def _write_policy(tmp_path, anchors):
    p = tmp_path / "policy.toml"
    p.write_text(f'[user]\nemail = "{ME}"\n[receipts]\nanchor_dir = "{anchors}"\n')
    return p


def test_a_rebuilt_copy_elsewhere_matches_no_anchor_and_fails_closed(tmp_path):
    anchors = tmp_path / "anchors"
    policy = Policy(user_email=ME, anchor_dir=str(anchors))
    g = gate(tmp_path, mac=False, policy=policy)
    fill(g, 2)
    receipts.seal(tmp_path / "l", policy=policy, keys=keys())
    copy = tmp_path / "evidence-copy"
    (copy / ".hsm").mkdir(parents=True)
    (copy / LEDGER_FILE).write_bytes((tmp_path / "l" / LEDGER_FILE).read_bytes())
    assert receipts.verify_anchors(copy, anchors).ok                  # an honest copy verifies anywhere
    rebuild(copy, edit=0)
    rep = receipts.verify_anchors(copy, anchors)
    assert not rep.ok and "none for this ledger" in rep.lines[-1]


def test_a_scheduled_pass_on_a_rebuilt_ledger_refuses_and_says_so_in_the_brief(tmp_path):
    data = seeded(tmp_path)
    anchors = tmp_path / "anchors"
    with (data / "policy.toml").open("a") as f:
        f.write(f'\n[receipts]\nanchor_dir = "{anchors}"\n')
    run_pass(data, FIRST, now=datetime(2026, 10, 2, 7, 0))
    assert len(anchored(anchors)) == 1
    rebuild(data / "ledger", edit=1)
    asst.deliver_later_mail(data)
    p, _, shown = run_pass(data, [calls(call("read_email", id="msg-001"))] + SECOND, now=datetime(2026, 10, 2, 7, 15))
    assert p.receipts_refused and len(anchored(anchors)) == 1
    assert "**Receipts:** the gate REFUSED to sign a checkpoint" in (data / "brief.md").read_text()
    assert shown == [("homestead", "the receipts no longer match an earlier checkpoint; see the brief")]


# ---- keyed records -----------------------------------------------------------------------

def test_the_mac_catches_a_rebuilt_record_when_the_key_is_here(tmp_path, ledger_key_store, capsys):
    g = gate(tmp_path)
    g.submit({"action": tx()})                                    # flagged, denied by the human
    fill(g, 2)
    led = tmp_path / "l"
    assert receipts.verify_macs(ledger.read_all(led), keys().mac_key).ok
    rebuild(led, edit=2)                                          # the human's deny, rewritten
    m = receipts.verify_macs(ledger.read_all(led), keys().mac_key)
    assert m.bad and m.bad[0].startswith("record 2 ")
    assert cli_main(["watch", "--ledger", str(led), "--no-checkpoint"]) == 1
    assert "fails its MAC" in capsys.readouterr().err
    # Without the key (an auditor's machine) the MACs are reported as unchecked, not as passing.
    ledger_key_store.key, saved = None, ledger_key_store.key
    assert cli_main(["watch", "--ledger", str(led), "--no-checkpoint"]) == 0
    assert "MACs not checked" in capsys.readouterr().err and ledger_key_store.key is None
    ledger_key_store.key = saved


def test_the_mac_catches_a_deleted_record_and_a_stripped_mac(tmp_path):
    g = gate(tmp_path)
    fill(g, 3)
    led = tmp_path / "l"
    rebuild(led, drop=2)                                          # one record removed, chain recomputed
    m = receipts.verify_macs(ledger.read_all(led), keys().mac_key)
    # MAC v2 covers seq and prev_hash, so the record that now follows the gap fails its MAC (before v2,
    # with content-only MACs, this showed as a counter gap instead; the counter check still runs on
    # records whose MAC is good, but a failing record's counter is not trusted).
    assert m.bad and m.bad[0].startswith("record 2 ")

    g2 = gate(tmp_path, ledger_dir=tmp_path / "l2")
    fill(g2, 2)
    f = tmp_path / "l2" / LEDGER_FILE
    recs = [json.loads(x) for x in f.read_text().splitlines()]
    del recs[3]["meta"][receipts.MAC_FIELD]                       # edit it AND drop its MAC
    recs[3]["summary"] = "forged"
    f.write_text("".join(json.dumps(r) + "\n" for r in recs))
    rebuild(tmp_path / "l2")
    m2 = receipts.verify_macs(ledger.read_all(tmp_path / "l2"), keys().mac_key)
    assert m2.stripped and "record 3" in m2.stripped[0]


def test_concurrent_requests_keep_the_mac_counter_in_order(tmp_path):
    g = gate(tmp_path)
    ts = [threading.Thread(target=fill, args=(g, 2)) for _ in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    recs = ledger.read_all(tmp_path / "l")
    m = receipts.verify_macs(recs, keys().mac_key)
    assert m.ok and m.checked == len(recs) == 37        # 12 requests x 3, plus the one policy.loaded


def test_a_session_resumed_in_a_new_gate_continues_its_counter(tmp_path):
    fill(gate(tmp_path, session="same"), 1)
    receipts._counters.clear()                                   # as if a new process
    fill(gate(tmp_path, session="same"), 1)
    assert receipts.verify_macs(ledger.read_all(tmp_path / "l"), keys().mac_key).ok


# ---- backward compatibility ----------------------------------------------------------------

def test_old_ledgers_and_old_hsm_checkpoints_still_verify(tmp_path):
    led = tmp_path / "l"
    for i in range(3):                                            # a ledger from before any of this
        ledger.append("gate.request", target="gate:email", summary=f"old {i}", vault=led,
                      agent="homestead-gate", session="old", phase=ledger.PHASE_PRE)
    ledger.checkpoint(led, key_path=tmp_path / "old-hsm-key")    # signed the old way, with a key file
    assert cli_main(["watch", "--ledger", str(led), "--no-checkpoint"]) == 0
    fill(gate(tmp_path), 1)                                       # new keyed records after the old ones
    m = receipts.verify_macs(ledger.read_all(led), keys().mac_key)
    assert m.ok and m.unkeyed_before == 3 and m.checked == 4    # policy.loaded + 3 for the request
    r = receipts.seal(led, keys=keys())
    assert r.status == "written" and r.checkpoint["records"] == 7   # extends the old hsm checkpoint
    assert cli_main(["watch", "--ledger", str(led), "--no-checkpoint"]) == 0


def test_without_a_credential_store_it_warns_and_writes_unsigned_checkpoints(tmp_path, monkeypatch):
    def none():
        raise credstore.CredentialError("no supported credential store")
    monkeypatch.setattr(credstore, "load_or_create_ledger_key", none)
    said = []
    assert receipts.ledger_keys(warn=said.append) is None
    assert "WARNING" in said[0] and "UNSIGNED" in said[0]
    g = gate(tmp_path, mac=False)
    fill(g, 1)
    r = receipts.seal(tmp_path / "l", policy=g.policy, keys=None, log=said.append)
    assert r.status == "written" and r.checkpoint["signed"] is False
    assert not (tmp_path / "l" / ledger.CHECKPOINT_REL).exists()     # hsm would read an unsigned one as forged
    assert receipts.check_signatures(r.checkpoint) is None


def test_a_broken_chain_is_never_signed(tmp_path):
    g = gate(tmp_path)
    fill(g, 2)
    f = tmp_path / "l" / LEDGER_FILE
    f.write_text(f.read_text().replace('"summary":"policy:approve', '"summary":"policy:APPROVE', 1))
    r = receipts.seal(tmp_path / "l", keys=keys(), log=lambda s: None)
    assert r.status == "refused" and "break" in r.problems[0]


# ---- the key never touches the disk -----------------------------------------------------

class FakeKeychain:
    """Stands in for `security` and `secret-tool` with the ledger key's real code path."""
    def __init__(self):
        self.items, self.argvs, self.stdins = {}, [], []

    def run(self, args, *a, input=None, **kw):
        self.argvs.append(list(args))
        self.stdins.append(input or "")
        ok = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[:2] == ["security", "-i"]:
            words = shlex.split(input)
            assert words[0] == "add-generic-password" and "-T" in words
            self.items[(words[words.index("-s") + 1], words[words.index("-a") + 1])] = words[words.index("-w") + 1]
            return ok
        if args[:2] == ["secret-tool", "store"]:
            self.items[(args[args.index("service") + 1], args[args.index("user") + 1])] = input
            return ok
        if args[1] in ("find-generic-password", "lookup"):
            k = ((args[args.index("-s") + 1], args[args.index("-a") + 1]) if args[0] == "security"
                 else (args[args.index("service") + 1], args[args.index("user") + 1]))
            v = self.items.get(k)
            return types.SimpleNamespace(returncode=0 if v else 44, stdout=(v or "") + "\n", stderr="")
        raise AssertionError(args)


@pytest.mark.parametrize("backend", ["keychain", "libsecret"])
def test_the_ledger_key_is_never_written_to_disk_or_argv(tmp_path, monkeypatch, backend):
    fake = FakeKeychain()
    monkeypatch.setattr(credstore, "subprocess", types.SimpleNamespace(run=fake.run))
    monkeypatch.setattr(credstore, "_backend", lambda: backend)
    monkeypatch.setattr(credstore, "load_or_create_ledger_key", lambda: credstore._ledger_key_from_store(True))
    monkeypatch.setattr(credstore, "load_ledger_key", lambda: credstore._ledger_key_from_store(False))
    monkeypatch.setattr(credstore, "store_ledger_head", REAL_STORE_HEAD)
    monkeypatch.setattr(credstore, "load_ledger_head", REAL_LOAD_HEAD)
    monkeypatch.setattr(credstore, "HOME", tmp_path / "gatehome")
    monkeypatch.setattr(cli, "HOME", tmp_path / "gatehome")
    hsm_default = Path("~/.config/homestead-memory/ed25519_key").expanduser()
    had_hsm_key = hsm_default.exists() and hsm_default.stat().st_mtime

    data = seeded(tmp_path)
    with (data / "policy.toml").open("a") as f:
        f.write(f'\n[receipts]\nanchor_dir = "{tmp_path / "anchors"}"\n'
                f'anchor_command = "cat > {tmp_path}/cmd.json"\n')
    run_pass(data, FIRST, now=datetime(2026, 10, 2, 7, 0))
    fill(gate(tmp_path, ledger_dir=data / "ledger"), 1)
    assert cli_main(["watch", "--ledger", str(data / "ledger")]) == 0

    hexkey = fake.items[(credstore.LEDGER_KEY_SERVICE, credstore.LEDGER_KEY_ACCOUNT)]
    [head_mark] = [v for (svc, _), v in fake.items.items() if svc == credstore.LEDGER_HEAD_SERVICE]
    assert head_mark == f"{len(ledger.read_all(data / 'ledger'))}:{ledger.head_hash(data / 'ledger')}"
    master = bytes.fromhex(hexkey)
    k = receipts.Keys.from_master(master)
    from cryptography.hazmat.primitives import serialization
    seed = k.signer.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
    secrets_ = [master, k.mac_key, seed]
    needles = [s for b in secrets_ for s in (b, b.hex().encode(), b.hex().upper().encode())]
    files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert len(files) > 10
    for p in files:
        body = p.read_bytes()
        assert not any(n in body for n in needles), f"key material in {p}"
    for argv in fake.argvs:
        assert not any(s.hex() in " ".join(argv) for s in secrets_), argv
    assert ((hsm_default.exists() and hsm_default.stat().st_mtime) == had_hsm_key)   # no hsm key file made
    assert receipts.verify_macs(ledger.read_all(data / "ledger"), k.mac_key).ok
    cp = json.loads((data / "ledger" / receipts.CHECKPOINTS_FILE).read_text().splitlines()[-1])
    assert cp["signer_pubkey"] == k.pubkey


# ---- found in review ---------------------------------------------------------------------

def test_a_rebuild_that_strips_every_mac_is_refused_without_anchors(tmp_path, capsys):
    """Strip every MAC (so the ledger looks like an old one), recompute the chain, delete both local
    checkpoint files, configure no anchors: the head kept in the credential store still refuses it."""
    g = gate(tmp_path)
    fill(g, 2)
    led = tmp_path / "l"
    assert receipts.seal(led, policy=g.policy, keys=keys()).status == "written"
    f = led / LEDGER_FILE
    recs = [json.loads(x) for x in f.read_text().splitlines()]
    for r in recs:
        r["meta"].pop(receipts.MAC_FIELD)
    recs[1]["summary"] = "forged"
    f.write_text("".join(json.dumps(r) + "\n" for r in recs))
    rebuild(led)
    assert not receipts.has_macs(ledger.read_all(led))
    r = receipts.seal(led, policy=g.policy, keys=keys(), log=lambda s: None)
    assert r.status == "refused" and not (led / receipts.CHECKPOINTS_FILE).exists()
    assert cli_main(["watch", "--ledger", str(led)]) == 1
    assert "no longer extends the head this machine last sealed" in capsys.readouterr().err
    assert not (led / receipts.CHECKPOINTS_FILE).exists()


def test_a_receipts_failure_never_stops_a_pass_from_saving_its_state(tmp_path, monkeypatch):
    data = seeded(tmp_path)

    def boom(*a, **kw):
        raise TimeoutError("timed out waiting for vault lock")
    monkeypatch.setattr(receipts, "seal", boom)
    p, _, _ = run_pass(data, FIRST, now=datetime(2026, 10, 2, 7, 0))
    assert sorted(always_on.load_state(data)["seen"]) == ["msg-001", "msg-002", "msg-003", "msg-004"]
    assert "no checkpoint was written this pass (TimeoutError" in (data / "brief.md").read_text()


def test_a_malformed_anchor_file_is_reported_not_a_traceback(tmp_path):
    anchors = tmp_path / "anchors"
    policy = Policy(user_email=ME, anchor_dir=str(anchors))
    g = gate(tmp_path, policy=policy)
    fill(g, 1)
    receipts.seal(tmp_path / "l", policy=policy, keys=keys())
    (anchors / f"{receipts.ANCHOR_PREFIX}junk.json").write_text(
        json.dumps({"ledger": str((tmp_path / "l").resolve()), "records": "many", "head_hash": "x"}))
    rep = receipts.verify_anchors(tmp_path / "l", anchors)
    assert not rep.ok and any("not a readable checkpoint" in line for line in rep.lines)


@pytest.mark.parametrize("have_key", [True, False])
def test_egress_records_get_a_mac_when_the_key_exists(tmp_path, monkeypatch, ledger_key_store, have_key):
    from homestead_gate import sandbox
    if have_key:
        fill(gate(tmp_path), 1)                                   # `up` created the key and keyed the ledger

    def fake_run(cmd, *, on_deny, **kw):
        on_deny("evil.example", "host not on the allowlist")
        return 0
    monkeypatch.setattr(sandbox, "run", fake_run)
    led = tmp_path / "l"
    assert cli_main(["run", "--ledger", str(led), "--", "true"]) == 0
    recs = ledger.read_all(led)
    eg = recs[-1]
    assert eg["action"] == "egress.denied" and eg["phase"] == "pre_execution"
    assert (receipts.MAC_FIELD in eg["meta"]) is have_key
    assert ledger_key_store.key is None or have_key               # `run` never creates a key
    if have_key:
        assert receipts.verify_macs(recs, keys().mac_key).ok
        rebuild(led, edit=len(recs) - 1)                          # the blocked host's record, rewritten
        assert receipts.verify_macs(ledger.read_all(led), keys().mac_key).bad


def test_each_executed_action_is_sealed_so_tail_truncation_is_caught_before_the_session_ends(tmp_path, monkeypatch):
    # Before: checkpoints only at session ends, passes and watch; the newest records of a running
    # session could be deleted with nothing to catch it.
    sent = tmp_path / "sent"
    policy = Policy(user_email=ME, user_wallet=WALLET, anchor_command=f"cat >> {shlex.quote(str(sent))}")
    g = Gate(policy=policy, reviewer=FakeReviewer("block"), approver=scripted(), ledger_dir=tmp_path / "l",
             task="t", session="s", outbox=tmp_path / "out", keys=keys())
    fill(g, 2)
    led = tmp_path / "l"
    cps = [json.loads(x) for x in (led / receipts.CHECKPOINTS_FILE).read_text().splitlines()]
    assert [(c["reason"], c["records"]) for c in cps] == [("executed", 4), ("executed", 7)]
    assert not sent.exists()                                    # anchor_command waits for a full seal
    f = led / LEDGER_FILE
    f.write_text("".join(x + "\n" for x in f.read_text().splitlines()[:-1]))     # drop the newest record
    assert ledger.verify_chain(led) == []
    assert receipts.check_stored_head(led, ledger.read_all(led))                  # caught already
    assert cli_main(["watch", "--ledger", str(led), "--no-checkpoint"]) == 1


def test_a_full_seal_after_a_per_action_seal_still_runs_anchor_command(tmp_path):
    sent = tmp_path / "sent"
    policy = Policy(user_email=ME, user_wallet=WALLET, anchor_command=f"cat >> {shlex.quote(str(sent))}")
    g = Gate(policy=policy, reviewer=FakeReviewer("block"), approver=scripted(), ledger_dir=tmp_path / "l",
             task="t", session="s", outbox=tmp_path / "out", keys=keys())
    fill(g, 1)
    r = receipts.seal(tmp_path / "l", policy=policy, reason="session-end", keys=keys(), log=lambda s: None)
    assert r.status == "written" and r.checkpoint["records"] == 4 and "anchor_command" in r.anchored
    assert json.loads(sent.read_text())["reason"] == "session-end"
    assert receipts.seal(tmp_path / "l", policy=policy, reason="watch", keys=keys(),
                         log=lambda s: None).status == "unchanged"


def test_a_failing_per_action_seal_never_fails_the_action(tmp_path, monkeypatch):
    said = []
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(receipts, "seal", boom)
    g = Gate(policy=Policy(user_email=ME), reviewer=FakeReviewer(), approver=scripted(), ledger_dir=tmp_path / "l",
             task="t", session="s", outbox=tmp_path / "out", keys=keys(), seal_log=said.append)
    r = g.submit({"action": {"type": "email", "to": ME, "subject": "s", "body": "b"}})
    assert r["status"] == "executed" and "disk full" in said[0]
