#!/usr/bin/env python3
"""Test vectors and an independent verifier for Agent Action Receipts v0.1 (docs/receipts-spec.md).

    python tools/receipts_vectors.py generate [DIR]     write the vectors (default docs/receipts-vectors)
    python tools/receipts_vectors.py verify [DIR]       check them; exit 0 only if every check passes

generate drives the gate's real writer (receipts.append over homestead-memory's ledger.append) with a
fixed clock, fixed request ids and a fixed TEST key, so every byte is reproducible. The checkpoints are
built field for field like receipts.seal() builds them, with a fixed ledger path in place of the real
absolute one (tests/test_receipts_spec.py checks that against seal() itself).

verify is written from the spec text, not from the gate's code: it imports neither homestead_gate nor
homestead_memory. It needs only the standard library, plus `cryptography` for Ed25519. That separation is
the point. When the gate's own checks and this file agree on the same bytes, the spec says what the code
does.

THE KEY IN vectors.json IS A PUBLIC TEST KEY. Never use it for a real ledger.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIR = ROOT / "docs" / "receipts-vectors"

TEST_MASTER_KEY = bytes(range(32))          # 000102...1f. Public. Test vectors only.
SESSION = "vectors"
AGENT = "homestead-gate"
LEDGER_PATH = "/vectors/ledger"              # stands in for the absolute ledger path in checkpoints
POLICY_PATH = "/vectors/policy.toml"
CLOCK_START = "2026-10-05T12:00:00"          # one second per timestamp the writer asks for
ME, WALLET, FRIEND = "me@example.com", "0x" + "1" * 40, "friend@example.org"
ZERO = "0x" + "0" * 40
QWEN_9B = "sha256:dec52a44569a2a25341c4e4d3fee25846eed4f6f0b936278e3a3c900bb99d37c"
MANIFEST = "sha256:" + "ab" * 32
POLICY_TOML = f"""# Agent Action Receipts v0.1 test vector policy
[user]
email = "{ME}"
wallet = "{WALLET}"

[email]
allow = ["{FRIEND}"]

[review]
model = "qwen3.5:9b"
digest = "{QWEN_9B}"
manifest_digest = "{MANIFEST}"
"""
GENESIS = "0" * 64
PRE, POST = "pre_execution", "post_execution"
SIGN_INFO = b"homestead-gate checkpoint ed25519 v1"
MAC_INFO = b"homestead-gate record mac v1"     # the key derivation label; MAC v2 uses the same key
TYPED_FIELDS = {
    "email": ("type", "to", "cc", "bcc", "subject", "body", "attachments"),
    "wallet_tx": ("type", "chain_id", "to", "value_eth", "data"),
}
POST_ACTIONS = ("gate.executed", "gate.failed", "gate.denied", "gate.expired")


# ====================================================================== generate

def _clock():
    from datetime import datetime, timedelta, timezone
    t0 = datetime.fromisoformat(CLOCK_START).replace(tzinfo=timezone.utc)
    n = [0]

    def now_ts() -> str:
        t = t0 + timedelta(seconds=n[0])
        n[0] += 1
        return t.isoformat(timespec="seconds")
    return now_ts


def _requests() -> list[dict]:
    """The actions in the vector ledger, by request id. Published so a verifier can recompute
    payload_sha256 from the payload, which the receipts themselves never contain."""
    hijack = {"type": "wallet_tx", "chain_id": 11155111, "to": ZERO, "value_eth": 0.01,
              "note": "extra keys never reach the fingerprint"}
    return [
        {"rid": "a000000001", "action": {"type": "email", "to": ME, "subject": "summary",
                                          "body": "Local models in 2026: memory bandwidth decides speed."}},
        {"rid": "a000000002", "action": {"type": "email", "to": FRIEND, "subject": "lunch",
                                          "body": "Thursday works."}},
        {"rid": "a000000003", "action": hijack, "read": [{"source": "inbox:msg-17"}]},
        {"rid": "a000000004", "action": {"type": "email", "to": FRIEND, "subject": "menu for café night",
                                          "body": "Attached is the menu."},
         "read": [{"source": "web:café.example/menu"}]},
        {"rid": "a000000005", "action": {"type": "wallet_tx", "chain_id": 1, "to": WALLET, "value_eth": 1}},
        {"rid": "a000000006", "action": dict(hijack), "read": [{"source": "inbox:msg-17"}]},
    ]


def _fingerprint_cases(pv: str) -> list[dict]:
    from homestead_gate.core import payload_hash, typed_action
    cases = [
        ("email, extra keys ignored", {"type": "email", "to": ME, "subject": "s", "body": "b",
                                       "user_intent": "send it", "approved": True}),
        ("email, same typed fields as above", {"type": "email", "to": ME, "subject": "s", "body": "b"}),
        ("wallet_tx, data missing becomes null", {"type": "wallet_tx", "chain_id": 11155111, "to": ZERO,
                                                  "value_eth": 0.01}),
        ("wallet_tx, integer value differs from float", {"type": "wallet_tx", "chain_id": 11155111, "to": ZERO,
                                                         "value_eth": 1}),
        ("wallet_tx, float value", {"type": "wallet_tx", "chain_id": 11155111, "to": ZERO, "value_eth": 1.0}),
        ("email, non-ASCII is escaped as \\uXXXX", {"type": "email", "to": ME, "subject": "café", "body": "ü"}),
        ("unknown type, every key sorted", {"type": "post", "channel": "#general", "text": "hi"}),
    ]
    out = []
    for label, action in cases:
        body = {"action": typed_action(action), "policy_version": pv}
        pre = json.dumps(body, sort_keys=True, separators=(",", ":"))
        h = payload_hash(action, pv)
        assert h == hashlib.sha256(pre.encode()).hexdigest()
        out.append({"label": label, "action": action, "policy_version": pv, "preimage": pre, "payload_sha256": h})
    return out


def _policy_rules(p) -> dict:
    """Policy.version's preimage, rebuilt here (the code exposes only the hash) and checked against it."""
    from homestead_gate.policy import _NOT_RULES
    rules = {k: v for k, v in sorted(vars(p).items()) if not k.startswith("_") and k not in _NOT_RULES}
    for k in ("dual_control", "review_digest", "review_manifest_digest"):
        if not rules[k]:
            del rules[k]
    want = hashlib.sha256(json.dumps(rules, sort_keys=True, default=str).encode()).hexdigest()[:16]
    assert want == p.version, "Policy.version changed; update the spec section 4.3 and this function"
    return rules


def _policy_cases(vector_policy, loaded_minimal) -> list[dict]:
    from homestead_gate.policy import Policy
    cases = [
        ("defaults with user email", Policy(user_email=ME)),
        ("the same rules loaded from a file: floats where the defaults are ints", loaded_minimal),
        ("anchor settings are not rules", Policy(user_email=ME, anchor_dir="/x", anchor_command="cat")),
        ("dual control enters once set", Policy(user_email=ME, dual_control=["wallet_tx"])),
        ("the vector ledger's policy (pinned reviewer)", vector_policy),
    ]
    return [{"label": label, "rules": _policy_rules(p), "version": p.version} for label, p in cases]


def _checkpoint(recs: list[dict], keys, policy, reason: str) -> dict:
    """Field for field what receipts.seal() writes, with LEDGER_PATH for the ledger and the fixed clock."""
    from homestead_gate import receipts
    from homestead_memory.core import ledger, provenance, signing
    head, count = recs[-1]["hash"], len(recs)
    cp = {"hg_checkpoint": receipts.CHECKPOINT_VERSION, "head_hash": head, "records": count,
          "ts": provenance.now_ts(), "ledger": LEDGER_PATH, "ledger_id": recs[0]["hash"],
          "policy_version": policy.version, "reviewer_model": policy.model, "reason": reason,
          "ledger_version": ledger.LEDGER_VERSION}
    cp.update(signed=True, alg=signing.ALG, sig_version=signing.SIG_VERSION, signer_pubkey=keys.pubkey,
              signature=keys.signer.sign(f"{head}:{count}".encode()).hex())
    cp["gate_signature"] = keys.signer.sign(receipts._gate_body(cp)).hex()
    cp["attestation"] = receipts.attestation_line(cp)
    return cp


def generate(out_dir: Path = DEFAULT_DIR) -> Path:
    import tempfile

    from homestead_gate import receipts, reviewer
    from homestead_gate.core import describe, payload_hash
    from homestead_gate.policy import Policy
    from homestead_memory.core import ledger, provenance

    out_dir = Path(out_dir)
    keys = receipts.Keys.from_master(TEST_MASTER_KEY)
    if keys.signer is None:
        raise SystemExit("generate needs the `cryptography` package for Ed25519")
    real_now = provenance.now_ts
    provenance.now_ts = _clock()
    try:
        with tempfile.TemporaryDirectory(prefix="hg-vectors-") as td:
            pfile = Path(td) / "policy.toml"
            pfile.write_bytes(POLICY_TOML.encode())
            policy = Policy.load(pfile)
            pv, psha = policy.version, policy.file_sha256
            led = Path(td) / "ledger"
            checkpoints: list[dict] = []

            def log(action, summary, meta, phase, target):
                receipts.append(keys.mac_key, action, target=target, summary=summary, meta=meta, vault=led,
                                agent=AGENT, session=SESSION, phase=phase)

            log("policy.loaded", f"policy {pv} file {psha[:12]}",
                {"policy_path": POLICY_PATH, "policy_sha256": psha, "policy_version": pv,
                 "approvers_sha256": None, "dual_control": []}, None, "gate:policy")

            review_meta = {"digest": QWEN_9B, "manifest_digest": MANIFEST, "prompt_version": reviewer.PROMPT_VERSION,
                           "prompt_sha256": reviewer.PROMPT_SHA256, "think": False, "pinned_digest": QWEN_9B,
                           "pin_state": "ok"}
            identity = {"channel": "terminal", "os_user": "alice", "uid": 501, "host": "vectors-host",
                        "tty": "/dev/ttys001"}
            reqs = {r["rid"]: r for r in _requests()}

            def request(rid):
                r = reqs[rid]
                a = r["action"]
                base = {"request_id": rid, "payload_sha256": payload_hash(a, pv), "policy_version": pv,
                        "policy_sha256": psha}
                target = f"gate:{a.get('type', '?')}"
                pre = lambda act, s, **m: log(act, s, {**base, **m}, PRE, target)
                post = lambda act, s, **m: log(act, s, {**base, **m}, POST, target)
                pre("gate.request", f"request {describe(a)}", to=a.get("to"),
                    read_sources=[str(x.get("source", "?")) for x in r.get("read", [])])
                return pre, post

            def review(pre, verdict, secs):
                pre("gate.review", f"llm:{verdict}", **review_meta, model="qwen3.5:9b", verdict=verdict, secs=secs)

            def human(pre, decision, *, latency, overrode=False):
                pre("gate.decision", f"human:{decision}" + (" (overrode flag)" if overrode else ""),
                    decided_by="human:terminal", decision=decision, channel="terminal", latency_s=latency,
                    overrode_flag=overrode, approver=identity, full_view={"required": False, "viewed": False})

            # 1. send to self: policy auto-approves, no review
            pre, post = request("a000000001")
            pre("gate.decision", "policy:approve send to self", decided_by="policy", decision="approve")
            post("gate.executed", "executed (dry run)",
                 result={"delivered": False, "dry_run": "/vectors/outbox/1791201601000.eml"})
            # 2. allowlisted, model approves: policy approves after review
            pre, post = request("a000000002")
            review(pre, "approve", 1.25)
            pre("gate.decision", "policy:approve allowlisted and the model approved",
                decided_by="policy", decision="approve")
            post("gate.executed", "executed (dry run)",
                 result={"delivered": False, "dry_run": "/vectors/outbox/1791201603000.eml"})
            # 3. hijacked transfer: model blocks, web lookup for the human, human denies
            pre, post = request("a000000003")
            review(pre, "block", 2.5)
            pre("gate.lookup", f"web lookup wallet {ZERO}: 3 results", lookup_kind="wallet", lookup_target=ZERO,
                lookup_ok=True, lookup_results=3)
            human(pre, "deny", latency=4.5)
            post("gate.denied", "not executed", reason="human deny")
            checkpoints.append(_checkpoint(ledger.read_all(led), keys, policy, "scheduled-pass"))
            # 4. model flags, human overrides with the typed phrase, delay and second yes
            pre, post = request("a000000004")
            review(pre, "block", 1.5)
            human(pre, "approve", latency=73.25, overrode=True)
            post("gate.executed", "executed (dry run)",
                 result={"delivered": False, "dry_run": "/vectors/outbox/1791201690000.eml"})
            # 5. hard policy rule: wrong chain, nobody asked
            pre, post = request("a000000005")
            why = "chain 1 is not the allowed chain 11155111"
            pre("gate.decision", f"policy:deny {why}", decided_by="policy", decision="deny")
            post("gate.denied", "not executed", reason=why)
            # 6. identical retry of 3: refused by fingerprint, no review, no question
            pre, post = request("a000000006")
            why = "the same action was already refused in this session"
            pre("gate.decision", f"policy:deny {why}", decided_by="policy", decision="deny")
            post("gate.denied", "not executed", reason=why)
            checkpoints.append(_checkpoint(ledger.read_all(led), keys, policy, "session-end"))

            ledger_bytes = (led / ledger.LEDGER_REL).read_bytes()
            fingerprints = _fingerprint_cases(pv)
            mfile = Path(td) / "minimal.toml"
            mfile.write_bytes(f'[user]\nemail = "{ME}"\n'.encode())
            policies = _policy_cases(policy, Policy.load(mfile))
    finally:
        provenance.now_ts = real_now

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "ledger.jsonl").write_bytes(ledger_bytes)
    (out_dir / "checkpoints.jsonl").write_text("".join(json.dumps(c, sort_keys=True) + "\n" for c in checkpoints))
    anchors = out_dir / "anchors"
    anchors.mkdir(exist_ok=True)
    for old in anchors.glob(f"{receipts.ANCHOR_PREFIX}*.json"):
        old.unlink()
    for c in checkpoints:
        (anchors / f"{receipts.anchor_name(c)}.json").write_text(json.dumps(c, sort_keys=True, indent=1) + "\n")
    meta = {"spec": "Agent Action Receipts v0.1", "warning": "PUBLIC TEST KEY. Never use it for a real ledger.",
            "test_master_key_hex": TEST_MASTER_KEY.hex(), "mac_key_hex": keys.mac_key.hex(),
            "signer_pubkey": keys.pubkey, "session": SESSION, "agent": AGENT, "ledger_path": LEDGER_PATH,
            "policy_toml": POLICY_TOML, "policy_version": pv, "policy_sha256": psha,
            "requests": [{"request_id": r["rid"], "action": r["action"]} for r in _requests()]}
    _dump(out_dir / "vectors.json", meta)
    _dump(out_dir / "fingerprints.json", fingerprints)
    _dump(out_dir / "policy_versions.json", policies)
    return out_dir


def _dump(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")


# ====================================================================== verify (independent of the code)

def record_hash(rec: dict) -> str:
    """Spec 3.2."""
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False).encode("utf-8")).hexdigest()


def fingerprint(action: dict, policy_version: str) -> str:
    """Spec 4.1 and 4.2."""
    fields = TYPED_FIELDS.get(action.get("type"), tuple(sorted(action)))
    body = {"action": {k: action.get(k) for k in fields}, "policy_version": policy_version}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def policy_version(rules: dict) -> str:
    """Spec 4.3."""
    return hashlib.sha256(json.dumps(rules, sort_keys=True, default=str).encode()).hexdigest()[:16]


def derive_keys(master: bytes) -> tuple[bytes, bytes]:
    """Spec 6.1: (mac_key, ed25519 seed)."""
    return hmac.new(master, MAC_INFO, hashlib.sha256).digest(), hmac.new(master, SIGN_INFO, hashlib.sha256).digest()


def parse_lines(text: str) -> tuple[list[dict], list[str]]:
    recs, problems = [], []
    for i, line in enumerate(text.split("\n")):
        if not line.strip():
            continue
        try:
            recs.append(json.loads(line))
        except ValueError:
            problems.append(f"line {i}: torn (not JSON)")
    return recs, problems


def check_chain(text: str) -> list[str]:
    """Spec 8, step 1: hashes, prev_hash links and seq. Reports every break."""
    problems = []
    exp_prev, exp_seq = GENESIS, 0
    for i, line in enumerate(text.split("\n")):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            problems.append(f"line {i}: torn")
            continue
        seq = rec.get("seq")
        if rec.get("hash") != record_hash(rec):
            problems.append(f"line {i}: hash_mismatch")
        if rec.get("prev_hash") != exp_prev:
            problems.append(f"line {i}: {'bad_genesis' if i == 0 else 'prev_mismatch'}")
        if seq != exp_seq:
            problems.append(f"line {i}: seq_gap (expected {exp_seq}, found {seq})")
        exp_prev = rec.get("hash") or exp_prev
        exp_seq = (seq if isinstance(seq, int) else exp_seq) + 1
    return problems


def mac_input(rec: dict, n: int) -> bytes:
    """Spec 6.2, MAC v1 (records written before v2)."""
    meta = {k: v for k, v in (rec.get("meta") or {}).items() if k != "hg_mac"}
    body = {"v": 1, "n": n, "agent": rec.get("agent"), "session": rec.get("session"), "action": rec.get("action"),
            "target": rec.get("target"), "summary": rec.get("summary"), "phase": rec.get("phase"), "meta": meta}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def mac_input_v2(rec: dict) -> bytes:
    """Spec 6.2, MAC v2: the record without `hash`, and without `mac` inside meta.hg_mac."""
    body = {k: v for k, v in rec.items() if k != "hash"}
    meta = dict(body.get("meta") or {})
    meta["hg_mac"] = {k: v for k, v in meta["hg_mac"].items() if k != "mac"}
    body["meta"] = meta
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _keyed(r: dict) -> bool:
    return isinstance(r.get("meta"), dict) and isinstance(r["meta"].get("hg_mac"), dict)


def check_macs(recs: list[dict], mac_key: bytes) -> list[str]:
    """Spec 8, step 2."""
    problems, expected, began, v2_seen, claims = [], {}, False, False, set()
    first = next((r.get("seq") for r in recs if _keyed(r)), None)
    for i, r in enumerate(recs):
        meta = r.get("meta") if isinstance(r.get("meta"), dict) else {}
        m = meta.get("hg_mac")
        if not isinstance(m, dict):
            act = str(r.get("action", ""))
            must = act.startswith(("gate.", "policy.")) or (v2_seen and act.startswith("egress."))
            if began and r.get("agent") == AGENT and must:
                problems.append(f"record {i}: no MAC after MACs began ({act})")
            continue
        began = True
        try:
            n = int(m["n"])
            inp = mac_input(r, n) if m.get("v") == 1 else mac_input_v2(r) if m.get("v") == 2 else None
            good = inp is not None and hmac.compare_digest(hmac.new(mac_key, inp, hashlib.sha256).hexdigest(),
                                                           str(m.get("mac", "")))
        except (KeyError, TypeError, ValueError):
            n, good = None, False
        if not good:
            problems.append(f"record {i}: MAC does not verify")
            continue
        if m.get("v") == 2:
            v2_seen = True
            claims.add(m.get("began"))
        s = str(r.get("session"))
        exp = expected.get(s, 0)
        if n != exp:
            problems.append(f"record {i}: session {s} MAC counter {n}, expected {exp}")
        expected[s] = max(n + 1, exp)
    for b in claims:
        if b != first:
            problems.append(f"MACs began at record {b}, but the first record with a MAC is {first} (MACs stripped)")
    return problems


def check_ordering(recs: list[dict]) -> list[str]:
    """Spec 5.3, rules O1 to O6. Only this tool checks them; the gate's watch does not."""
    problems, by_rid = [], {}
    for i, r in enumerate(recs):
        rid = (r.get("meta") or {}).get("request_id") if isinstance(r.get("meta"), dict) else None
        if rid is not None and str(r.get("action", "")).startswith("gate."):
            by_rid.setdefault(rid, []).append((i, r))
    for rid, group in by_rid.items():
        acts = [r.get("action") for _, r in group]
        if acts[0] != "gate.request":
            problems.append(f"request {rid}: first record is {acts[0]}, not gate.request (O1)")
        decisions = [(i, r) for i, r in group if r.get("action") == "gate.decision"]
        posts = [(i, r) for i, r in group if r.get("action") in POST_ACTIONS]
        if len(decisions) > 1 or len(posts) > 1:
            problems.append(f"request {rid}: {len(decisions)} decisions and {len(posts)} outcomes (O3)")
        for i, r in group:
            want = POST if r.get("action") in POST_ACTIONS else PRE
            if r.get("phase") != want:
                problems.append(f"request {rid}: {r.get('action')} has phase {r.get('phase')} (O2)")
        if posts:
            pi, pr = posts[0]
            if not decisions or decisions[0][0] > pi:
                problems.append(f"request {rid}: outcome {pr.get('action')} with no earlier decision (O4)")
            elif pr.get("action") in ("gate.executed", "gate.failed") and \
                    decisions[0][1]["meta"].get("decision") != "approve":
                problems.append(f"request {rid}: {pr.get('action')} after decision "
                                f"{decisions[0][1]['meta'].get('decision')} (O5)")
            elif pr.get("action") == "gate.expired" and decisions[0][1]["meta"].get("decision") != "expired":
                problems.append(f"request {rid}: gate.expired after a decision that was not expired (O5)")
            elif pr.get("action") == "gate.denied" and decisions[0][1]["meta"].get("decision") not in ("deny", "expired"):
                problems.append(f"request {rid}: gate.denied after an approval (O5)")
            if any(i > pi for i, _ in group):
                problems.append(f"request {rid}: records after its outcome (O2)")
        pins = {((r.get("meta") or {}).get("payload_sha256"), (r.get("meta") or {}).get("policy_version"))
                for _, r in group}
        if len(pins) != 1:
            problems.append(f"request {rid}: payload_sha256 or policy_version differs between its records (O6)")
    return problems


def _ed25519_verify(pub_hex: str, sig_hex: str, msg: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(bytes.fromhex(sig_hex), msg)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def jcs(obj) -> bytes:
    """RFC 8785, enough for checkpoint bodies (strings, integers, booleans, null, flat objects)."""
    if obj is None:
        return b"null"
    if obj is True:
        return b"true"
    if obj is False:
        return b"false"
    if isinstance(obj, int):
        return str(obj).encode()
    if isinstance(obj, float):
        if obj.is_integer() and abs(obj) < 1e21:
            return str(int(obj)).encode()
        return repr(obj).encode()          # not reached by checkpoint bodies
    if isinstance(obj, str):
        out = ['"']
        for ch in obj:
            c = ord(ch)
            if ch == '"':
                out.append('\\"')
            elif ch == "\\":
                out.append("\\\\")
            elif c < 0x20:
                out.append({8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r"}.get(c, f"\\u{c:04x}"))
            else:
                out.append(ch)
        out.append('"')
        return "".join(out).encode("utf-8")
    if isinstance(obj, list):
        return b"[" + b",".join(jcs(x) for x in obj) + b"]"
    if isinstance(obj, dict):
        keys = sorted(obj, key=lambda k: k.encode("utf-16-be"))
        return b"{" + b",".join(jcs(k) + b":" + jcs(obj[k]) for k in keys) + b"}"
    raise TypeError(type(obj))


def check_checkpoint(cp: dict, recs: list[dict], signer: str | None = None) -> list[str]:
    """Spec 8, step 3."""
    problems = []
    if not cp.get("signature"):
        if signer is not None:
            return [f"checkpoint at {cp.get('records')} records: unsigned, and a signer is pinned"]
        return [] if cp.get("signed") is False and _extends(cp, recs) is None else \
            [_extends(cp, recs) or "unsigned checkpoint that does not say it is unsigned"]
    if signer is not None and cp.get("signer_pubkey") != signer:
        problems.append(f"checkpoint at {cp.get('records')} records: signed by another key")
    if not _ed25519_verify(cp["signer_pubkey"], cp["signature"], f"{cp['head_hash']}:{cp['records']}".encode()):
        problems.append(f"checkpoint at {cp.get('records')} records: head signature does not verify")
    if "gate_signature" in cp:
        body = jcs({k: v for k, v in cp.items() if k not in ("gate_signature", "attestation")})
        if not _ed25519_verify(cp["signer_pubkey"], cp["gate_signature"], body):
            problems.append(f"checkpoint at {cp.get('records')} records: gate signature does not verify")
    if cp.get("attestation") is not None:
        want = (f"hsm-checkpoint v1 head={cp['head_hash']} records={cp['records']} ts={cp['ts']} "
                f"pubkey={cp['signer_pubkey']} sig={cp['signature']}")
        if cp["attestation"] != want:
            problems.append(f"checkpoint at {cp.get('records')} records: attestation line does not match")
    why = _extends(cp, recs)
    if why:
        problems.append(f"checkpoint at {cp.get('records')} records: {why}")
    return problems


def _extends(cp: dict, recs: list[dict]) -> str | None:
    n, head = int(cp["records"]), str(cp["head_hash"])
    if n > len(recs):
        return f"ledger has {len(recs)} records, {n} were checkpointed (records removed)"
    if n >= 1 and recs[n - 1].get("hash") != head:
        return f"record {n - 1} is not the checkpointed head (chain rebuilt)"
    if recs and cp.get("ledger_id") not in (None, recs[0].get("hash")):
        return "ledger_id is not this ledger's first record hash"
    return None


def verify(vec_dir: Path = DEFAULT_DIR, *, ledger_text: str | None = None, mac_key: bytes | None = None,
           checkpoints: list[dict] | None = None) -> list[str]:
    """Every check in spec section 8, plus the fingerprint and policy-version vectors.
    Empty list means everything passed. ledger_text, mac_key and checkpoints override the files."""
    d = Path(vec_dir)
    meta = json.loads((d / "vectors.json").read_text(encoding="utf-8"))
    text = ledger_text if ledger_text is not None else (d / "ledger.jsonl").read_text(encoding="utf-8")
    problems = check_chain(text)
    recs, torn = parse_lines(text)
    if mac_key is None:
        mac_key, seed = derive_keys(bytes.fromhex(meta["test_master_key_hex"]))
        if mac_key.hex() != meta["mac_key_hex"]:
            problems.append("mac key derivation does not match vectors.json")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
        pub = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        if pub != meta["signer_pubkey"]:
            problems.append("signing key derivation does not match vectors.json")
    problems += check_macs(recs, mac_key)
    problems += check_ordering(recs)
    cps = checkpoints if checkpoints is not None else \
        [json.loads(x) for x in (d / "checkpoints.jsonl").read_text().splitlines() if x.strip()]
    for cp in cps:
        problems += check_checkpoint(cp, recs, signer=meta["signer_pubkey"])
    for p in sorted((d / "anchors").glob("hg-checkpoint-*.json")):
        cp = json.loads(p.read_text())
        if cp not in cps:
            problems.append(f"anchor {p.name} is not in checkpoints.jsonl")
    # payloads published next to the ledger: recompute each request's fingerprint
    by_rid = {r["request_id"]: r["action"] for r in meta["requests"]}
    for r in recs:
        m = r.get("meta") or {}
        if m.get("request_id") in by_rid:
            if m.get("payload_sha256") != fingerprint(by_rid[m["request_id"]], m.get("policy_version", "")):
                problems.append(f"seq {r.get('seq')}: payload_sha256 does not match the published action")
    for case in json.loads((d / "fingerprints.json").read_text(encoding="utf-8")):
        if fingerprint(case["action"], case["policy_version"]) != case["payload_sha256"]:
            problems.append(f"fingerprint vector {case['label']!r} does not reproduce")
        body = json.loads(case["preimage"])
        if hashlib.sha256(case["preimage"].encode()).hexdigest() != case["payload_sha256"] or \
                body["policy_version"] != case["policy_version"]:
            problems.append(f"fingerprint vector {case['label']!r}: preimage does not hash to it")
    for case in json.loads((d / "policy_versions.json").read_text(encoding="utf-8")):
        if policy_version(case["rules"]) != case["version"]:
            problems.append(f"policy version vector {case['label']!r} does not reproduce")
    return problems


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("generate", "verify"):
        print(__doc__.strip().splitlines()[2], file=sys.stderr)
        print(__doc__.strip().splitlines()[3], file=sys.stderr)
        return 2
    d = Path(argv[1]) if len(argv) > 1 else DEFAULT_DIR
    if argv[0] == "generate":
        print(f"wrote {generate(d)}")
        return 0
    problems = verify(d)
    for p in problems:
        print(f"FAIL {p}")
    print("all vectors verify" if not problems else f"{len(problems)} problem(s)")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
