"""Receipts as audit evidence: signed checkpoints, off-machine anchors, keyed records.

The homestead-memory chain catches an edited record. It cannot catch someone with your files who
rebuilds the whole chain: its links are plain SHA-256, so they can be recomputed. Three things here
close most of that gap, all gate-side and all backward compatible (old ledgers verify as before):

1. Signed checkpoints, written automatically when a gate session ends, after every scheduled pass
   and on `homestead-gate watch`. Each one records the head hash, the record count, the time, the
   policy version and the reviewer model. The signature over `head:records` is exactly the one
   `hsm checkpoint` makes, so `hsm watch` and `hsm checkpoint --verify` understand it; a second
   signature covers the whole checkpoint (time, policy version, reviewer). The key is NOT a file:
   it comes from the OS credential store (credstore.py, entry "homestead-gate-ledger-key"),
   generated on first use. No credential store: checkpoints are written unsigned, with a warning.

2. Anchors outside the machine. Policy `[receipts] anchor_dir` gets one new file per checkpoint,
   created exclusively and never rewritten; `anchor_command` gets the checkpoint JSON on stdin
   (email it to yourself, git-push it, ask an RFC 3161 timestamp authority to stamp it). A rebuilt
   chain cannot match a head that was anchored before the rebuild, and `watch --anchors DIR` says
   which anchored checkpoint is the first one the local chain no longer matches.

3. A keyed MAC on every record the gate writes (gate, policy and, from `run`, egress records), in its
   meta (`hg_mac`). Version 2 covers the whole record, including seq, ts and prev_hash, so without the
   key a rebuilt record fails its MAC, and so does the record after anything inserted, deleted or
   moved. A per-session counter and the seq where MACs began (`began`) are covered too. To compute it
   inside homestead-memory's lock, `append` writes the line itself, exactly as ledger.append does.

A checkpoint is never signed over a chain that does not verify, whose MACs fail, or that does not
extend every earlier checkpoint it can see: local files, anchors, and the last sealed head, which is
kept in the credential store (entry "homestead-gate-ledger-head") because it is the one local record
someone with only your files can't rewrite. Otherwise the gate's own automatic signing would launder a
rebuild: strip the MACs, rebuild the file, delete the checkpoint files, wait for the next pass, get a
fresh signature.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from homestead_memory.core import jcs, ledger, provenance, store

from . import credstore

CHECKPOINTS_FILE = "checkpoints.jsonl"       # in the ledger dir: every checkpoint this ledger got
MAC_FIELD = "hg_mac"
MAC_VERSION = 2                              # 1: records written before 2026-10-05 (still verified)
CHECKPOINT_VERSION = 1
ANCHOR_PREFIX = "hg-checkpoint-"
ANCHOR_TIMEOUT_S = 60
_SIGN_INFO = b"homestead-gate checkpoint ed25519 v1"
_MAC_INFO = b"homestead-gate record mac v1"


# ---------------------------------------------------------------- keys

@dataclass
class Keys:
    """Both keys derive from one master secret in the credential store. The signer is None when
    `cryptography` is missing (MACs still work)."""
    mac_key: bytes
    signer: object | None
    pubkey: str | None

    @classmethod
    def from_master(cls, master: bytes) -> "Keys":
        seed = hmac.new(master, _SIGN_INFO, hashlib.sha256).digest()
        mac_key = hmac.new(master, _MAC_INFO, hashlib.sha256).digest()
        try:
            from homestead_memory.core import signing
            ed25519, serialization, _ = signing._ed25519()
        except RuntimeError:
            return cls(mac_key, None, None)
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        pub = sk.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                           format=serialization.PublicFormat.Raw).hex()
        return cls(mac_key, sk, pub)


def ledger_keys(create: bool = True, warn: Callable[[str], None] = print) -> Keys | None:
    """The ledger keys from the OS credential store, or None (with a warning) when there is none.
    `create=False` only loads: verifying on someone else's machine must not plant a key there."""
    try:
        master = credstore.load_or_create_ledger_key() if create else credstore.load_ledger_key()
    except credstore.CredentialError as e:
        if create:
            warn(f"receipts: WARNING: no ledger key ({e}). Checkpoints are written UNSIGNED and new "
                 "records carry no MAC; anchors still catch a rebuilt chain.")
        return None
    return Keys.from_master(master) if master else None


# ---------------------------------------------------------------- keyed records

_counters: dict[tuple[str, str], int] = {}
_began: dict[str, int] = {}                  # ledger -> seq of its first MAC'd record, once known
_locks: dict[str, threading.Lock] = {}
_registry_lock = threading.Lock()


def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _mac_input(*, n: int, agent: str, session: str, action: str, target, summary, phase, meta: dict) -> bytes:
    """MAC v1 (records written before 2026-10-05): content and counter, not seq/ts/prev_hash."""
    return _canon({"v": 1, "n": n, "agent": agent, "session": session, "action": action,
                   "target": target, "summary": summary, "phase": phase,
                   "meta": {k: v for k, v in meta.items() if k != MAC_FIELD}})


def _mac_input_v2(rec: dict) -> bytes:
    """MAC v2: the whole record as it is hashed (every key but `hash`, so seq, ts and prev_hash too),
    with `mac` itself left out of meta.hg_mac. Binding prev_hash chains each MAC to the record before it:
    a record inserted, deleted or moved anywhere before a v2 record breaks that record's MAC."""
    body = {k: v for k, v in rec.items() if k != "hash"}
    meta = dict(body.get("meta") or {})
    meta[MAC_FIELD] = {k: v for k, v in (meta.get(MAC_FIELD) or {}).items() if k != "mac"}
    body["meta"] = meta
    return _canon(body)


def _is_mac(r: dict) -> bool:
    return isinstance(r.get("meta"), dict) and isinstance(r["meta"].get(MAC_FIELD), dict)


def append(mac_key: bytes, action: str, *, target: str | None, summary: str | None, meta: dict,
           vault: Path, agent: str, session: str | None, phase: str | None) -> dict:
    """Append one record with an HMAC (v2) in meta.hg_mac, under homestead-memory's ledger lock.

    This is homestead-memory's ledger.append, line for line (same lock file, same envelope, same
    hash, same O_APPEND + fsync; tests/test_receipts_spec.py checks the bytes are identical), with one
    difference: the MAC is computed inside the lock, after seq, ts and prev_hash are known, so it can
    cover them. ledger.append takes its lock itself and the lock is not reentrant, so the gate cannot
    wrap it. hg_mac also carries `n` (the per-session counter) and `began`: the seq of the first record
    in this ledger that has a MAC, so stripping the MACs from the first sessions is detectable."""
    root = Path(vault).expanduser()             # homestead_memory.core.vault._resolve, for a given path
    path = root / ledger.LEDGER_REL
    path.parent.mkdir(parents=True, exist_ok=True)
    agent_s, session_s = provenance.resolve_agent(agent), provenance.resolve_session(session)
    lk = str(root.resolve())
    with _registry_lock:
        lock = _locks.setdefault(lk, threading.Lock())
    with lock, store.vault_lock(root):
        prev = ledger._last_record(path)
        seq = (prev["seq"] + 1) if prev else 0
        k = (lk, session_s)
        scan = None
        if lk not in _began or _counters.get(k) is None:
            scan = ledger.read_all(root) if prev else []
        if lk not in _began:
            first = next((r.get("seq") for r in scan if _is_mac(r)), None)
            if isinstance(first, int):
                _began[lk] = first
        began = _began.get(lk, seq)
        n = _counters.get(k)
        if n is None:                            # a session resumed in a new process continues its count
            n = 1 + max((int(r["meta"][MAC_FIELD]["n"]) for r in scan
                         if r.get("session") == session_s and _is_mac(r)), default=-1)
        clean = json.loads(json.dumps(meta or {}))   # exactly what a reader will parse back
        clean[MAC_FIELD] = {"v": MAC_VERSION, "n": n, "alg": "hmac-sha256", "began": began}
        rec = {"v": ledger.LEDGER_VERSION, "seq": seq, "ts": provenance.now_ts(), "agent": agent_s,
               "session": session_s, "action": action, "target": target, "summary": summary,
               "meta": clean, "prev_hash": prev["hash"] if prev else ledger.GENESIS_HASH}
        if phase:
            rec["phase"] = phase
        clean[MAC_FIELD]["mac"] = hmac.new(mac_key, _mac_input_v2(rec), hashlib.sha256).hexdigest()
        rec["hash"] = ledger.record_hash(rec)
        line = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        _began.setdefault(lk, began)
        _counters[k] = n + 1
        return rec


@dataclass
class MacReport:
    checked: int = 0
    unkeyed_before: int = 0                   # records written before MACs began (old ledgers): fine
    bad: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)
    stripped: list[str] = field(default_factory=list)   # records without a MAC after MACs began

    @property
    def ok(self) -> bool:
        return not (self.bad or self.gaps or self.stripped)

    def problems(self) -> list[str]:
        return self.bad + self.gaps + self.stripped


def has_macs(recs: list[dict]) -> bool:
    return any(isinstance(r.get("meta"), dict) and MAC_FIELD in r["meta"] for r in recs)


# Records that must carry a MAC once MACs began. egress.denied only from the first v2 record on: before
# that, `run` wrote them without one, and flagging those would make seal refuse every existing ledger.
def _must_mac(r: dict, v2_seen: bool) -> bool:
    if r.get("agent") != "homestead-gate":
        return False
    a = str(r.get("action", ""))
    return a.startswith(("gate.", "policy.")) or (v2_seen and a.startswith("egress."))


def verify_macs(recs: list[dict], mac_key: bytes) -> MacReport:
    rep = MacReport()
    expected: dict[str, int] = {}
    began = v2_seen = False
    first = next((r.get("seq") for r in recs if _is_mac(r)), None)
    claims: set = set()
    for i, r in enumerate(recs):
        meta = r.get("meta") if isinstance(r.get("meta"), dict) else {}
        m = meta.get(MAC_FIELD)
        if not isinstance(m, dict):
            if not began:
                rep.unkeyed_before += 1
            elif _must_mac(r, v2_seen):
                rep.stripped.append(f"record {i} ({r.get('action')}) has no MAC, written after MACs began: "
                                    "forged, or written while the key store was unavailable")
            continue
        began = True
        rep.checked += 1
        try:
            n, v = int(m["n"]), m.get("v")
            if v == 1:
                inp = _mac_input(n=n, agent=r.get("agent"), session=r.get("session"), action=r.get("action"),
                                 target=r.get("target"), summary=r.get("summary"), phase=r.get("phase"), meta=meta)
            elif v == 2:
                inp = _mac_input_v2(r)
            else:
                raise ValueError(f"unknown MAC version {v!r}")
            want = hmac.new(mac_key, inp, hashlib.sha256).hexdigest()
            good = hmac.compare_digest(want, str(m.get("mac", "")))
        except (KeyError, TypeError, ValueError):
            n, v, good = None, None, False
        if not good:
            rep.bad.append(f"record {i} ({r.get('action')}) fails its MAC: rewritten, inserted, removed or "
                           "moved without the key")
            continue
        if v == 2:
            v2_seen = True
            claims.add(m.get("began"))
        s = str(r.get("session"))
        exp = expected.get(s, 0)                 # every session's counter starts at 0
        if n != exp:
            rep.gaps.append(f"session {s}: record {i} has MAC counter {n}, expected {exp} "
                            + ("(records removed)" if n > exp else "(records reordered or duplicated)"))
        expected[s] = max(n + 1, exp)
    for b in sorted(claims, key=str):
        if b != first:
            pre = [j for j, r in enumerate(recs) if not _is_mac(r) and isinstance(b, int)
                   and isinstance(r.get("seq"), int) and b <= r["seq"] < (first if isinstance(first, int) else 0)
                   and _must_mac(r, False)]
            rep.stripped.append(f"MACs began at record {b} (say the keyed records), but the first record with a "
                                f"MAC is {first}: the MACs of the records before it were stripped"
                                + (f" (records {pre[0]}..{pre[-1]})" if pre else ""))
    return rep


# ---------------------------------------------------------------- checkpoints

def _snapshot(root: Path) -> tuple[list[dict], list]:
    """Records and chain breaks from ONE read under the ledger's lock, so the head and the count
    can't come from different moments (another process may be appending)."""
    with store.vault_lock(root):
        return ledger.read_all(root), ledger.verify_chain(root)


def attestation_line(cp: dict) -> str | None:
    """The line `hsm checkpoint --export` prints, so `hsm checkpoint --verify` reads an anchor."""
    if not cp.get("signature"):
        return None
    return (f"{ledger.ATTESTATION_PREFIX} head={cp['head_hash']} records={cp['records']} ts={cp['ts']} "
            f"pubkey={cp['signer_pubkey']} sig={cp['signature']}")


def _gate_body(cp: dict) -> bytes:
    return jcs.canonicalize({k: v for k, v in cp.items() if k not in ("gate_signature", "attestation")})


def check_signatures(cp: dict) -> str | None:
    """None when every signature on the checkpoint verifies (or it is honestly unsigned)."""
    if not cp.get("signature"):
        return None if cp.get("signed") is False else "checkpoint has no signature and does not say it is unsigned"
    from homestead_memory.core import signing
    try:
        ed25519, _s, Invalid = signing._ed25519()
    except RuntimeError as e:
        return f"signature not checked: {e}"
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(cp["signer_pubkey"]))
        pub.verify(bytes.fromhex(cp["signature"]), f"{cp['head_hash']}:{cp['records']}".encode())
        if "gate_signature" in cp:
            pub.verify(bytes.fromhex(cp["gate_signature"]), _gate_body(cp))
    except (Invalid, KeyError, ValueError, TypeError):
        return "signature does not verify"
    return None


def _extends(recs: list[dict], cp: dict) -> str | None:
    """None if the local chain still contains the checkpointed head at the checkpointed length."""
    try:
        n, head = int(cp["records"]), str(cp["head_hash"])
    except (KeyError, TypeError, ValueError):
        return "unreadable checkpoint"
    if n > len(recs):
        return f"the ledger has {len(recs)} records but {n} were checkpointed (records removed)"
    if n >= 1 and recs[n - 1].get("hash") != head:
        return (f"record {n - 1} hashes to {str(recs[n - 1].get('hash'))[:12]}…, the checkpoint says "
                f"{head[:12]}… (the chain was rebuilt)")
    return None


def _head_account(root: Path) -> str:
    return hashlib.sha256(str(Path(root).resolve()).encode()).hexdigest()[:16]


def stored_head(root: Path) -> dict | None:
    """The last head the gate sealed for this ledger, from the credential store (None if none, or no
    store). Loading never creates anything, so this is safe on an auditor's machine."""
    try:
        v = credstore.load_ledger_head(_head_account(root))
    except credstore.CredentialError:
        return None
    if not v:
        return None
    n, _, head = v.strip().partition(":")
    try:
        return {"records": int(n), "head_hash": head}
    except ValueError:
        return {"records": -1, "head_hash": "unreadable"}


def _remember_head(root: Path, cp: dict) -> str | None:
    try:
        credstore.store_ledger_head(_head_account(root), f"{int(cp['records'])}:{cp['head_hash']}")
    except credstore.CredentialError as e:
        return f"WARNING: could not record the sealed head in the credential store: {e}"
    return None


def check_stored_head(root: Path, recs: list[dict]) -> str | None:
    """None when the chain still extends the head this machine last sealed (or there is none)."""
    h = stored_head(root)
    return None if h is None else _extends(recs, h)


def _local_checkpoints(root: Path) -> list[dict]:
    out = []
    p = root / CHECKPOINTS_FILE
    if p.exists():
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                cp = json.loads(line)
                if isinstance(cp, dict):
                    out.append(cp)
            except ValueError:
                continue
    sig = root / ledger.CHECKPOINT_REL
    if sig.exists():
        try:
            cp = json.loads(sig.read_text(encoding="utf-8"))
            if isinstance(cp, dict):
                out.append(cp)
        except ValueError:
            pass
    return out


def load_anchors(anchor_dir: Path) -> list[tuple[Path, dict]]:
    out = []
    d = Path(anchor_dir).expanduser()
    if not d.is_dir():
        return out
    for p in sorted(d.rglob(f"{ANCHOR_PREFIX}*.json")):
        try:
            cp = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(cp, dict):
            continue
        try:
            cp["records"] = int(cp["records"])
            str(cp["head_hash"])
        except (KeyError, TypeError, ValueError):
            cp = {"_malformed": True, "records": 0, "head_hash": "", "ledger": cp.get("ledger"),
                  "ledger_id": cp.get("ledger_id")}
        out.append((p, cp))
    return out


def _for_this_ledger(root: Path, recs: list[dict], anchors: list[tuple[Path, dict]]):
    here = str(root.resolve())
    gid = recs[0].get("hash") if recs else None
    mine = [(p, c) for p, c in anchors if c.get("ledger") == here or (gid and c.get("ledger_id") == gid)]
    return mine, [(p, c) for p, c in anchors if (p, c) not in mine]


@dataclass
class SealResult:
    status: str                               # written | unchanged | empty | refused
    checkpoint: dict | None = None
    anchored: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def seal(ledger_dir: Path, *, policy=None, reviewer_model: str | None = None, reason: str = "",
         keys: Keys | None = None, log: Callable[[str], None] = print) -> SealResult:
    """Write a checkpoint of the ledger as it is now, and anchor it. Refuses (and says so) rather
    than sign a chain that does not verify or does not extend every earlier checkpoint."""
    root = Path(ledger_dir).expanduser()
    if not (root / ledger.LEDGER_REL).exists():
        return SealResult("empty")
    recs, breaks = _snapshot(root)
    if not recs:
        return SealResult("empty")
    res = SealResult("refused")
    if breaks:
        res.problems.append(f"the chain has {len(breaks)} break(s), first at record {breaks[0].index}: "
                            f"{breaks[0].detail}")
    if keys is not None:
        res.problems += verify_macs(recs, keys.mac_key).problems()
    anchor_dir = Path(policy.anchor_dir).expanduser() if policy is not None and policy.anchor_dir else None
    earlier = [("local", c) for c in _local_checkpoints(root)]
    sh = stored_head(root)
    if sh is not None:
        earlier.append(("the head last sealed on this machine, kept in the credential store", sh))
    if anchor_dir is not None:
        earlier += [(str(p), c) for p, c in _for_this_ledger(root, recs, load_anchors(anchor_dir))[0]]
    for where, cp in earlier:
        why = _extends(recs, cp) or (check_signatures(cp) if cp.get("signature") else None)
        if why:
            res.problems.append(f"does not match an earlier checkpoint ({where}): {why}")
    if res.problems:
        for pr in res.problems:
            log(f"receipts: REFUSED to checkpoint {root}: {pr}")
        log("receipts: run `homestead-gate watch --ledger " + str(root) + "` and compare with your anchors.")
        return res

    head, count = recs[-1]["hash"], len(recs)
    newest = max(earlier, key=lambda wc: int(wc[1].get("records", 0)), default=None)
    if newest and newest[1].get("head_hash") == head and int(newest[1].get("records", -1)) == count:
        return SealResult("unchanged", checkpoint=newest[1])

    cp = {"hg_checkpoint": CHECKPOINT_VERSION, "head_hash": head, "records": count,
          "ts": provenance.now_ts(), "ledger": str(root.resolve()), "ledger_id": recs[0]["hash"],
          "policy_version": getattr(policy, "version", None), "reviewer_model": reviewer_model,
          "reason": reason, "ledger_version": ledger.LEDGER_VERSION}
    if keys is not None and keys.signer is not None:
        from homestead_memory.core import signing
        cp.update(signed=True, alg=signing.ALG, sig_version=signing.SIG_VERSION, signer_pubkey=keys.pubkey,
                  signature=keys.signer.sign(f"{head}:{count}".encode()).hex())
        cp["gate_signature"] = keys.signer.sign(_gate_body(cp)).hex()
        cp["attestation"] = attestation_line(cp)
    else:
        cp.update(signed=False, signer_pubkey=None, signature=None)
        res.warnings.append("checkpoint is UNSIGNED (no ledger key); it still anchors the head hash")
    line = json.dumps(cp, sort_keys=True) + "\n"
    fd = os.open(str(root / CHECKPOINTS_FILE), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    if cp["signed"]:
        store.atomic_write(root / ledger.CHECKPOINT_REL, line)     # what `hsm watch` reads
    res.status, res.checkpoint = "written", cp
    remembered = _remember_head(root, cp)
    if remembered:
        res.warnings.append(remembered)
    res.anchored, anchor_problems = anchor(cp, policy)
    res.warnings += anchor_problems
    for w in res.warnings:
        log(f"receipts: {w}")
    return res


def anchor_name(cp: dict) -> str:
    return f"{ANCHOR_PREFIX}{str(cp.get('ledger_id'))[:12]}-{int(cp['records']):09d}-{cp['head_hash'][:16]}"


def anchor(cp: dict, policy) -> tuple[list[str], list[str]]:
    """Append the checkpoint to every configured anchor. Returns (where it went, what failed)."""
    done, failed = [], []
    if policy is None:
        return done, failed
    body = json.dumps(cp, sort_keys=True, indent=1) + "\n"
    name = anchor_name(cp)
    if policy.anchor_dir:
        d = Path(policy.anchor_dir).expanduser()
        try:
            d.mkdir(parents=True, exist_ok=True)
            p = d / f"{name}.json"
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)   # new files only, never a rewrite
            try:
                os.write(fd, body.encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            done.append(str(p))
        except FileExistsError:
            done.append(str(d / f"{name}.json"))
        except OSError as e:
            failed.append(f"WARNING: could not anchor to {d}: {e}")
    if policy.anchor_command:
        with tempfile.TemporaryDirectory(prefix="hg-anchor-") as td:
            f = Path(td) / f"{name}.json"
            f.write_text(body)
            env = {**os.environ, "HG_CHECKPOINT": str(f), "HG_CHECKPOINT_NAME": name}
            try:
                r = subprocess.run(["/bin/sh", "-c", policy.anchor_command], input=body, text=True,
                                   capture_output=True, timeout=ANCHOR_TIMEOUT_S, env=env)
                if r.returncode == 0:
                    done.append("anchor_command")
                else:
                    failed.append(f"WARNING: anchor_command exited {r.returncode}: "
                                  f"{(r.stderr or r.stdout or '').strip()[:200]}")
            except (OSError, subprocess.SubprocessError) as e:
                failed.append(f"WARNING: anchor_command failed: {e}")
    return done, failed


# ---------------------------------------------------------------- verification against anchors

@dataclass
class AnchorReport:
    ok: bool
    lines: list[str] = field(default_factory=list)
    last_good: dict | None = None
    first_bad: dict | None = None


def verify_anchors(ledger_dir: Path, anchor_dir: Path, signer: str | None = None) -> AnchorReport:
    """Re-verify the local chain against every checkpoint anchored for it. Fails closed: anchors that
    exist but none of which belong to this ledger is a failure, not a pass."""
    root = Path(ledger_dir).expanduser()
    recs, breaks = _snapshot(root) if (root / ledger.LEDGER_REL).exists() else ([], [])
    rep = AnchorReport(ok=True)
    say = rep.lines.append
    if breaks:
        rep.ok = False
        say(f"!! the local chain itself is broken: {len(breaks)} break(s), first at record {breaks[0].index}")
    allofthem = load_anchors(anchor_dir)
    if not allofthem:
        rep.ok = False
        say(f"!! no anchored checkpoints in {anchor_dir}")
        return rep
    mine, other = _for_this_ledger(root, recs, allofthem)
    if not mine:
        rep.ok = False
        seen = sorted({str(c.get("ledger")) for _, c in other})
        say(f"!! {len(allofthem)} anchored checkpoint(s) in {anchor_dir}, none for this ledger (its first record "
            f"is not the one they anchored). They belong to: {', '.join(seen)}. A chain rebuilt from its first "
            "record looks exactly like this.")
        return rep
    mine.sort(key=lambda pc: (int(pc[1].get("records", 0)), str(pc[1].get("ts"))))
    pin = signer
    for p, cp in mine:
        if cp.get("_malformed"):
            rep.ok = False
            say(f"!! anchored file {p.name} is not a readable checkpoint")
            continue
        label = f"{int(cp['records'])} records at {cp.get('ts')} ({p.name})"
        sig_problem = check_signatures(cp)
        if not sig_problem and signer is not None and not cp.get("signature"):
            # anyone can write an unsigned checkpoint; with a pinned signer it proves nothing
            sig_problem = "unsigned, and a signer is pinned (--signer)"
        if sig_problem:
            rep.ok = False
            say(f"!! anchored checkpoint {label}: {sig_problem}")
            continue
        if cp.get("signer_pubkey"):
            if pin is None:
                pin = cp["signer_pubkey"]
            elif cp["signer_pubkey"] != pin:
                if signer is not None:
                    rep.ok = False
                    say(f"!! anchored checkpoint {label} is signed by {cp['signer_pubkey'][:16]}…, not {pin[:16]}…")
                    continue
                say(f"-- anchored checkpoint {label}: signer changed to {cp['signer_pubkey'][:16]}… (new key?)")
        why = _extends(recs, cp)
        if why is None:
            if rep.first_bad is None:
                rep.last_good = cp
        else:
            rep.ok = False
            if rep.first_bad is None:
                rep.first_bad = cp
                say(f"!! FIRST DIVERGENCE: anchored checkpoint {label}: {why}")
            else:
                say(f"!! also diverges: anchored checkpoint {label}")
    if rep.first_bad is not None:
        lo = int(rep.last_good["records"]) if rep.last_good else 0
        say(f"!! the local chain matches anchors up to {lo} records; the history between record {lo} and record "
            f"{int(rep.first_bad['records']) - 1} was rewritten or removed after it was anchored")
    elif rep.ok:
        top = int(mine[-1][1]["records"])
        say(f"ok  local chain matches all {len(mine)} anchored checkpoint(s), the latest at {top} records"
            + (f"; {len(recs) - top} record(s) since are not anchored yet" if len(recs) > top else ""))
        if pin:
            say(f"    signer {pin}")
    if other:
        say(f"-- {len(other)} anchored checkpoint(s) in {anchor_dir} belong to other ledgers")
    return rep
