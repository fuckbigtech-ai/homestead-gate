# Agent Action Receipts v0.1

Status: v0.1, written 2026-10-05 against homestead-gate at commit `cbb527d` and homestead-memory 0.5.2.
Not a standard. Part of fuckbigtech.ai.

This document says exactly what homestead-gate writes when an AI agent asks it to send an email or a
wallet transaction, and how anyone can check those records without trusting the gate. The code is the
ground truth. Where this text and the code disagree, the text has a bug. Anything the code does not do
is marked **Not implemented**.

The words MUST, SHOULD and MAY are used as in RFC 2119.

## Summary (for a blog post)

Agent Action Receipts are a small, checkable record of every outbound action an AI agent tried to
take: what it asked to do, what a local model said about it, who said yes or no, and whether it ran.
The gate writes the decision to disk, and forces it to the disk, before the email or transaction
leaves, so a receipt can show that a "no" was enforced and not just noted afterwards. The receipts
never hold the email body or the model's free-text reasoning. They hold a fingerprint of the exact
action and of the rules that judged it, so an old "yes" cannot be reused for a different action or
under different rules. Each record carries the hash of the one before it and a keyed MAC; the gate
signs checkpoints of the whole log and can copy them off the machine. Someone holding only your files
cannot quietly edit, delete or rebuild anything a checkpoint has already covered, and cannot edit a
single gate record without the key. Someone running code as you can rewrite only what no off-machine
anchor has seen yet. The spec, a reference verifier that shares no code with the gate,
and byte-for-byte test vectors are in the homestead-gate repository.

## 1. Scope

A receipt ledger is an append-only JSON Lines file. Each line is one record. homestead-gate writes:

- **gate records** (`gate.*`): one group per outbound request, tied together by `request_id`;
- **policy records** (`policy.*`): which rules were in force, and when they changed;
- **egress records** (`egress.denied`): network connections the sandbox blocked.

Around the ledger sit three kinds of evidence:

- **record MACs**: an HMAC in each new gate and policy record, keyed from the OS credential store;
- **checkpoints**: Ed25519-signed statements of the head hash and record count;
- **anchors**: copies of checkpoints placed where an attacker on this machine cannot rewrite them.

Conformance levels (Section 12): **L1** hash chain, **L2** L1 plus record MACs, **L3** L2 plus signed,
anchored checkpoints.

## 2. Files

| Path | What | Written by |
|---|---|---|
| `<ledger>/.hsm/ledger.jsonl` | the records | `homestead_memory.core.ledger.append` |
| `<ledger>/checkpoints.jsonl` | every checkpoint this ledger got, one JSON object per line | `receipts.seal` |
| `<ledger>/.hsm/ledger.sig` | the newest signed checkpoint (what `hsm watch` reads) | `receipts.seal`, or `hsm checkpoint` |
| `<anchor_dir>/hg-checkpoint-<id12>-<records:09d>-<head16>.json` | one file per checkpoint, never rewritten | `receipts.anchor` |
| `<ledger>/.hsm/ledger.drops.jsonl` | events that could not be recorded | homestead-memory only. The gate never writes it. |

The gate's default ledger is `~/.homestead-gate/ledger`. An assistant data dir uses `<data>/ledger`.
`ledger.jsonl` is created with mode `0600`. Anchor files are created with mode `0644`.

## 3. Records

### 3.1 Envelope

Every record is a JSON object with these keys. homestead-memory sets all of them inside one lock.

| Key | Type | Value |
|---|---|---|
| `v` | integer | `1`. Verifiers do not check it today. |
| `seq` | integer | `0` for the first record, else the previous intact record's `seq + 1`. |
| `ts` | string | UTC, ISO 8601, seconds, for example `2026-10-05T12:00:05+00:00`. The system clock. |
| `agent` | string | `"homestead-gate"` for every gate, policy and egress record. Whitespace becomes `_`, `]` is removed. |
| `session` | string | The gate session: 8 hex characters per `up`, assistant run, scheduled pass or held item; `"demo"` in the demo. Sanitized like `agent`. |
| `action` | string | The record type (Section 5). |
| `target` | string or null | `"gate:<action type>"`, for example `"gate:email"`; `"gate:?"` if the action has no type; `"gate:policy"`; `"egress"`. |
| `summary` | string or null | One short human line. Never the body. |
| `meta` | object | Record data (Section 5). `{}` if none. |
| `prev_hash` | string | 64 lowercase hex: the previous record's `hash`, or 64 zeros for the first record. |
| `phase` | string | `"pre_execution"` or `"post_execution"`. The key is absent when the writer gives no phase (policy records). |
| `hash` | string | 64 lowercase hex, Section 3.2. |

Each line is `C_rec(record) + "\n"` (Section 3.2), appended with `O_APPEND` and then `fsync`. Two
writers cannot read the same head: `ledger.append` holds an advisory lock (`store.vault_lock`) across
"read last record, write one line".

### 3.2 Record hash and canonical form

```
C_rec(x) = UTF-8( json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False) )
hash     = hex( SHA-256( C_rec(record without the "hash" key) ) )
```

- Every key except `hash` is covered, including `phase` when present and the MAC inside `meta`.
- Non-ASCII characters are written as UTF-8, not escaped.
- Numbers use Python's `repr`: `0.0` stays `0.0`, integer `1` and float `1.0` are different bytes.
  This is **not** RFC 8785 (JCS). A verifier in another language MUST reproduce Python's form.
- Keys are sorted by Python string order (code points).

The reference verifier implements this as `record_hash()` in `tools/receipts_vectors.py`.

## 4. Typed-action fingerprint and policy version

### 4.1 Typed action

The fields that decide what an action does are fixed in code per type (`core.TYPED_FIELDS`), never
chosen by the model or the agent:

| `type` | Fields |
|---|---|
| `email` | `type`, `to`, `cc`, `bcc`, `subject`, `body`, `attachments` |
| `wallet_tx` | `type`, `chain_id`, `to`, `value_eth`, `data` |
| anything else | every key the action has, sorted |

`typed_action(action) = {k: action.get(k) for k in fields}`. A missing field is present with value
`null`. Extra keys in an email or wallet action (`"user_intent"`, `"approved": true`, `"note"`) do not
change the fingerprint. An unsupported type is still fingerprinted (over all its keys) and then denied.

### 4.2 Fingerprint (`payload_sha256`)

```
C_fp(x)        = UTF-8( json.dumps(x, sort_keys=True, separators=(",", ":")) )     # ensure_ascii=True
payload_sha256 = hex( SHA-256( C_fp({"action": typed_action(action), "policy_version": pv}) ) )
```

Differences from the record hash: non-ASCII is escaped as `\uXXXX`. Numbers use Python `repr`, so
`"value_eth": 1` and `"value_eth": 1.0` give different fingerprints.

The fingerprint binds an approval to the exact typed action and the rules that judged it. The gate
keeps no approvals to reuse; it uses the fingerprint to refuse, without a second review or question,
an identical retry of something a human refused (or a scheduled pass held) in the same Gate process.
It also uses it to make identical requests that arrive together wait for the first one's decision.

### 4.3 Policy version (`policy_version`)

```
rules          = every attribute of the Policy object whose name does not start with "_",
                 minus anchor_dir, anchor_command, lookup_tavily,
                 minus dual_control, review_digest, review_manifest_digest when they are empty
policy_version = hex( SHA-256( UTF-8( json.dumps(rules, sort_keys=True, default=str) ) ) )[:16]
```

- Default separators (`", "`, `": "`) and `ensure_ascii=True`. A third serializer.
- Truncated to 16 hex characters (64 bits).
- Covers the action rules and also reviewer settings: `model`, `ollama_url`, `review_timeout_s`,
  `review_think`, and once pinned, the reviewer's weight and manifest digests.
- Does not cover the anchor settings or the lookup switch. Changing them does not change the version.
  The policy receipt's file hash still moves.
- Does not cover live state: the hourly action count and the 24-hour autonomous spend.
- Types matter. `Policy.load` turns TOML numbers into floats (`300.0`), while a `Policy` built in code
  keeps integer defaults (`300`). The same rules therefore have two versions depending on where they
  came from. See the vector "the same rules loaded from a file".

The file's own hash (`policy_sha256`, SHA-256 of the exact bytes parsed, comments included) is
recorded next to the version on every gate record. It is `null` for a policy built in code.

## 5. Record types

### 5.1 Common meta on every gate record

| Key | Type | Value |
|---|---|---|
| `request_id` | string | 10 hex characters, `uuid4().hex[:10]` |
| `payload_sha256` | string | Section 4.2 |
| `policy_version` | string | Section 4.3 |
| `policy_sha256` | string or null | Section 4.3 |
| `hg_mac` | object | Section 6.2. Present only when the gate has a ledger key. |

### 5.2 Gate records

| `action` | `phase` | `summary` | Extra meta |
|---|---|---|---|
| `gate.request` | pre | `request email -> <to>` or `request tx <value_eth> ETH -> <to>` | `to`; `read_sources`: list of strings, the `source` of each item the agent says it read (`"?"` if missing) |
| `gate.review` | pre | `llm:approve`, `llm:block` or `llm:invalid` | `model`, `verdict`, `secs` (float); `digest`, `manifest_digest`, `prompt_version`, `prompt_sha256` (always present, `null` when unknown, for example `--no-model`); from a pinned reviewer also `think`, `pinned_digest`, `pin_state` (`ok`, `unpinned`, `mismatch`, `unreadable`, `unreachable`, `absent`), and `pin_override: true` when run with `--allow-unpinned-reviewer` |
| `gate.lookup` | pre | `web lookup <kind> <target>: <n> results` or `...: unavailable` | `lookup_kind` (`domain` or `wallet`), `lookup_target`, `lookup_ok`, `lookup_results` (a count), `lookup_error` when not ok |
| `gate.decision` by policy | pre | `policy:<approve or deny> <reason>` | `decided_by: "policy"`, `decision`; `dual_control: {"required": true, "satisfied": false}` when denied for lack of a second approver |
| `gate.decision` by a human | pre | `human:<decision>`, plus ` (overrode flag)` and ` (dual control: ...)` when they apply | `decided_by: "human:<channel>"`, `decision` (`approve`, `deny`, `expired`), `channel`, `latency_s`, `overrode_flag`, `approver`, `full_view: {"required", "viewed"}`, and `dual_control: {"required", "satisfied", "second_approver"}` when dual control applies |
| `gate.executed` | post | `executed` or `executed (dry run)` | `result` (below) |
| `gate.failed` | post | `approved but failed: <ExceptionType>` | `error`: the first 300 characters of the exception text |
| `gate.denied` | post | `not executed` | `reason` |
| `gate.expired` | post | `not executed` | `reason` |

`approver` is what the OS reports for the approving process: `{"channel", "os_user", "uid", "host",
"tty"}`. It names an account, not a verified person. When nobody answered (a scheduled pass held the
item), it is `{"channel": "held", "identified": false}`, `decided_by` is `"human:held"` and `decision` is
`"expired"`. `second_approver` is the registered name of the second person, written only when their
passphrase matched; the passphrase is never written.

`result` as the adapters return it:

- email, dry run: `{"delivered": false, "dry_run": "<absolute path of the .eml file>"}`;
- email, live SMTP: `{"delivered": true, "via": "smtp <host>"}`;
- wallet: `{"unsigned_tx": {"chainId", "to", "value" (hex wei), "data"}, "signed": false, "note": "..."}`.

`gate.executed` means the adapter returned without raising. For a wallet action it means a transaction
was prepared, unsigned. It does not prove an effect in the world.

### 5.3 Phases and ordering

The gate's guarantee: **for every request, the decision record is appended and fsynced before the
action starts.** `Gate._submit` calls the adapter only after the `gate.decision` append returned. If any
append raises (for example the lock times out), the exception propagates and nothing after it runs.
The gate fails closed and does not write a drops record.

The paths `Gate._submit` can take, in `seq` order for one `request_id`:

| Path | Records |
|---|---|
| identical retry of a refused action | `gate.request`, `gate.decision` (policy, deny), `gate.denied` |
| hard policy rule (cap, chain, calldata size, hourly limit, type, no recipient) | `gate.request`, `gate.decision` (policy, deny), `gate.denied` |
| send to self | `gate.request`, `gate.decision` (policy, approve), then `gate.executed` or `gate.failed` |
| allowlisted, model approves, within limits | `gate.request`, `gate.review`, `gate.decision` (policy, approve), then `gate.executed` or `gate.failed` |
| dual control on, no second approver registered | `gate.request`, `gate.review`, `gate.decision` (policy, deny), `gate.denied` |
| human decides | `gate.request`, `gate.review`, optional `gate.lookup`, `gate.decision` (human), then `gate.executed` or `gate.failed` (approve), `gate.denied` (deny), `gate.expired` (expired) |

A request whose reviewer or approver raised has a `gate.request` (and maybe a `gate.review`) and
nothing else. Nothing ran.

The daemon serves requests on parallel threads, so groups of different requests can interleave in the
file. Ordering is defined per `request_id`. Rules a verifier can check:

- **O1** The first record of a `request_id` is `gate.request`.
- **O2** `gate.executed`, `gate.failed`, `gate.denied` and `gate.expired` have phase `post_execution`;
  every other gate record has `pre_execution`. Nothing for a `request_id` follows its post record.
- **O3** A `request_id` has at most one `gate.decision` and at most one post record.
- **O4** A post record has a `gate.decision` for the same `request_id` at a lower `seq`.
- **O5** `gate.executed` and `gate.failed` follow `decision: "approve"`; `gate.expired` follows
  `"expired"`; `gate.denied` follows `"deny"` or `"expired"`.
- **O6** All records of a `request_id` share `payload_sha256` and `policy_version`.

A decision with no post record means the outcome is unknown (the process may have died after the
action). It is not a violation.

**Only `tools/receipts_vectors.py verify` checks O1 to O6.** `homestead-gate watch`, `hsm watch` and
`ledger.verify_chain` do not check them.

### 5.4 Policy records

Written with `target: "gate:policy"`, **no `phase` key**, and no `request_id`.

| `action` | When | Meta |
|---|---|---|
| `policy.loaded` | the first time a Gate serves (`up` at start, an assistant run or scheduled pass with its first request), when nothing differs from the last policy record | `policy_path`, `policy_sha256`, `policy_version`, `approvers_sha256` (SHA-256 of `approvers.json`, or null), `dual_control` |
| `policy.changed` | instead of `policy.loaded`, when any of those five differ from the last `policy.loaded` or `policy.changed` in the ledger; also mid-session if the in-memory rules change | the five keys above, plus `changed` (list of keys) and `previous` (the old values) |
| `policy.edited` | at the next request after the policy file's bytes on disk change under a running gate (once per new file hash). The running gate keeps the rules it loaded. | `policy_path`, `on_disk_sha256`, `in_force_sha256`, `policy_version` |

### 5.5 Egress records

`homestead-gate run` writes `egress.denied` when the sandbox blocks a connection:
`target: "egress"`, `phase: "pre_execution"`, `summary: "blocked <host>: <why>"`, `meta: {"host", "reason"}`.
They differ from gate records: no `request_id` or fingerprint, **no MAC**, and `session` is not the
gate session (it is `HSM_SESSION` if set, else a random per-process value). At most one record per host
per 60 seconds; repeats inside that window are not recorded.

## 6. Keys and record MACs

### 6.1 Keys

One 32-byte master secret lives in the OS credential store (macOS Keychain via `security`, or Secret
Service via `secret-tool`), service `homestead-gate-ledger-key`, account `receipts`, stored as 64 hex
characters. It is generated on first use. Both working keys derive from it:

```
mac_key     = HMAC-SHA256(master, "homestead-gate record mac v1")
ed25519_seed = HMAC-SHA256(master, "homestead-gate checkpoint ed25519 v1")     # Ed25519 private seed
```

Verification on another machine loads the key only if it is already there; it never creates one.
With no credential store, the gate writes records without MACs and checkpoints unsigned, with a
warning. Without the `cryptography` package, MACs still work and checkpoints are unsigned.

### 6.2 Record MAC (`meta.hg_mac`)

```
hg_mac = {"v": 1, "n": <counter>, "alg": "hmac-sha256", "mac": <hex>}
mac    = hex( HMAC-SHA256( mac_key, C_rec({
            "v": 1, "n": n, "agent": agent, "session": session, "action": action,
            "target": target, "summary": summary, "phase": phase_or_null,
            "meta": meta without "hg_mac" }) ) )
```

- `n` counts MAC'd records per (ledger, session), starting at 0. A Gate resuming a session continues
  from the highest `n` already in the file for that session.
- The lock around counter and append makes file order match counter order within a process.
- `phase` is `null` in the MAC input for policy records (the record itself has no `phase` key).
- The MAC does **not** cover `seq`, `ts`, `prev_hash` or `v`, because homestead-memory assigns those
  inside its own lock after the MAC is computed.

Every record the gate writes through `Gate._log` carries a MAC when the Gate has a key: all `gate.*`
and `policy.*` records. `egress.denied` and demo records do not.

## 7. Checkpoints and anchoring

### 7.1 Checkpoint format

A checkpoint is a JSON object:

| Key | Value |
|---|---|
| `hg_checkpoint` | `1` |
| `head_hash`, `records` | the last record's `hash`, and the number of intact records |
| `ts` | system clock, Section 3.1 format |
| `ledger` | absolute path of the ledger dir |
| `ledger_id` | the first record's `hash` |
| `policy_version`, `reviewer_model` | of the gate that sealed it (either may be null) |
| `reason` | `session-end`, `scheduled-pass`, `pending` or `watch` |
| `ledger_version` | `1` |
| `signed` | `true`, or `false` with `signer_pubkey` and `signature` null |
| `alg`, `sig_version` | `"ed25519"`, `1` (signed only) |
| `signer_pubkey` | 64 hex, raw Ed25519 public key |
| `signature` | 128 hex: Ed25519 over the ASCII bytes `"<head_hash>:<records>"`. Identical to what `hsm checkpoint` signs, so `hsm watch` and `hsm checkpoint --verify` accept it. |
| `gate_signature` | 128 hex: Ed25519 over `JCS(checkpoint without gate_signature and attestation)` (RFC 8785, `homestead_memory.core.jcs`). Covers `ts`, `ledger`, `policy_version`, `reviewer_model` and `reason`, which `signature` does not. |
| `attestation` | `"hsm-checkpoint v1 head=<h> records=<n> ts=<ts> pubkey=<pk> sig=<signature>"`, the line `hsm checkpoint --export` prints |

`checkpoints.jsonl` stores each as `json.dumps(cp, sort_keys=True)` (default separators). A signed one
also replaces `.hsm/ledger.sig`. Anchor files hold `json.dumps(cp, sort_keys=True, indent=1) + "\n"`.

### 7.2 When the gate seals

`receipts.seal` runs at the end of an `up` session and an assistant session, after every scheduled
pass, after `assistant --pending`, and on `homestead-gate watch` when every check passed (not with
`--no-checkpoint`). It does not seal after each decision. Records after the last checkpoint are not
covered until the next one.

### 7.3 Seal refuses to launder a rebuild

Under the ledger lock, seal reads the records and verifies the chain once, then refuses (writes
nothing, reports why, and `watch` exits 1) if any of these hold:

1. the chain has a break;
2. with a key: any MAC fails, any session counter has a gap, or a `gate.*` record lacks a MAC after
   MACs began;
3. the chain does not extend an earlier checkpoint it can see: `checkpoints.jsonl`, `.hsm/ledger.sig`,
   anchors for this ledger in `anchor_dir`, and the **stored head**;
4. an earlier signed checkpoint's signatures do not verify.

"Extends" means: the ledger has at least `records` records and record `records - 1` has hash
`head_hash`. If the newest earlier checkpoint already names the current head and count, seal writes
nothing (`unchanged`).

The stored head is `"<records>:<head_hash>"` in the credential store, service
`homestead-gate-ledger-head`, account `hex(SHA-256(absolute ledger path))[:16]`, updated after each
written checkpoint. Someone with only the files cannot change it.

### 7.4 Anchors

Set in the policy's `[receipts]` table:

- `anchor_dir`: one new file per checkpoint, created with `O_EXCL` and never rewritten. An existing
  file with the same name counts as anchored.
- `anchor_command`: run with `/bin/sh -c`, checkpoint JSON on stdin, `$HG_CHECKPOINT` (a temp file with
  the same JSON) and `$HG_CHECKPOINT_NAME`, 60 second timeout. A non-zero exit is a warning; the
  checkpoint stays written.

A failed anchor never blocks a checkpoint. An anchor is worth only what an attacker on this machine
cannot change: a protected remote, an email to yourself, a removed USB stick. A folder on the same disk
is not an anchor.

**RFC 3161 time.** There is no built-in timestamp client. The README shows an `anchor_command` that
uses `openssl ts` and `curl` to get a timestamp reply from a public TSA for each checkpoint file.
Checking it is `openssl ts -verify`, outside the gate. **Not implemented**: storing, checking or
reporting TSA replies in `watch`.

## 8. Verification algorithm

Input: the ledger file; optionally the ledger key, earlier checkpoints, anchor files, an expected
signer public key, and published actions. A verifier MUST report every problem, not stop at the first.

1. **Chain.** Set `expected_prev` to 64 zeros and `expected_seq` to 0. For each line (index `i`
   counts every line):
   1. skip blank lines;
   2. if it is not JSON, report `torn` and continue without changing the expectations;
   3. if `hash` differs from Section 3.2, report `hash_mismatch`;
   4. if `prev_hash` differs from `expected_prev`, report `bad_genesis` when `i` is 0, else `prev_mismatch`;
   5. if `seq` differs from `expected_seq`, report `seq_gap`;
   6. set `expected_prev` to the stored `hash` (if present) and `expected_seq` to `seq + 1` (or
      `expected_seq + 1` if `seq` is not an integer).

   Advancing with the stored hash means one edited record gives one `hash_mismatch`, not a break at
   every later record. This is `ledger.verify_chain`.
2. **MACs (L2, needs the key).** Walk the intact records in order with `began = false` and an empty
   map of expected counters:
   1. no `meta.hg_mac`: before `began`, count as pre-MAC and continue; after, report a stripped MAC if
      `agent` is `homestead-gate` and `action` starts with `gate.`;
   2. set `began = true`; recompute the MAC (Section 6.2) with the record's `n`; compare in constant
      time; report a bad MAC on mismatch;
   3. for a good MAC: if `n` differs from the session's expected counter (0 at first), report a gap
      ("records removed" if larger, "reordered or duplicated" if smaller); set the expected counter
      to `max(n + 1, expected)`.

   This is `receipts.verify_macs`.
3. **Checkpoints (L3).** For each checkpoint, local or anchored:
   1. if a signer is pinned, a signed checkpoint's `signer_pubkey` MUST equal it (an empty pin fails).
      An honestly unsigned checkpoint (`signed: false`) is not held to the pin: the code checks only
      that the ledger extends it. A verifier SHOULD reject unsigned checkpoints when a signer is
      pinned; **not implemented** in `verify_anchors`;
   2. verify `signature` over `"<head_hash>:<records>"`; if `gate_signature` is present, verify it over
      the JCS body;
   3. check that the ledger extends it (Section 7.3).

   A ledger copy with no checkpoint at all is "rebuild not excluded", never a pass. Anchors that exist
   but none of which name this ledger (by `ledger` path or `ledger_id`) are a failure: a chain rebuilt
   from its first record looks exactly like that. Sort anchored checkpoints by `records` and report the
   last one the ledger matches and the first one it does not; the rewrite lies between them.
4. **Stored head (on the owning machine).** The ledger MUST extend the stored head (Section 7.3).
5. **Ordering.** Check O1 to O6 (Section 5.3).
6. **Payloads (optional).** Given the action for a `request_id` from elsewhere, recompute
   `payload_sha256` (Section 4.2) and compare.

The ledger passes only if steps 1 to 5 report nothing. Records after the newest checkpoint the
verifier trusts SHOULD be reported as not protected against truncation.

Which tool does which step today:

| Step | `hsm watch` | `homestead-gate watch` | `tools/receipts_vectors.py verify` |
|---|---|---|---|
| 1 chain | yes | yes (runs `hsm watch`) | yes |
| 2 MACs | no | yes, on a machine with the key | yes, with the vector test key |
| 3 checkpoints | `.hsm/ledger.sig` only, `head:records` signature only | `ledger.sig` via hsm, and every anchor in `--anchors` and the policy's `anchor_dir`, both signatures, `--signer` pin | yes, both signatures, pinned signer |
| 4 stored head | no | yes | no |
| 5 ordering | no | no | yes |
| 6 payloads | no | no | yes, for the published vector actions |

An auditor's command on a copy: `homestead-gate watch --ledger COPY --anchors DIR --signer PUBKEY
--no-checkpoint`. `--no-checkpoint` keeps it read-only and creates no key.

## 9. Threat model

The ledger rows are asserted by tests in `tests/test_receipts_spec.py` (vectors) and `tests/test_receipts.py`
(live gates, including the stored-head refusal). The last four rows restate the README and are not tested here.

| Attack | Caught? | By what |
|---|---|---|
| edit one record, leave its hash | yes | chain: one `hash_mismatch` at that record |
| edit records and recompute the whole chain, no key | yes | MAC fails on the edited record |
| rebuild with every MAC stripped | yes, if a checkpoint is visible | the stored head (owner's machine) or an anchor: stripping changes record 0, so anchors no longer recognise the ledger, or the anchored head is not a prefix |
| strip MACs from some `gate.*` records after MACs began | yes | stripped-MAC check |
| delete a record from the middle of a session, rebuild | yes | MAC counter gap |
| strip the MACs from every record of the first sessions, rebuild | **no**, unless a checkpoint covered them | they read as history written before MACs began (`unkeyed_before`); later sessions' counters still start at 0 |
| plant an unsigned anchor file that matches a rebuilt chain, with `--signer` set | **no** | the pin is checked only on signed checkpoints |
| reorder records within one session, rebuild | yes | MAC counter gap, and ordering rule O4 when a post record moves above its decision |
| delete the newest records (tail truncation) | only if a checkpoint covered them | anchors, local checkpoints or the stored head. Chain and MACs both pass. |
| reorder records of different sessions, rebuild | **no**, unless an anchor covered them | MACs bind neither `seq` nor `prev_hash`, and each session's counter stays in order |
| insert a forged MAC-less `policy.*` record after MACs began, rebuild | **no**, unless an anchor covered the span | `verify_macs` flags missing MACs on `gate.*` records only |
| insert a forged `egress.denied` record, rebuild | **no**, unless anchored | egress records never carry a MAC |
| delete local checkpoint files and rebuild | yes on the owner's machine | stored head in the credential store; anchors elsewhere |
| someone running code as you rewrites unanchored history | **no** | they can read the key and the stored head. Only off-machine anchors bound the damage. |
| a verifier without the key | MACs **not checked** | HMAC is symmetric. `watch` says so. Checkpoint signatures are public-key and still check. |
| a changed key (keychain entry lost) | noted, not failed | `watch` notes the new signer; `--signer` turns it into a failure |
| wrong time | **no** without a TSA | `ts` is the system clock. Order is still provable from `seq`, the chain and MAC counters. |

What a valid ledger never proves: what the human asked for (the task is not recorded), that the
reviewer was right, that the agent reported everything it read (`read_sources` is the agent's claim),
that an executed action had an effect, or who sat at the keyboard (`approver` names an OS account).

## 10. Privacy

Never written to a receipt:

- email bodies, subjects and attachments (only fingerprints cover them);
- the reviewer's free-text reason and suspicious span (they can quote the body);
- the untrusted content the agent read (only its `source` labels);
- web lookup titles, URLs and snippets (only kind, target, ok and a count);
- a second approver's passphrase, or a typed name that did not match;
- the human's task text.

Written, and so visible to anyone with the ledger: recipients (`to`, `lookup_target`, wallet
addresses in summaries and `unsigned_tx`), the calldata of an executed wallet transaction
(`gate.executed.result.unsigned_tx.data`, at most `max_calldata_bytes`), the agent-reported `read_sources` strings (agent-controlled,
not length-limited), the approver's OS user, uid, host and tty, the dry-run `.eml` path, policy file
path, and up to 300 characters of an adapter exception. The `.eml` file in the outbox does hold the
body; it is not part of the ledger.

## 11. Versioning and extension

- `v` (record), `hg_mac.v`, `hg_checkpoint` and `sig_version` are each `1`. A change to any hashed or
  MAC'd preimage MUST bump the matching version, and verifiers MUST keep accepting the old one.
- Optional keys enter preimages only when present or set (`phase`, the rules in Section 4.3), so older
  ledgers and policies keep their hashes. New optional keys MUST follow the same rule.
- New `meta` keys MAY be added to any record. Verifiers MUST ignore keys they do not know; the hash and
  MAC cover them anyway.
- New action types SHOULD get a fixed typed field list in `TYPED_FIELDS` rather than hashing every
  key. Adding a type's list changes its fingerprints, so it is a version change for that type.
- New record types MUST use a dotted prefix (`gate.`, `policy.`, `egress.`). A new `gate.*` post type
  needs O2 and O5 updated here.
- **Not implemented**: a version negotiation or registry; v0.1 is defined by this document and the
  vectors only.

## 12. Conformance levels

**L1, hash chain.** A writer MUST write the envelope (3.1) with the hash (3.2), serialize appends so
two writers cannot read the same head, fsync each record before returning, write and fsync the
`pre_execution` decision before the action starts and not start it if that write fails, include the
Section 5.1 keys in every record of a request, compute `payload_sha256` as in 4.2, and follow the
privacy rules (10). A verifier MUST run step 1 of Section 8 and SHOULD run step 5.

**L2, L1 plus record MACs.** A writer MUST add `hg_mac` (6.2) to every gate and policy record when it
has a key, and SHOULD warn when it has none. A verifier holding the key MUST run step 2 and MUST say
"not checked" rather than pass when it has no key.

**L3, L2 plus signed, anchored checkpoints.** A writer MUST write signed checkpoints (7.1) at least at
the end of every session, MUST refuse to sign as in 7.3, and MUST anchor each checkpoint somewhere the
writer's machine cannot rewrite. A verifier MUST run step 3 against the anchors, SHOULD pin the signer,
and MUST treat "no anchors for this ledger" as a failure.

homestead-gate meets L3 when a credential store and `cryptography` are present and `[receipts]` names
an off-machine anchor; L2 with a credential store and no anchor; L1 otherwise (and in the demo). It
does not itself check O1 to O6 (Section 8).

## 13. Test vectors

`docs/receipts-vectors/` is generated by `python tools/receipts_vectors.py generate` and checked by
`python tools/receipts_vectors.py verify` (exit 0 on success). `tests/test_receipts_spec.py`
regenerates them and compares bytes, runs the independent verifier, runs the gate's own checks on the
same bytes, and checks that the meta keys of each record type match a live Gate run through the same
six requests.

| File | Contents |
|---|---|
| `vectors.json` | the **public test key** (`master` = bytes 0x00..0x1f; never use it), derived `mac_key_hex` and `signer_pubkey`, the policy TOML, and the six published actions by `request_id` |
| `ledger.jsonl` | 23 records, session `vectors`: `policy.loaded`, then requests `a000000001` (send to self, auto), `a000000002` (allowlisted, model approves), `a000000003` (hijacked transfer: model blocks, web lookup, human denies), `a000000004` (model flags, human overrides), `a000000005` (wrong chain, policy deny), `a000000006` (identical retry of 3, refused by fingerprint) |
| `checkpoints.jsonl`, `anchors/` | two signed checkpoints, at 13 and 23 records, with `ledger` set to `/vectors/ledger` |
| `fingerprints.json` | typed-action cases with the exact preimage: extra keys ignored, missing `data` as null, `1` vs `1.0`, non-ASCII escaping, an unknown type |
| `policy_versions.json` | rule sets and versions, including the code-built vs file-loaded difference |

Key values:

- `mac_key` = `e3f9d1427e44d45b995a540824f9d865993c386bb0c04338a22f05b7fda93b37`
- `signer_pubkey` = `98b108bfe5783ab421ae5bdde1f294e5050fecaecc932b2d43d30a194541fc45`
- `Policy(user_email="me@example.com").version` = `4088984b870d45c8`; the same rules from a file = `cbd82fd891fb95e5`

Record `seq` 2 of `ledger.jsonl`, as stored:

```json
{"action":"gate.decision","agent":"homestead-gate","hash":"4fd34308fd05d4a9be7caa30bc20b9f8584775576b92bc429803d28fadb86bd7","meta":{"decided_by":"policy","decision":"approve","hg_mac":{"alg":"hmac-sha256","mac":"c2d4e77e38252676fef6ed8168fca63f8f0ef9e7a870a02f2cf42bc3a84375f2","n":2,"v":1},"payload_sha256":"fe261df033a795f9dd074c986f5a75f55edc597502f2cd62cd2f4913eb57edc7","policy_sha256":"095ed9837156e37ea47c67a2f3f9c5932d8aa4f314871b9dec552348b690eaca","policy_version":"96f2ed88c81208ab","request_id":"a000000001"},"phase":"pre_execution","prev_hash":"413e5bfa2029749cd571edc365d5c659fda6f669f4530dccb67bedaa943ab3d6","seq":2,"session":"vectors","summary":"policy:approve send to self","target":"gate:email","ts":"2026-10-05T12:00:05+00:00","v":1}
```

Its MAC preimage (HMAC-SHA256 with `mac_key` gives the `mac` above):

```json
{"action":"gate.decision","agent":"homestead-gate","meta":{"decided_by":"policy","decision":"approve","payload_sha256":"fe261df033a795f9dd074c986f5a75f55edc597502f2cd62cd2f4913eb57edc7","policy_sha256":"095ed9837156e37ea47c67a2f3f9c5932d8aa4f314871b9dec552348b690eaca","policy_version":"96f2ed88c81208ab","request_id":"a000000001"},"n":2,"phase":"pre_execution","session":"vectors","summary":"policy:approve send to self","target":"gate:email","v":1}
```

A fingerprint preimage (`wallet_tx`, `data` missing):

```
{"action":{"chain_id":11155111,"data":null,"to":"0x0000000000000000000000000000000000000000","type":"wallet_tx","value_eth":0.01},"policy_version":"96f2ed88c81208ab"}
-> 638bbab9e7808eac19bc6c162bc6e5a44f5e0bc2e80f976717c3c7b68992fecb
```

The vector clock advances one second on every timestamp the writer asks for, including the lock
file's, so record times skip.

## 14. Mapping to the IETF Agent Audit Trail draft

The Agent Audit Trail (AAT) is an individual Internet-Draft by Raza Sharif, not adopted by a working
group: https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/ . homestead-memory 0.5.2 cites
revision **-01** (2026-08-19). The latest revision on the datatracker is **-06** (2026-09-29). This
section was checked against -01 only.

homestead-memory has an export, not a native format: `hsm export <ledger> --format aat`
(`homestead_memory/adapters/aat.py`). Per native record:

| AAT field | Value |
|---|---|
| `record_id` | UUID v5 (URL namespace) of `"hsm-record-<native hash>"`, so the same ledger always exports the same ids |
| `timestamp` | native `ts` |
| `agent_id` | `urn:hsm:agent:<agent>` |
| `agent_version` | the homestead-memory version, not the gate's |
| `session_id` | native `session` as is (for example `vectors`), not a UUID |
| `action_type` | `"decision"` for every gate, policy and egress record |
| `action_detail` | `{"tool": target, "target": summary, "meta": meta}` |
| `outcome` | `gate.decision` pre-phase with `decision: "deny"`: `denied`; other decisions: `success`; `gate.denied` and `gate.failed`: `failure`; `gate.expired`: `timeout`; otherwise `success` |
| `trust_level` | `"L1"` |
| `parent_record_id` | the previous exported record's `record_id`, or null |
| `prev_hash` | SHA-256 of RFC 8785 JCS of the previous exported record without `signature`, or null |
| `record_phase` | native `phase`; records without one (policy records) become `post_execution` |

Consequences: the AAT chain is a separate chain. The native `hash` is not carried, so an AAT record
cannot be matched to a native checkpoint by hash (only through `record_id`, which is derived from it).
The export is unsigned: `sign_p1363` (ECDSA P-256, IEEE P1363 `r||s`, base64url) exists but nothing calls
it. -01 asks for UUID v4 `record_id` and `session_id`; the export uses neither. Human approvals export
as `success`, `egress.denied` (a blocked connection) exports as `success`, and nothing exports as
`escalated`.

## 15. Not implemented

- Ordering rules O1 to O6 in `watch` or `hsm watch` (only the vector tool checks them).
- MACs that cover `seq`, `ts` and `prev_hash` (proposed: compute the MAC inside `ledger.append`).
- MACs on `egress.denied` records, and stripped-MAC detection for `policy.*` records.
- Detection of a MAC-less prefix after the key existed (a MAC-less start reads as pre-MAC history).
- The signer pin on unsigned checkpoints.
- A checkpoint after every decision; today the gate seals at session ends, passes and `watch`.
- A built-in RFC 3161 client, or checking TSA replies in `watch`.
- Recording a hash of the human's task in `gate.request`.
- A single canonical form: three serializers are in use (record hash and MAC, fingerprint, policy
  version) plus JCS for `gate_signature`. None of the first three is RFC 8785.
- Normalizing number types before hashing (`1` vs `1.0` in actions; int vs float defaults in policies).
- A signed AAT export, UUID v4 ids, or a mapping to AAT revisions after -01.
- Per-record signatures. Records are authenticated by a symmetric MAC only.

The earlier draft of this document is kept at `docs/archive/receipts-spec-draft-2026-09-30.md`.
