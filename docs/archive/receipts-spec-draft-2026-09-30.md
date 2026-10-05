> Superseded on 2026-10-05 by `docs/receipts-spec.md` (Agent Action Receipts v0.1). Kept for history. It describes the gate before record MACs, signed checkpoints and anchors, and parts of it are no longer true.

# Agent Action Receipts v0.1 (draft)

Status: draft for discussion. Not a standard. Part of fuckbigtech.ai.

This document describes the receipt format that homestead-gate writes today. The code is the
ground truth. Where this text and the code disagree, the code wins and this text has a bug.
Anything not confirmed in code is marked UNVERIFIED.

Sources read for this draft:

- `homestead-gate/src/homestead_gate/core.py` (`Gate.submit`, `TYPED_FIELDS`, `typed_action`, `payload_hash`)
- `homestead-gate/src/homestead_gate/policy.py` (`Policy.version`)
- `homestead-gate/src/homestead_gate/cli.py` (`demo`, `run` egress receipts, `watch`)
- `homestead_memory/core/ledger.py` 0.5.0 (`append`, `record_hash`, `verify_chain`, `checkpoint`, attestations)
- `homestead_memory/adapters/aat.py` and `homestead_memory/core/jcs.py`
- `homestead_memory/cli.py` (`hsm watch`, `hsm checkpoint`, `hsm export --format aat`)

The installed `homestead_memory/core/ledger.py` is identical to the local checkout in
`~/Projects/homestead-memory`.

## 1. Purpose and threat model

A receipt is one line in an append-only, hash-chained JSON Lines file. The gate writes receipts
for every outbound action an agent asks it to perform. The goal is that another tool can emit
the same records, and anyone can verify them without trusting the tool that wrote them.

### What a valid chain proves

- No record was edited in place since it was written. An edit changes the record's hash.
- No record was removed, inserted or reordered before the last record. Each record carries the
  previous record's hash and a sequence number.
- For each request, the gate wrote its decision to disk (fsynced) before the action ran.
  This is an ordering property of the writer. Section 4 says how a verifier can check it.
  No existing verifier checks it today.

### What a valid chain does NOT prove

- **That the chain was not rebuilt.** Anyone who can write the file can recompute every hash
  and produce a new, internally valid chain. Only a checkpoint signed with a key the rewriter
  does not hold, or a head hash published outside the machine, detects this (Section 5.3).
- **That the tail is complete.** Removing the last N records leaves a valid chain.
  Verified on a copy of the demo ledger: after deleting the last 2 of 19 records,
  `hsm watch` exits 0 and reports no break. Only records covered by a checkpoint are
  protected against truncation.
- **Who wrote a record.** `agent`, `session` and `ts` are values the writer asserts about
  itself. Records are not signed one by one.
- **What the action contained.** Receipts store a fingerprint (`payload_sha256`), not the
  email body or transaction fields. To check that a given payload was the one approved,
  the verifier needs the payload from somewhere else.
- **What the human asked for.** The task the human gave the gate is not recorded in any receipt.
- **That the reviewer was right,** or that the agent reported everything it read.
  `read_sources` lists only what the agent chose to report.
- **That an "executed" action had an effect in the world.** In v0.1, email is written to a
  local outbox unless `--live` is set, and a wallet transaction is only prepared, unsigned.
  `gate.executed` means the adapter returned without raising.
- **That approved actions finished.** A crash after the decision and before the post record
  leaves a decision with no outcome. The record never shows an outcome with no decision.

## 2. Record schema

### 2.1 File layout

- The ledger is `<ledger_dir>/.hsm/ledger.jsonl`. The gate's default `ledger_dir` is
  `~/.homestead-gate/ledger`.
- One JSON object per line, terminated by `\n`.
- The file is created with mode `0600`.
- Each append takes an advisory lock (`store.vault_lock`), reads the last intact record,
  writes one line with `O_APPEND`, and calls `fsync` on the file. The containing directory
  is not fsynced on first creation.
- Each line is written as `json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`.

### 2.2 Envelope fields (written by `ledger.append`)

| Field | Type | Value as written |
|---|---|---|
| `v` | integer | `1` (`LEDGER_VERSION`). Not checked by `verify_chain`. |
| `seq` | integer | `0` for the first record, else previous record's `seq + 1`. |
| `ts` | string | UTC time, ISO 8601, seconds precision, for example `2026-09-30T23:48:55+00:00`. |
| `agent` | string | Writer identity. The gate always passes `"homestead-gate"`. Sanitized by `provenance._sanitize`. |
| `session` | string | Gate session: 8 hex characters from `secrets.token_hex(4)` per `up`, or `"demo"` in the demo. |
| `action` | string | Event name. See 2.4. |
| `target` | string or null | For gate events: `"gate:<action.type>"`, for example `"gate:email"`. `"gate:?"` if no type. |
| `summary` | string or null | Short human line. See 2.4. |
| `meta` | object | Event data. See 2.3 and 2.4. `{}` if none. |
| `prev_hash` | string | 64 lowercase hex. Previous record's `hash`, or 64 zeros for the first record. |
| `phase` | string | `"pre_execution"` or `"post_execution"`. Omitted entirely if the writer passes no phase. The gate always passes one. |
| `hash` | string | 64 lowercase hex. See Section 5.1. |

### 2.3 Common `meta` fields on every gate record

| Field | Type | Meaning |
|---|---|---|
| `request_id` | string | 10 hex characters, `uuid4().hex[:10]`. Groups the records of one request. |
| `payload_sha256` | string | Typed action fingerprint, 64 hex. See Section 3. |
| `policy_version` | string | 16 hex characters. See Section 3.3. |

### 2.4 Event types

| `action` | `phase` | `summary` | Extra `meta` fields |
|---|---|---|---|
| `gate.request` | pre | `request email -> <to>` or `request tx <value_eth> ETH -> <to>` | `to`, `read_sources` (list of strings, the `source` of each item the agent says it read; `"?"` if missing) |
| `gate.review` | pre | `llm:<verdict>` | `model` (string), `verdict` (`approve`, `block` or `invalid`), `secs` (float) |
| `gate.decision` (policy) | pre | `policy:<decision> <reason>` | `decided_by: "policy"`, `decision` (`deny` or `approve`) |
| `gate.decision` (human) | pre | `human:<decision>`, plus ` (overrode flag)` when true | `decided_by: "human:<channel>"`, `decision` (`approve`, `deny` or `expired`), `channel`, `latency_s` (float), `overrode_flag` (bool) |
| `gate.executed` | post | `executed` or `executed (dry run)` | `result` (see below) |
| `gate.denied` | post | `not executed` | `reason` (string) |
| `gate.expired` | post | `not executed` | `reason` (string) |
| `gate.failed` | post | `approved but failed: <ExceptionType>` | `error` (string, first 300 characters of the exception text) |
| `egress.denied` | pre | `blocked <host>: <why>` | `host`, `reason`. No `request_id`, `payload_sha256` or `policy_version`. See 2.6. |

`result` in `gate.executed`, as the adapters return it:

- Email, dry run: `{"delivered": false, "dry_run": "<absolute path of the .eml file>"}`.
- Email, live SMTP: `{"delivered": true, "via": "smtp <host>"}`.
- Wallet: `{"unsigned_tx": {"chainId", "to", "value" (hex wei), "data"}, "signed": false, "note": "..."}`.

The email body and subject are never written to a receipt. The model's free-text reason is
also kept out, because it can quote the body.

### 2.5 Example record

This is seq 5 of a real demo run (`homestead-gate demo --no-model --auto-deny`, run with a
temporary `HOME` and `TMPDIR`). The human denied a hijacked wallet transfer. The hash covers
exactly this compact form, minus the `hash` field.

```json
{"action":"gate.decision","agent":"homestead-gate","hash":"f27b95a58f2ee2dba33104ab003526e9544898114fefbac39e5d7fe75d0b9a2b","meta":{"channel":"terminal","decided_by":"human:terminal","decision":"deny","latency_s":0.0,"overrode_flag":false,"payload_sha256":"b54d511b44516a136ef28f17597070944258e41c99443f8b16dca7d9ab02be04","policy_version":"c9d0ded0c03ba308","request_id":"2d5e48df43"},"phase":"pre_execution","prev_hash":"dc8489d6589e92fe47fb1969d482d95da082e72289481c9b2f7f2cf97a70ad15","seq":5,"session":"demo","summary":"human:deny","target":"gate:wallet_tx","ts":"2026-09-30T23:48:55+00:00","v":1}
```

The full group for request `2d5e48df43` in that run:

| seq | phase | action | summary |
|---|---|---|---|
| 3 | pre | `gate.request` | `request tx 0.01 ETH -> 0x0000000000000000000000000000000000000000` |
| 4 | pre | `gate.review` | `llm:block` |
| 5 | pre | `gate.decision` | `human:deny` |
| 6 | post | `gate.denied` | `not executed` |

### 2.6 Egress receipts

`homestead-gate run` writes `egress.denied` when the sandbox blocks a network connection.
These differ from gate receipts:

- `target` is `"egress"`.
- No `request_id`, `payload_sha256` or `policy_version`.
- `session` is not the gate session. It comes from `HSM_SESSION`, or a random per-process value.
- At most one receipt per host per 60 seconds. Repeated attempts inside that window are not recorded.

## 3. Typed action fingerprint and policy version

### 3.1 Typed action

The fields that decide what an action does are fixed in code per type:

| `type` | Fields, in this order |
|---|---|
| `email` | `type`, `to`, `cc`, `bcc`, `subject`, `body`, `attachments` |
| `wallet_tx` | `type`, `chain_id`, `to`, `value_eth`, `data` |
| any other | every key in the action, sorted |

`typed_action(action)` returns `{k: action.get(k) for k in fields}`. A missing field is
included with the value `null`. It is not omitted. Extra keys in the request, such as
`"user_intent"` or `"approved": true`, do not change the fingerprint for the two typed
action types.

The fingerprint is computed before the policy check. A request with an unsupported type is
still fingerprinted over all its keys, and then denied.

### 3.2 Fingerprint

```
payload_sha256 = hex(SHA-256(UTF-8(C({"action": typed_action(action), "policy_version": pv}))))
```

`C` is Python `json.dumps(obj, sort_keys=True, separators=(",", ":"))`. Note:

- `ensure_ascii` is left at its default, `True`. Non-ASCII characters are written as `\uXXXX`.
  This differs from the record hash (Section 5.1).
- Numbers use Python `repr`. `0.01` stays `0.01`. `1e-05` stays `1e-05`. Integer `0` and float
  `0.0` produce different bytes.
- This is not RFC 8785 (JCS).

Test vectors, reproduced from the demo run:

| Action | `policy_version` | `payload_sha256` |
|---|---|---|
| `{"type":"wallet_tx","chain_id":11155111,"to":"0x0000000000000000000000000000000000000000","value_eth":0.01}` | `c9d0ded0c03ba308` | `b54d511b44516a136ef28f17597070944258e41c99443f8b16dca7d9ab02be04` |
| `{"type":"email","to":"me@example.com","subject":"summary","body":"Local LLMs in 2026: memory bandwidth decides speed ..."}` | `c9d0ded0c03ba308` | `4a29ab3480ec53f2e8a935b47109b7386d867e9b0ca31d74ed7d8eb51f4bdfc2` |

The canonical preimage for the first vector is:

```
{"action":{"chain_id":11155111,"data":null,"to":"0x0000000000000000000000000000000000000000","type":"wallet_tx","value_eth":0.01},"policy_version":"c9d0ded0c03ba308"}
```

### 3.3 Policy version

```
policy_version = hex(SHA-256(UTF-8(json.dumps(rules, sort_keys=True, default=str))))[:16]
```

- `rules` is every attribute of the `Policy` object whose name does not start with `_`.
- The serializer uses Python's default separators, `", "` and `": "`, and `ensure_ascii=True`.
  Values that are not JSON types are converted with `str`.
- The result is truncated to 16 hex characters (64 bits).
- The hash covers limits and allowlists, and also non-rule settings: `model`, `ollama_url`,
  `review_timeout_s`, `approval_timeout_s` and `override_delay_s`. Changing the reviewer model
  changes the version.
- It does not cover in-memory state: the hourly action counter and the daily autonomous spend.
  Two decisions with the same version can see different remaining budgets.
- Test vector: `Policy(user_email="me@example.com", user_wallet="0x1111111111111111111111111111111111111111", override_delay_s=60)`
  with all other fields at their defaults gives `c9d0ded0c03ba308`. In the demo, adding two
  addresses to `evm_allow` changed it to `224e07c990b0d350`.

The version is a label on each decision. The gate does not cache or reuse approvals, so there
is no code path where an old approval could be replayed under a new policy.

## 4. Ordering rules

The gate enforces these by the order of calls in `Gate.submit`. Every append is fsynced
before the next step runs. If an append raises (for example, the lock times out), the
exception propagates and nothing after it runs. The gate fails closed. It does not write
to `ledger.drops.jsonl`.

The gate daemon serves requests on parallel threads, so records of different requests can
interleave in the file. Ordering is defined per `request_id`, by `seq`.

For one `request_id`, the valid sequences are:

| Path | Records in seq order |
|---|---|
| Policy deny | `gate.request`, `gate.decision` (policy, deny), `gate.denied` |
| Policy auto-approve (send to self) | `gate.request`, `gate.decision` (policy, approve), then `gate.executed` or `gate.failed` |
| Reviewed, auto-approved (allowlisted, model approved, within limits) | `gate.request`, `gate.review`, `gate.decision` (policy, approve), then `gate.executed` or `gate.failed` |
| Reviewed, human decides | `gate.request`, `gate.review`, `gate.decision` (human), then `gate.executed` or `gate.failed` if approved, `gate.denied` if denied, `gate.expired` if expired |

Rules a verifier can derive from this:

1. Every `post_execution` record for a `request_id` MUST have a `pre_execution`
   `gate.decision` for the same `request_id` at a lower `seq`.
2. A `gate.executed` or `gate.failed` record MUST follow a `gate.decision` with
   `decision: "approve"`.
3. Each `request_id` has at most one `gate.decision` and at most one post record.
4. All records for one `request_id` MUST share `payload_sha256` and `policy_version`.
5. A `gate.decision` with `decision: "approve"` and no post record means the outcome is
   unknown. The action may or may not have run. It is not a chain error.
6. A `gate.request` with no decision means the request was aborted before a decision
   (for example, the reviewer or approver raised). Nothing ran.

`hsm watch` and `verify_chain` do not check rules 1 to 6. They check hashes, `prev_hash`
and `seq` only. A per-request ordering check is not implemented anywhere in the code today.

## 5. Chain verification

### 5.1 Record hash

```
hash = hex(SHA-256(UTF-8(json.dumps(rec_without_hash, sort_keys=True, separators=(",", ":"), ensure_ascii=False))))
```

- `rec_without_hash` is the record with only the `hash` key removed. All other keys,
  including `phase` when present, are covered.
- Non-ASCII characters are written as UTF-8, not escaped.
- Numbers use Python `repr`. This is not RFC 8785. Checked on the demo ledger: 7 of 19
  records hash differently under `homestead_memory.core.jcs` (every record carrying a float
  such as `"secs":0.0` or `"latency_s":0.0`). A verifier MUST reproduce the Python form.

### 5.2 Algorithm

This is what `ledger.verify_chain` does. It reports every break and does not stop at the first.

1. If the file does not exist, return no breaks.
2. Set `expected_prev` to 64 zeros and `expected_seq` to 0.
3. For each line, with `index` counting every line in the file:
   1. Skip the line if it is empty or whitespace.
   2. Parse it as JSON. If that fails, report `torn` and go to the next line.
      `expected_prev` and `expected_seq` do not change.
   3. Recompute the hash (5.1). If it differs from the stored `hash`, report `hash_mismatch`.
   4. If `prev_hash` differs from `expected_prev`, report `bad_genesis` when `index` is 0,
      else `prev_mismatch`.
   5. If `seq` differs from `expected_seq`, report `seq_gap`.
   6. Set `expected_prev` to the record's stored `hash` (if present), and `expected_seq` to
      the record's `seq + 1` (if `seq` is an integer, else `expected_seq + 1`).
4. The chain is valid if no break was reported.

Notes:

- Step 3.6 advances using the stored hash, not the recomputed one. An edit to one record
  without fixing its `hash` produces one `hash_mismatch` at that record, not a break at
  every later record. The demo's tamper test shows exactly one break at index 5.
- `v` is not checked.
- `hsm watch` also reads `.hsm/ledger.drops.jsonl`. Any drop record makes it exit 1.
  The gate never writes drops.
- Removing records from the end is not detected (Section 1).

### 5.3 Checkpoints

`hsm checkpoint <ledger_dir>` signs the current head.

- Key: Ed25519, from `HSM_SIGNING_KEY`, else `~/.config/homestead-memory/ed25519_key`.
  Created if absent.
- Signed message: the ASCII string `"<head_hash>:<records>"`. `records` is the count of
  intact records (`read_all`, which skips torn lines). There is no domain-separation prefix.
- Written to `<ledger_dir>/.hsm/ledger.sig` as JSON with `head_hash`, `records`, `ts`,
  `signer_pubkey` (hex), `signature` (hex), `alg: "ed25519"`, `sig_version: 1`,
  `ledger_version: 1`. `ts` is not covered by the signature.
- `hsm checkpoint --export` prints one line to publish somewhere the attacker cannot reach:
  `hsm-checkpoint v1 head=<hex> records=<n> ts=<ts> pubkey=<hex> sig=<hex>`.

Checkpoint verification (`_check_attestation`), for both the on-disk file and an exported line:

1. If a signer key is pinned (`--signer`), the checkpoint's `signer_pubkey` MUST equal it.
   An empty pin fails.
2. Verify the Ed25519 signature over `"<head_hash>:<records>"`.
3. If the current head hash equals `head_hash`, pass.
4. Else, if the ledger now has more records than `records`, and the stored `hash` of record
   `records - 1` equals `head_hash`, pass as "valid as of N records, M appended since".
5. Else fail. The checkpointed head is not a prefix, so the ledger was rebuilt.

Checkpoint verification alone does not run chain verification. `hsm checkpoint --verify`
runs both and passes only if the signature, the prefix, the chain and the drops file are all
clean. `hsm watch` runs the chain check and reports checkpoint coverage.

A checkpoint signed with a key on the same machine does not stop an attacker who holds that
key. The exported line, stored off the machine, does.

The gate does not create checkpoints on its own. The operator runs `hsm checkpoint` and MUST
pass the gate's ledger directory. Without a path, it signs `$HSM_VAULT`, else the current
directory.

## 6. Mapping to the IETF agent audit trail draft

homestead-memory has an export, not a native mapping: `hsm export <ledger_dir> --format aat`
(`adapters/aat.py`). The code cites `draft-sharif-agent-audit-trail-01` (individual draft,
Raza Sharif, dated 2026-08-19). The draft's text was not read for this document. Every
statement below about what the draft requires is taken from code comments and is UNVERIFIED.

What the export does, per native record:

| AAT field | Value from the code |
|---|---|
| `record_id` | New random `uuid4` on every export. |
| `timestamp` | Native `ts`. |
| `agent_id` | `urn:hsm:agent:<agent>`, for example `urn:hsm:agent:homestead-gate`. |
| `agent_version` | The homestead-memory version (`0.5.0`), not the gate version. |
| `session_id` | Native `session` (for example `"demo"`), not converted to a UUID. |
| `action_type` | `"tool_call"` if native `action` is `"tool_call"`, else `"decision"`. All gate records become `"decision"`. |
| `action_detail` | `{"tool": <target>, "target": <summary>, "meta": <meta>}`. |
| `outcome` | `"failure"` only if `meta.response.error` or `meta.response.is_error` is set, else `"success"`. |
| `trust_level` | `"L1"`. |
| `parent_record_id` | Previous exported record's `record_id`, or `null`. |
| `prev_hash` | SHA-256 over RFC 8785 JCS of the previous exported record (without `signature`), or `null` for the first. |
| `record_phase` | Native `phase`. Records with no phase become `"post_execution"`. |

Consequences for gate receipts:

- `gate.denied`, `gate.expired` and `gate.failed` all export as `outcome: "success"`.
  The gate's `decision` and `reason` survive only inside `action_detail.meta`.
  The code comment says the draft's `denied` outcome MUST be `pre_execution` (UNVERIFIED).
  The gate does write its deny decisions `pre_execution`, but the exporter does not map them.
- The native `hash` and `prev_hash` are dropped. The AAT chain is a new chain. Because
  `record_id` is random and feeds the next `prev_hash`, two exports of the same ledger differ,
  and an export cannot be matched to a native checkpoint.
- The export is unsigned. `sign_p1363` (ECDSA P-256, IEEE P1363 `r||s`, base64url) exists,
  but nothing calls it, and `aat_export` ignores its `key_path` argument.
- `record_phase` is carried through correctly for all gate records.

## 7. Conformance

An implementation that emits receipts:

- MUST write one JSON object per line with the envelope fields in 2.2.
- MUST compute `hash` exactly as in 5.1 and chain `prev_hash` and `seq` as in 2.2.
- MUST serialize appends so two writers cannot read the same head. MUST fsync each record
  before returning.
- MUST write the `pre_execution` decision record, and have it durable on disk, before the
  action starts. MUST NOT start the action if that write fails.
- MUST write exactly one `post_execution` record per started or refused request, unless the
  process dies first.
- MUST include `request_id`, `payload_sha256` and `policy_version` in every record of a request.
- MUST compute `payload_sha256` exactly as in Section 3.2, with the typed field list for the
  action type. For a new action type, SHOULD define a fixed typed field list rather than
  hashing all keys.
- MUST NOT write message bodies, secrets or model free-text reasons to receipts.
- SHOULD create the ledger file with owner-only permissions.
- SHOULD record the fsync of the containing directory when creating the file (the reference
  code does not).

An implementation that verifies receipts:

- MUST run the algorithm in 5.2 and treat any break as failure.
- MUST treat a missing checkpoint as "rebuild not excluded", never as success.
- When a checkpoint or exported line is present, MUST verify it (5.3) and MUST also run 5.2.
  Passing one without the other is not a pass.
- SHOULD pin the expected signer public key.
- SHOULD check the per-request ordering rules in Section 4. The reference code does not.
- SHOULD report the number of records after the last checkpoint as unprotected against
  truncation.

## 8. Open questions

1. **Canonical form.** The native chain uses Python `json.dumps`, not RFC 8785, and three
   different serializers are in use (record hash, fingerprint, policy version). Should v0.2
   move all three to JCS? That breaks every existing chain unless records gain a version bump
   (`v: 2`) and verifiers support both.
2. **Tail truncation.** Should the gate checkpoint automatically, for example after every
   decision or on shutdown, and publish the head off-machine?
3. **Per-record authenticity.** Records are not signed. Should decision records carry a
   signature so a verifier knows the gate wrote them?
4. **Ordering verifier.** Section 4 rules are enforced by the writer only. Should `hsm watch`
   or a gate command check them?
5. **Task binding.** The human's task is not recorded. Should `gate.request` carry a hash of
   the task, so a verifier can tell which instruction a decision was made under?
6. **Policy version scope.** It includes reviewer settings and excludes the live spend state,
   and it is truncated to 64 bits. Should it be the full hash of rules only, with reviewer
   identity recorded separately (it already is, in `gate.review.model`)?
7. **AAT export fidelity.** Should the exporter map `gate.denied` to `denied`, use deterministic
   `record_id` values (for example derived from the native hash), carry the native `hash`, and
   sign with `sign_p1363`? The draft text needs to be read before deciding. UNVERIFIED.
8. **Egress receipts.** They have no request binding and are rate limited. Should they carry
   the gate session and a count of suppressed attempts?
9. **`executed` wording.** For a prepared, unsigned transaction or a dry-run email, should the
   post record say `gate.prepared` instead of `gate.executed`?
10. **Signed message format.** The checkpoint signs `"<head>:<records>"` with no context
    string. Should it add a domain-separation prefix and cover `ts`?
