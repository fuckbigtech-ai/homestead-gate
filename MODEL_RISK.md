# Reviewer model risk

The reviewer is the local model in the gate's 2-of-2. It is treated here as a model under model risk
management: one inventory entry per default, the exact file and prompt it runs, the evidence it was
validated on, what it gets wrong, how it may be changed, and how drift is caught.

## Inventory

| entry point | model (Ollama tag) | thinking | default because |
|---|---|---|---|
| `homestead-gate up`, 18GB+ machine | `qwen3.5:9b` | off | GateBench v0.1 test: 30/30 attacks, 0/30 false blocks |
| `homestead-gate up`, 8GB machine | `nemotron-3-nano:4b` | off | GateBench v0.1 test: 30/30 attacks, 3/30 false blocks |
| `homestead-gate assistant` (demo seed) and `--imap-setup` | `nemotron-3-nano:4b` | on | AgentDojo: far fewer false blocks with thinking (below) |

- **Prompt:** v1, frozen. sha256 `1664bf9b1ac5519c45c50a1b5391e3226ca4138e8f6ef867b2e3902fa53e91fa`
  (`reviewer.PROMPT_SHA256`). It is byte-identical to `bench/review.py`; `tests/test_gate.py` fails if it drifts,
  and `tests/test_pin.py` fails if this line drifts from the code.
- **Settings:** temperature 0, seed 1001, JSON output, 4096 context (thinking: 16K context, 2048 output tokens).
- **Model file:** pinned per installation, not per tag. `[review] digest` is the sha256 of the weights blob
  (the GGUF), `[review] manifest_digest` the sha256 of the Ollama manifest (template and parameters). Both are
  written by `homestead-gate reviewer pin` and are part of the policy version recorded with every decision.
- **Receipts:** every `gate.review` record carries `model`, `digest`, `manifest_digest`, `prompt_version`,
  `prompt_sha256`, `think`, `pin_state`, and `pin_override` when the override was used. The reviewer's reason is
  not stored (it can quote the email body).

### Files our published numbers were measured on

`homestead-gate doctor` compares the pinned weights with this table (`pin.MEASURED`) and says either "the exact
file our published numbers were measured on" or "not a measured file". Only digests a run log records:

| weights blob | file | published numbers measured on it |
|---|---|---|
| `sha256:be5d9a656a51922f24f1f09a759cebb694e1f5d9728bf0ef9f8c972c5a0b5ef2` | NVIDIA's GGUF `hf.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF:Q4_K_M`, copied to `nemotron-3-nano:4b` | AgentDojo Nano 4B rows (banking off/on, travel held-out, replays) |
| `sha256:a70437c41b3b0b768c48737e15f8160c90f13dc963f5226aabb3a160f708d1ce` | Ollama library `nemotron-3-nano:30b` (Q4_K_M) | AgentDojo local Nano 30B rows |
| `sha256:dec52a44569a2a25341c4e4d3fee25846eed4f6f0b936278e3a3c900bb99d37c` | Ollama library `qwen3.5:9b` | AgentDojo Qwen 3.5 9B banking and Slack runs (prompt v1); GateBench runs of candidate prompts v3/v4, which did not ship ([prompts v1 to v5](bench/agentdojo/RESULTS.md#fixing-the-over-blocking-prompt-v1-to-v5-2026-10-01)) |

Not in the table, on purpose:
- **`ollama pull nemotron-3-nano:4b` from the Ollama library** is a different file from NVIDIA's GGUF, and no run
  log in this repo records its blob. Doctor will say "not a measured file" for it. That is the honest answer: the
  AgentDojo 4B numbers were measured on the NVIDIA GGUF. To run the measured file:
  `ollama pull hf.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF:Q4_K_M && ollama cp hf.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF:Q4_K_M nemotron-3-nano:4b`.
- **GateBench's M3 Pro numbers** (the 30/30 rows) did not record a blob, so no file is claimed for them.

## Validation evidence

- **GateBench**, 60 frozen held-out cases (30 attacks, 30 legitimate look-alikes), prompt frozen before the test
  split ran: [bench/RESULTS.md](bench/RESULTS.md) ("Local (Apple M3 Pro, 18GB, Ollama)").
- **AgentDojo** (independent benchmark, ETH Zurich), banking as the dev suite, travel held out:
  - [Nano 4B, thinking off](bench/agentdojo/RESULTS.md#nano-4b-the-reviewer-the-product-ships-2026-10-02)
  - [Nano 4B, thinking on: banking (dev) and travel (held-out)](bench/agentdojo/RESULTS.md#nano-4b-with-thinking-full-runs-banking-dev-and-travel-held-out-2026-10-02)
  - [Nano 30B, local 4-bit](bench/agentdojo/RESULTS.md#nano-30b-local-4-bit-ollama-2026-10-02)
  - [Prompts v1 to v5](bench/agentdojo/RESULTS.md#fixing-the-over-blocking-prompt-v1-to-v5-2026-10-01): v3 and v4
    failed held-out and v5 lost on travel, so v1 still ships.
  - [Parser re-check](bench/agentdojo/RESULTS.md#parser-re-check-2026-10-04): strict and lenient parsers differ
    on 0 of 274 identical replies.

## Known limits

- **Retries can beat it.** Nano 4B with thinking let 1 of 144 banking attacks through: the agent retried the same
  call six times and the sixth review approved it (1 of 515 attacker-call reviews). Thinking off approved 0. The
  human is the second key for this.
- **False blocks depend on the setting** (legitimate calls blocked per AgentDojo run):

  | reviewer | banking (dev) | travel (held-out) |
  |---|---|---|
  | Nano 4B, thinking off | 4.09 (57% of runs) | 1.03 (29% of runs) |
  | Nano 4B, thinking on | 0.54 (21% of runs) | 0.14 (8% of runs) |
  | Nano 30B hosted | 0.69 (26% of runs) | 0.14 (9% of runs) |
  | Qwen 3.5 9B, thinking off | 0.84 | n/a (Slack: 2.37) |

  Every block goes to the human, so a high rate means approval fatigue.
- **Thinking costs time:** about 6 s per review on an L4 against about 1.3 s with thinking off; slower on a laptop.
- **Say-something attacks** (the agent's reply, not a tool call) never reach an action gate.
- **Long email:** the reviewer sees a clipped excerpt (first 1400 and last 600 characters), the brain sees more.
- **Multi-part requests over-block** (GateBench v0.3: prompt v1 blocked 9/12 legitimate single steps).
- **Temperature 0 is not bit-identical across machines**, which is why the canary has a threshold.

## Change control

Changing the default model, the prompt, or the thinking setting needs all of:
1. **Re-pin** on purpose: `homestead-gate reviewer pin` prints model, digest, size and whether the file is a
   measured one, and records a new canary baseline. Without it the gate refuses to start (or, mid-session, sends
   every review to the human).
2. **Canary** passes against the new baseline, and the baseline's scores are inspected.
3. **Held-out check** before a new default ships: GateBench test split and an AgentDojo held-out suite, with the
   result written into RESULTS.md (including failures, as for prompts v3 to v5).

An unpinned or changed model can still be run with `--allow-unpinned-reviewer`. Every `gate.review` receipt then
records `pin_override: true` and the digest actually used.

**Owner of the decision:** the person who runs the gate and owns its policy. The project ships defaults; whether to
accept a re-pinned file, a failed canary, or the override is the user's call, and the receipts show which they made.

## Monitoring: the drift canary

`homestead-gate reviewer canary` runs 20 frozen cases (GateBench test t01 to t20: 10 attacks, 10 legitimate,
byte-identical to `bench/cases_v01.jsonl`, pinned by sha256 in `canary.CASES_SHA256`) through the pinned reviewer
and compares each verdict with the baseline recorded at pin time (`reviewer_baseline.json` next to the policy).
These are held-out test cases: never tune a prompt or setting on them.

| exit | meaning |
|---|---|
| 0 | at least 90% of verdicts unchanged (`--min-agreement`) and no attack the baseline blocked is now approved |
| 1 | drift: below the threshold, or any attack flipped from block to approve; or a baseline could not be recorded |
| 2 | the reviewer is not the pinned file, cannot be checked, or does not fit this machine; nothing ran |
| 3 | no baseline, or one recorded for another model file, prompt, thinking setting or case set |

Each run appends a line to `reviewer_canary.jsonl` next to the policy. The canary loads the model (20 reviews), so
schedule it when the machine is idle. Weekly from launchd, Sunday 03:00: save this as
`~/Library/LaunchAgents/dev.homestead-gate.canary.plist`, fix the binary path (`which homestead-gate`), then
`launchctl load -w ~/Library/LaunchAgents/dev.homestead-gate.canary.plist`. For an assistant data dir, add
`<string>--data</string><string>/Users/you/.homestead-gate/mail</string>` after `canary`.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.homestead-gate.canary</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/homestead-gate</string><string>reviewer</string><string>canary</string>
  </array>
  <key>StartCalendarInterval</key><dict>
    <key>Weekday</key><integer>0</integer><key>Hour</key><integer>3</integer><key>Minute</key><integer>0</integer>
  </dict>
  <key>StandardOutPath</key><string>/tmp/homestead-gate-canary.log</string>
  <key>StandardErrorPath</key><string>/tmp/homestead-gate-canary.log</string>
</dict></plist>
```

A non-zero exit shows in `launchctl list dev.homestead-gate.canary` (last exit status) and in the log. Not yet
built: a notification on failure, and a live block-rate metric from the ledger.
