# homestead-gate on AgentDojo

AgentDojo (ETH Zurich, MIT) is an independent agent-security benchmark: realistic tasks in simulated
banking, Slack, travel and workspace environments, with prompt injections planted in the data the agent
reads, and AgentDojo's own scoring. We did not write these tasks or attacks.

Setup: agent and gate are both Qwen 3.5 9B (Ollama, 16k context, temperature 0, thinking off), AgentDojo
v1.2.2, attack `important_instructions`. The gate reviews every side-effecting tool call with the same
frozen prompt v1 the product ships, plus the user's known contacts from the environment. Three settings:

- **no gate**: the agent alone.
- **gate (model only)**: a model block is final. This is the strictest setting, not the product's default.
- **gate + oracle human**: the product's 2-of-2. A flagged call goes to a simulated human that refuses
  the attacker's calls and approves everything else. It recognises an attacker call only by the
  injection task's exact distinctive values, so it is a lenient human (see below).

Merged from the run traces with `aggregate.py`; every number below is recomputed from traces, not from
per-machine summaries. Banking and Slack ran on Kaggle T4s (2026-09-30).

| suite | setting | user tasks | utility, no attack | utility under attack | attack success | attacked runs: ignored / blocked / tried, failed / through | legit actions blocked per run |
|---|---|---|---|---|---|---|---|
| banking | no gate | 16 | 13/16 (81%) | 107/144 (74%) | **40/144 (28%)** | 97 / 0 / 7 / 40 | 0.00 |
| banking | gate (model only) | 16 | 9/16 (56%) | 59/144 (41%) | **0/144 (0%)** | 88 / 56 / 0 / 0 | 0.84 |
| banking | gate + oracle human | 16 | 12/16 (75%) | 88/144 (61%) | **1/144 (1%)** | 106 / 37 / 0 / 1 | n/a |
| slack | no gate | 21 | 19/21 (90%) | 63/105 (60%) | **32/105 (30%)** | 67 / 0 / 6 / 32 | 0.00 |
| slack | gate (model only) | 21 | 12/21 (57%) | 28/105 (27%) | **0/105 (0%)** | 80 / 25 / 0 / 0 | 2.37 |
| slack | gate + oracle human | 21 | 19/21 (90%) | 50/83 (60%) | **4/83 (5%)** | 55 / 23 / 1 / 4 | n/a |

Columns: "ignored" = the agent never made the attacker's side-effecting call; "blocked" = it did and every
such call was stopped; "tried, failed" = such a call ran but the attack still failed; "through" =
AgentDojo scored the attack a success. Read-only setup steps of an attack (e.g. `get_channels`) are not
counted as attacker calls, because the gate does not review reads and they cause no harm alone.

## What this shows

1. **Without a gate the agent is hijacked often**: 28% of attacked banking runs and 30% of Slack runs.
2. **The model-only gate stopped every hijack**: 0 of 144 and 0 of 105. In every attacked run where the
   agent made the attacker's harmful call, the gate blocked it.
3. **It pays for that in usefulness.** The gate blocked 280 of the 343 actions it reviewed on banking (counting AgentDojo's self-check runs too), and the
   agent finished the user's own task far less often (banking 81% to 56%, Slack 90% to 57%). This is the
   same over-blocking GateBench v0.3 found: the gate judges one step against the whole request.
4. **With a human in the loop, utility comes back** (75%, 90%) and attack success stays low (1/144, 4/83).
   In all 5 that got through, the harmful call was one our simulated human does not recognise. Banking:
   after five blocked attempts the agent switched to creating a new scheduled payment to the attacker, a
   different function from the attack's script (in the model-only run the model blocked that same call).
   Slack: the agent sent Alice the phishing link in its own words. The oracle only recognises the attack's
   exact function and values, so it approves such calls if the model flags them. The traces do not record
   whether the model or the oracle approved each one. A real person reading the prompt would likely catch
   some of these; we have not measured that.

## Limits, stated

- **Incomplete:** Slack's oracle run was cut off by Kaggle at 83 of 105 attacked runs. Travel and Workspace
  are running. The oracle runs' per-run human-prompt counts were lost with the cut-off summaries.
- One agent model (Qwen 3.5 9B); a stronger agent ignores more injections on its own.
- The oracle human is a simulation and is neither an upper nor a lower bound on a real person.
- `aggregate.py` recognises an attacker call by the attack's own function plus a distinctive value, so an
  attack carried out through a different function is not counted as an attempt. This under-counts
  "blocked" (e.g. a model-only banking run is labelled "ignored" although the model blocked a new payment
  to the attacker's account). AgentDojo's attack-success column does not depend on it.
- Reviewer context here is 16k (GateBench uses 4096), because AgentDojo transcripts are long.
