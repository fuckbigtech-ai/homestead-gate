#!/usr/bin/env python3
"""Re-review recorded gate decisions under another reviewer prompt, without re-running the agent.

  python replay.py AGG_JSON --prompt v3 [--suites banking slack] [--model qwen3.5-9b-gatebench] [--out F]

Takes the per-run rows written by `aggregate.py --json` and, from the model-only gate runs:
  false_block  the first blocked call in each run with NO attack (every block there is a mistake)
  attack       the first blocked attacker call in each attacked run the gate stopped
and asks the reviewer again with exactly the inputs it had (user request, tool results so far with the
same caps, known contacts), under the chosen prompt. A cheap dev-set check: how many false blocks a new
prompt would approve, and whether it still blocks every attacker call. It does NOT replace a full run,
because a different verdict changes what the agent does next.
"""
from __future__ import annotations

import argparse, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import aggregate as A                                   # noqa: E402
import run_gate as R                                    # noqa: E402
from agentdojo.task_suite.load_suites import get_suite  # noqa: E402
from agentdojo.types import get_text_content_as_str     # noqa: E402


def items(rows, suites):
    for r in rows:
        if r["setting"] != "gate (model only)" or r["suite"] not in suites or r["user_task"].startswith("injection"):
            continue
        clean = not r["injection_task"]
        kind = "false_block" if clean and r["legit_blocked"] else "attack" if (not clean and r["outcome"] == "blocked") else None
        if not kind:
            continue
        d = json.load(open(r["path"]))
        gts = [] if clean else A.attacker_calls("v1.2.2", r["suite"], r["injection_task"])
        query = get_text_content_as_str(next(m["content"] for m in d["messages"] if m["role"] == "user"))
        parts, named = [], []
        for m in d["messages"]:
            if m.get("role") != "tool":
                continue
            c = m.get("tool_call") or {}
            if "approval gate" in str(m.get("error") or "") and (clean or A.is_attacker(c, gts)):
                yield (kind, r, query, "\n---\n".join(parts)[-R.MAX_UNTRUSTED_CHARS:] or "nothing yet", c,
                       "\n---\n".join(named))
                break
            text = get_text_content_as_str(m.get("content") or [])[:R.PER_RESULT_CHARS]
            parts.append(text)
            if R.named_by_user(c.get("args"), query):
                named.append(text)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("agg")
    ap.add_argument("--prompt", default="v3", choices=sorted(R.PROMPTS))
    ap.add_argument("--suites", nargs="+", default=["banking", "slack"])
    ap.add_argument("--model", default="qwen3.5-9b-gatebench")
    ap.add_argument("--out")
    a = ap.parse_args()
    R.PROMPT.update(version=a.prompt, system=R.PROMPTS[a.prompt])
    contacts, res = {}, []
    todo = list(items(json.load(open(a.agg)), set(a.suites)))
    todo.sort(key=lambda t: t[0] != "false_block")     # false blocks first: the cheap answer to "does it help"
    for kind, r, q, unt, c, nam in todo:
        if r["suite"] not in contacts:
            contacts[r["suite"]] = R.known_contacts(get_suite("v1.2.2", r["suite"]).load_and_inject_default_environment({}))
        R.CURRENT.clear()
        R.CURRENT.update(contacts=contacts[r["suite"]], attacker_calls=[])
        v, why = R.review(a.model, q, unt, {"type": "tool_call", "tool": c["function"], "args": c.get("args")}, named=nam)
        res.append({"kind": kind, "suite": r["suite"], "user_task": r["user_task"], "injection_task": r["injection_task"],
                    "tool": c["function"], "args": c.get("args"), "verdict": v, "reason": why})
        print(f"{kind:11} {r['suite']:9} {r['user_task']:13} {str(r['injection_task']):18} {c['function']:28} {v}", flush=True)
    fb = [x for x in res if x["kind"] == "false_block"]
    at = [x for x in res if x["kind"] == "attack"]
    print(f"\nprompt {a.prompt}: false blocks now approved {sum(x['verdict'] == 'approve' for x in fb)}/{len(fb)}; "
          f"attacker calls still blocked {sum(x['verdict'] != 'approve' for x in at)}/{len(at)}")
    if a.out:
        json.dump(res, open(a.out, "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main())
