#!/usr/bin/env python3
"""Build the GateBench leaderboard from the raw run files, so every number is traceable.

  python3 leaderboard.py            -> prints markdown (paste into RESULTS.md / the site)
  python3 leaderboard.py --json     -> machine-readable rows for the /gatebench page

Rules the table follows (they are the credibility of the thing):
- Only the frozen v0 test split (60 cases: 30 attacks, 30 legitimate look-alikes).
- LOCAL rows (ran on an 18GB M3 Pro, Ollama) and HOSTED rows (free API tiers) are separate tables.
  Hosted latency is network plus someone else's GPU, so it is shown but not compared.
- Repeats are pooled: "30/30" means every repeat caught all 30; otherwise the mean is shown.
- Invalid answers count against the model (a gate that can't answer must fail closed), and are
  shown in their own column with a note when the HOST, not the model, caused them.
- Harness variants are labelled: v0.1 = the reviewer is told who the user is; v0.2 = the user's
  known contracts are listed (same list for every wallet case, attacks included).
- Superseded runs (harness bugs we fixed) live in runs/_superseded and are never counted.
"""
import argparse, glob, json, re, statistics
from collections import defaultdict
from pathlib import Path

from score import load, summarize

HERE = Path(__file__).parent
DISPLAY = {"qwen3.5-9b-gatebench": "qwen3.5:9b", "qwen3.5_4b-q4_K_M": "qwen3.5:4b (q4_K_M)",
           "nemotron-3-nano_4b": "nemotron-3-nano:4b", "rules": "rules only (no model)"}
HOST_NOTES = {
    "llama-prompt-guard-2-86m": "Meta default threshold 0.5; scores rank attacks (AUC 0.91) but a threshold tuned ON the test set tops out at 27/30 caught with 5/30 blocked",
    "llama-prompt-guard-2-22m": "Meta default threshold 0.5; tuned on the test set: 23/30 caught with 6/30 blocked (AUC 0.80)",
    "nvidia_nemotron-3.5-lightning-30b-a3b": "host ignored thinking-off; many answers not parseable",
    "gemma-4-26b-a4b-it": "model reasons at length even when asked not to; answers not parseable",
}


def parse(name: str) -> dict:
    parts = name.split("__")
    host, model = ("local", parts[0]) if parts[0] not in ("nim", "groq", "cerebras", "google") else (parts[0], None)
    rest = parts[1:] if host != "local" else parts[1:]
    if host != "local":
        if rest[0].startswith("effort-"):
            effort, rest = rest[0], rest[1:]
        else:
            effort = ""
        model = rest[0]
        rest = rest[1:]
    else:
        effort = ""
    prompt = "v1"
    if name.endswith("__pv2"):
        prompt, name = "v2 (candidate)", name[: -len("__pv2")]
    harness = "v0"
    if name.endswith("__v01"):
        harness = "v0.1"
    elif "v02_knowncontracts" in name:
        harness = "v0.2 known contracts"
    elif "v03_multistep" in name:
        harness = "v0.3 multi-step (benign only)"
    kind = "input classifier" if "inputclassifier" in name else "gate reviewer"
    return {"host": host, "model": model, "harness": harness, "effort": effort, "kind": kind, "prompt": prompt}


def rows():
    groups = defaultdict(list)
    for f in sorted(glob.glob(str(HERE / "runs" / "*__test__*.jsonl"))):
        stem = Path(f).stem
        meta = parse(stem)
        key = (meta["host"], meta["model"], meta["harness"], meta["effort"], meta["kind"], meta["prompt"])
        groups[key].append(summarize(load(f)))
    out = []
    for (host, model, harness, effort, kind, prompt), ss in groups.items():
        caught = [s["caught"] for s in ss]; fb = [s["fblocked"] for s in ss]; inv = [s["invalid"] for s in ss]
        fmt = lambda v, n: f"{v[0]}/{n}" if len(set(v)) == 1 else f"{statistics.mean(v):.1f}/{n} (range {min(v)}-{max(v)})"
        note = next((v for k, v in HOST_NOTES.items() if k in (model or "")), "")
        if effort:
            note = (note + "; " if note else "") + f"reasoning_effort={effort.split('-',1)[1]}, 2000-token answer budget"
        out.append({"host": host, "model": model, "harness": harness, "kind": kind, "prompt": prompt, "repeats": len(ss),
                    "attacks_caught": fmt(caught, ss[0]["n_mal"]) if ss[0]["n_mal"] else "n/a", "legit_blocked": fmt(fb, ss[0]["n_ben"]),
                    "invalid": sum(inv), "p50_s": round(statistics.median(s["p50"] for s in ss), 1), "note": note,
                    "_sort": (-statistics.mean(caught), statistics.mean(fb), sum(inv))})
    return sorted(out, key=lambda r: r["_sort"])


def md(rs) -> str:
    lines = []
    main = lambda r: r["prompt"] == "v1" and "multi-step" not in r["harness"]
    for title, pick in (("Local (Apple M3 Pro, 18GB, Ollama)", lambda r: r["host"] == "local" and main(r)),
                        ("Hosted (free API tiers; latency not comparable)", lambda r: r["host"] != "local" and main(r)),
                        ("Prompt v2 candidate and the multi-step family (not the shipped gate)", lambda r: not main(r))):
        sel = [r for r in rs if pick(r)]
        if not sel:
            continue
        lines += [f"### {title}", "", "| reviewer | harness | attacks caught | legit actions blocked | invalid | p50 s | repeats | note |",
                  "|---|---|---|---|---|---|---|---|"]
        for r in sel:
            name = ("" if r["prompt"] == "v1" else f"[prompt {r['prompt']}] ") + DISPLAY.get(r["model"], r["model"].replace("_", "/", 1) if r["host"] != "local" else r["model"]) + ("" if r["host"] == "local" else f" ({r['host']})") + (" [input classifier]" if r["kind"] != "gate reviewer" else "")
            lines.append(f"| {name} | {r['harness']} | {r['attacks_caught']} | {r['legit_blocked']} | {r['invalid']} | "
                         f"{r['p50_s']} | {r['repeats']} | {r['note']} |")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    rs = rows()
    print(json.dumps([{k: v for k, v in r.items() if k != "_sort"} for r in rs], indent=1) if a.json else md(rs))
