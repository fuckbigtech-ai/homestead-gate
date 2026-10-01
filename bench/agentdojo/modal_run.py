"""Run the AgentDojo defense benchmark on Modal GPUs, split by user task. Mirrors the Kaggle kernel:
same run_gate.py, same frozen reviewer prompt, qwen3.5:9b at 16k context as both agent and gate.

  modal run bench/agentdojo/modal_run.py --suite workspace --chunks 4           # full suite, 4 GPUs
  modal run bench/agentdojo/modal_run.py --suite workspace --smoke              # 1 task, gate only
  modal volume get agentdojo-results workspace ./results_workspace              # fetch results

Each chunk runs all three settings (no gate; gate, model only; gate + oracle human) on its slice
of user tasks and writes to the agentdojo-results volume, so a dead container loses one slice only.
"""
import json
from pathlib import Path

import modal

HERE = Path(__file__).resolve().parent
MODEL, AGENT = "qwen3.5:9b", "qwen3.5-9b-agent16k"
SETTINGS = {"nogate": [], "gate": ["--gate", AGENT, "--human", "none"],
            "gate_oracle": ["--gate", AGENT, "--human", "oracle"],
            "gate_v4": ["--gate", AGENT, "--human", "none", "--prompt", "v4"],
            "gate_oracle_v4": ["--gate", AGENT, "--human", "oracle", "--prompt", "v4"],
            "gate_v5": ["--gate", AGENT, "--human", "none", "--prompt", "v5"],
            "gate_oracle_v5": ["--gate", AGENT, "--human", "oracle", "--prompt", "v5"]}

image = (modal.Image.debian_slim(python_version="3.12")
         .apt_install("curl", "zstd", "ca-certificates")
         .run_commands("curl -fsSL https://ollama.com/install.sh | sh")
         .pip_install("agentdojo==0.1.35", "openai")
         .add_local_file(HERE.parent / "review.py", "/root/bench/review.py")
         .add_local_file(HERE / "run_gate.py", "/root/bench/agentdojo/run_gate.py")
         .add_local_file(HERE / "aggregate.py", "/root/bench/agentdojo/aggregate.py")
         .add_local_file(HERE / "replay.py", "/root/bench/agentdojo/replay.py")
         .add_local_file(HERE.parent / "score.py", "/root/bench/score.py")
         .add_local_dir(HERE.parent, "/root/bench", ignore=lambda p: not str(p).endswith(".jsonl") or "runs" in str(p)))
RUNS = Path.home() / "hg-runs"       # traces downloaded from Kaggle; agg_all.json paths point at /home/ubuntu/hg-runs
replay_image = (image
                .add_local_dir(RUNS / "kaggle-banking", "/home/ubuntu/hg-runs/kaggle-banking")
                .add_local_dir(RUNS / "kaggle-slack", "/home/ubuntu/hg-runs/kaggle-slack")
                .add_local_file(RUNS / "agg_all.json", "/home/ubuntu/hg-runs/agg_all.json"))
vol = modal.Volume.from_name("agentdojo-results", create_if_missing=True)
app = modal.App("homestead-gate-agentdojo", image=image)


def _ollama_up():
    import os, subprocess, time, urllib.request
    env = dict(os.environ, OLLAMA_CONTEXT_LENGTH="16384", OLLAMA_KEEP_ALIVE="60m")
    subprocess.Popen("ollama serve > /tmp/ollama.log 2>&1", shell=True, env=env)
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:11434/api/version", timeout=2); break
        except Exception:
            time.sleep(2)
    for _ in range(8):                      # the registry sometimes 524s; it says retry later
        if subprocess.run(f"ollama pull {MODEL}", shell=True).returncode == 0:
            break
        time.sleep(150)
    else:
        raise SystemExit(f"could not pull {MODEL}")
    Path("/tmp/Modelfile").write_text(f"FROM {MODEL}\nPARAMETER num_ctx 16384\nPARAMETER temperature 0\n")
    subprocess.run(f"ollama create {AGENT} -f /tmp/Modelfile", shell=True, check=True)


LANES = 3      # run_gate processes per GPU, each on its own task slice; Ollama batches them


@app.function(gpu="L4", timeout=24 * 3600, volumes={"/results": vol})
def run_chunk(suite: str, chunk: int, user_tasks: list[str], settings: list[str]) -> dict:
    import os, subprocess, time
    os.environ["OLLAMA_NUM_PARALLEL"] = str(LANES)       # read by `ollama serve` in _ollama_up
    _ollama_up()
    out = {}
    for name in settings:
        t, procs = time.time(), []
        for lane in range(LANES):
            mine = user_tasks[lane::LANES]
            if not mine:
                continue
            dest = f"/results/{suite}/chunk{chunk:02d}/{name}/lane{lane}"
            Path(dest).mkdir(parents=True, exist_ok=True)
            log = open(f"{dest}/stdout.txt", "w")
            procs.append(subprocess.Popen(["python", "/root/bench/agentdojo/run_gate.py", "--suite", suite,
                                           "--agent", AGENT, "--out", dest, "--user-tasks", *mine,
                                           *SETTINGS[name]], stdout=log, stderr=subprocess.STDOUT))
        while any(p.poll() is None for p in procs):
            time.sleep(180)
            done = sum(1 for _ in Path(f"/results/{suite}/chunk{chunk:02d}/{name}").rglob("agentdojo_logs/**/*.json"))
            print(f"{suite} chunk{chunk} {name}: {done} run logs, {round((time.time() - t) / 60)} min", flush=True)
            vol.commit()
        vol.commit()
        out[name] = {"rc": [p.returncode for p in procs], "minutes": round((time.time() - t) / 60, 1)}
        print(suite, chunk, name, out[name], flush=True)
    return out

@app.function(gpu="L4", timeout=3 * 3600, image=replay_image)
def replay(prompts: list[str]) -> dict:
    """Re-review the recorded banking + Slack gate decisions (replay.py) under each prompt, on a GPU."""
    import subprocess
    _ollama_up()
    subprocess.run("printf 'FROM qwen3.5:9b\\nPARAMETER temperature 0\\n' > /tmp/Mg && "
                   "ollama create qwen3.5-9b-gatebench -f /tmp/Mg", shell=True, check=True)
    out = {}
    for pv in prompts:
        r = subprocess.run(["python", "/root/bench/agentdojo/replay.py", "/home/ubuntu/hg-runs/agg_all.json",
                            "--prompt", pv, "--out", f"/tmp/replay_{pv}.json"], capture_output=True, text=True)
        print(r.stdout[-300:], r.stderr[-300:], flush=True)
        out[pv] = json.loads(Path(f"/tmp/replay_{pv}.json").read_text()) if r.returncode == 0 else {"error": r.stderr[-2000:]}
    return out


@app.function(gpu="L4", timeout=3 * 3600)
def gatebench(prompts: list[str], repeats: int = 3, split: str = "test") -> dict:
    """GateBench frozen test split (v0.1 harness, 60 cases) and the multi-step family, per prompt."""
    import subprocess
    _ollama_up()
    subprocess.run("printf 'FROM qwen3.5:9b\\nPARAMETER temperature 0\\n' > /tmp/Mg && "
                   "ollama create qwen3.5-9b-gatebench -f /tmp/Mg", shell=True, check=True)
    subprocess.run("pip install -q ollama", shell=True, check=True)
    out = {}
    for pv in prompts:
        for cases in ("cases_v01.jsonl", "cases_v03_multistep.jsonl"):
            r = subprocess.run(["python", "/root/bench/review.py", "--model", "qwen3.5-9b-gatebench", "--split", split,
                                "--cases", cases, "--prompt", pv, "--repeats", str(repeats)],
                               capture_output=True, text=True, cwd="/root/bench")
            print(pv, cases, r.returncode, r.stderr[-300:], flush=True)
    for f in Path("/root/bench/runs").glob("*.jsonl"):
        out[f.name] = f.read_text()
    return out


@app.local_entrypoint()
def main(suite: str = "workspace", chunks: int = 4, smoke: bool = False, replay_prompts: str = "",
         gatebench_prompts: str = "", settings: str = "", split: str = "test"):
    if gatebench_prompts:                                # e.g. --gatebench-prompts v4
        files = gatebench.remote(gatebench_prompts.split(","), repeats=1 if split == "dev" else 3, split=split)
        dest = HERE.parent / "runs"
        for name, text in files.items():
            (dest / name).write_text(text)
            print("WROTE", dest / name)
        return
    if replay_prompts:                                   # e.g. --replay-prompts v1,v3,v4
        res = replay.remote(replay_prompts.split(","))
        (RUNS / "replay_modal.json").write_text(json.dumps(res, indent=1))
        for pv, rows in res.items():
            if isinstance(rows, dict):
                print(pv, "ERROR", rows["error"][-500:]); continue
            fb = [x for x in rows if x["kind"] == "false_block"]; at = [x for x in rows if x["kind"] == "attack"]
            print(f"{pv}: false blocks now approved {sum(x['verdict'] == 'approve' for x in fb)}/{len(fb)}; "
                  f"attacker calls still blocked {sum(x['verdict'] != 'approve' for x in at)}/{len(at)}")
        return
    n = {"workspace": 40, "travel": 20, "banking": 16, "slack": 21}[suite]    # user tasks in v1.2.2
    ids = [f"user_task_{i}" for i in range(n)]
    if smoke:
        print(run_chunk.remote(suite, 99, ids[:1], ["gate"]))
        return
    slices = [ids[i::chunks] for i in range(chunks)]     # interleaved, so chunks take similar time
    chosen = settings.split(",") if settings else list(SETTINGS)
    for res in run_chunk.starmap([(suite, i, s, chosen) for i, s in enumerate(slices)]):
        print(res)
