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

# Nemotron on Nebius Token Factory: both models are hosted, so CPU containers and no Ollama.
SRC = HERE.parent.parent / "src" / "homestead_gate"   # not parents[1]: inside the container HERE is /root
nemo_image = (modal.Image.debian_slim(python_version="3.12")
              .pip_install("agentdojo==0.1.35", "openai")
              .add_local_file(HERE.parent / "review.py", "/root/bench/review.py")
              .add_local_file(HERE / "run_gate.py", "/root/bench/agentdojo/run_gate.py")
              .add_local_file(HERE / "hosted.py", "/root/bench/agentdojo/hosted.py")
              .add_local_file(SRC / "__init__.py", "/root/src/homestead_gate/__init__.py")
              .add_local_file(SRC / "llm.py", "/root/src/homestead_gate/llm.py")
              .add_local_file(SRC / "assistant.py", "/root/src/homestead_gate/assistant.py"))   # read for SYSTEM_GUARD only
SUPER, NANO = "nvidia/nemotron-3-super-120b-a12b", "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
NEMO_COMMON = ["--agent", SUPER, "--agent-backend", "tokenfactory", "--agent-system", "guard", "--skip-selfcheck"]
NEMO_SETTINGS = {"nogate": [], "gate": ["--gate", NANO, "--gate-backend", "tokenfactory", "--human", "none"]}


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

@app.function(image=nemo_image, cpu=1, memory=2048, timeout=6 * 3600, volumes={"/results": vol},
              secrets=[modal.Secret.from_name("nebius-token-factory")])
def run_nemotron(suite: str, lane: int, user_tasks: list[str], settings: list[str], cost_cap: float,
                 prefix: str = "nemotron") -> dict:
    """One lane: every setting runs AT THE SAME TIME on the same user tasks, so stopping early still
    leaves matched no-gate / gate data. Each process stops itself at `cost_cap` USD (estimate)."""
    import os, subprocess, time
    env = dict(os.environ, HG_LANE_COST_CAP_USD=str(cost_cap))
    t, procs = time.time(), {}
    for name in settings:
        dest = f"/results/{prefix}/{suite}/lane{lane:02d}/{name}"
        Path(dest).mkdir(parents=True, exist_ok=True)
        log = open(f"{dest}/stdout.txt", "w")
        procs[name] = subprocess.Popen(["python", "/root/bench/agentdojo/run_gate.py", "--suite", suite, "--out", dest,
                                        "--user-tasks", *user_tasks, *NEMO_COMMON, *NEMO_SETTINGS[name]],
                                       stdout=log, stderr=subprocess.STDOUT, env=env)
    while any(p.poll() is None for p in procs.values()):
        time.sleep(60)
        vol.commit()
        usd = 0.0
        for name in settings:
            u = Path(f"/results/{prefix}/{suite}/lane{lane:02d}/{name}/usage.json")
            if u.exists():
                try:
                    usd += json.loads(u.read_text())["usd_estimate"]
                except Exception:
                    pass
        runs = sum(1 for _ in Path(f"/results/{prefix}/{suite}/lane{lane:02d}").rglob("agentdojo_logs/**/*.json"))
        print(f"{suite} lane{lane}: {runs} run logs, ${usd:.3f}, {round((time.time() - t) / 60)} min", flush=True)
    vol.commit()
    return {name: p.returncode for name, p in procs.items()} | {"suite": suite, "lane": lane,
                                                                 "minutes": round((time.time() - t) / 60, 1)}


# Local reviewer: brain Nemotron 3 Super on Token Factory (guard prompt), reviewer a Nemotron Nano tag
# pulled from the Ollama registry exactly as a laptop would (`ollama pull nemotron-3-nano:30b`, the
# 4-bit default tag), served by Ollama on one GPU. Same run_gate.py path as the Nano 4B run: gate
# backend ollama, num_ctx 16384 (run_gate.CTX), frozen prompt v1, model only, LOCAL_LANES lanes sharing
# the one Ollama server. Ollama serves nemotron_h one request at a time, so reviews queue.
#   modal run --detach bench/agentdojo/modal_run.py --suite banking --local-gate nemotron-3-nano:30b \
#       --prefix nano30b_local --cost-cap 0.9 --total-cap 3.6
local_image = (modal.Image.debian_slim(python_version="3.12")
               .apt_install("curl", "zstd", "ca-certificates")
               .run_commands("curl -fsSL https://ollama.com/install.sh | sh")
               .pip_install("agentdojo==0.1.35", "openai")
               .add_local_file(HERE.parent / "review.py", "/root/bench/review.py")
               .add_local_file(HERE / "run_gate.py", "/root/bench/agentdojo/run_gate.py")
               .add_local_file(HERE / "hosted.py", "/root/bench/agentdojo/hosted.py")
               .add_local_file(SRC / "__init__.py", "/root/src/homestead_gate/__init__.py")
               .add_local_file(SRC / "llm.py", "/root/src/homestead_gate/llm.py")
               .add_local_file(SRC / "assistant.py", "/root/src/homestead_gate/assistant.py"))
LOCAL_LANES = 8


@app.function(image=local_image, gpu="L40S", timeout=2 * 3600, volumes={"/results": vol},
              secrets=[modal.Secret.from_name("nebius-token-factory")])
def run_local_gate(suite: str, gate_model: str, user_tasks: list[str], cost_cap: float, prefix: str,
                   total_cap: float = 3.6) -> dict:
    """All lanes in one container around one Ollama server. Each lane stops itself at `cost_cap` USD of
    brain spend (a loose backstop: the lanes holding banking tasks 12/13 cost the most), and every lane
    is terminated once the summed brain spend reaches `total_cap`. The reviewer is local and free. The
    2 h timeout is the hard GPU-spend stop."""
    import os, subprocess, time, urllib.request
    root = f"/results/{prefix}/{suite}"
    Path(root).mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, OLLAMA_CONTEXT_LENGTH="16384", OLLAMA_KEEP_ALIVE="120m")
    subprocess.Popen(f"ollama serve > {root}/ollama.log 2>&1", shell=True, env=env)
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:11434/api/version", timeout=2); break
        except Exception:
            time.sleep(2)
    for _ in range(6):
        if subprocess.run(f"ollama pull {gate_model}", shell=True).returncode == 0:
            break
        time.sleep(60)
    else:
        raise SystemExit(f"could not pull {gate_model}")
    sh = lambda c: subprocess.run(c, shell=True, capture_output=True, text=True).stdout
    info = {"ollama": sh("ollama --version").strip(), "gpu": sh("nvidia-smi --query-gpu=name,memory.total --format=csv,noheader").strip(),
            "gate_model": gate_model, "list": sh("ollama list"), "show": sh(f"ollama show {gate_model}"),
            "modelfile_from": [l for l in sh(f"ollama show --modelfile {gate_model}").splitlines() if l.startswith("FROM")],
            "manifest": sh(f"cat /root/.ollama/models/manifests/registry.ollama.ai/library/{gate_model.replace(':', '/')}"),
            "lanes": LOCAL_LANES, "user_tasks": user_tasks, "cost_cap_per_lane": cost_cap}
    # warm the model once so lane 0's first review is not the load
    subprocess.run(["curl", "-s", "http://127.0.0.1:11434/api/chat", "-d", json.dumps(
        {"model": gate_model, "stream": False, "think": False, "messages": [{"role": "user", "content": "hi"}],
         "options": {"num_ctx": 16384, "num_predict": 8}})], capture_output=True)
    info["vram_after_load"] = sh("nvidia-smi --query-gpu=memory.used --format=csv,noheader").strip()
    info["ps"] = sh("ollama ps")
    Path(f"{root}/env.json").write_text(json.dumps(info, indent=1))
    print(json.dumps(info, indent=1), flush=True)
    vol.commit()
    t, procs = time.time(), []
    for lane in range(LOCAL_LANES):
        mine = user_tasks[lane::LOCAL_LANES]
        if not mine:
            continue
        dest = f"{root}/lane{lane:02d}/gate"
        Path(dest).mkdir(parents=True, exist_ok=True)
        procs.append(subprocess.Popen(
            ["python", "/root/bench/agentdojo/run_gate.py", "--suite", suite, "--out", dest, "--user-tasks", *mine,
             *NEMO_COMMON, "--gate", gate_model, "--gate-backend", "ollama", "--human", "none"],
            stdout=open(f"{dest}/stdout.txt", "w"), stderr=subprocess.STDOUT,
            env=dict(os.environ, HG_LANE_COST_CAP_USD=str(cost_cap))))
    while any(p.poll() is None for p in procs):
        time.sleep(60)
        vol.commit()
        runs = sum(1 for _ in Path(root).rglob("agentdojo_logs/**/*.json"))
        rows = [json.loads(l) for f in Path(root).rglob("gate_log.jsonl") for l in f.read_text().splitlines() if l]
        usd, events = 0.0, {}
        for u in Path(root).rglob("usage.json"):
            try:
                j = json.loads(u.read_text())
            except Exception:
                continue
            usd += j.get("usd_estimate", 0)
            for k, v in j.get("events", {}).items():
                events[k] = events.get(k, 0) + v
        blk = sum(r["verdict"] == "block" for r in rows)
        print(f"{suite} {gate_model}: {runs} run logs, {len(rows)} reviews ({blk} block), ${usd:.3f} brain, "
              f"{round((time.time() - t) / 60)} min; events {events}; last: {rows[-1] if rows else None}", flush=True)
        if usd >= total_cap:
            print(f"TOTAL CAP ${total_cap} reached: terminating all lanes", flush=True)
            for p in procs:
                p.terminate()
    vol.commit()
    return {"rc": [p.returncode for p in procs], "minutes": round((time.time() - t) / 60, 1)}


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
         gatebench_prompts: str = "", settings: str = "", split: str = "test", nemotron: bool = False,
         lanes: int = 4, cost_cap: float = 1.2, tasks: str = "", prefix: str = "nemotron", local_gate: str = "",
         total_cap: float = 3.6):
    if local_gate:
        n = {"workspace": 40, "travel": 20, "banking": 16, "slack": 21}[suite]
        ids = tasks.split(",") if tasks else [f"user_task_{i}" for i in range(n)]
        print(run_local_gate.remote(suite, local_gate, ids, cost_cap, prefix, total_cap), flush=True)
        return
    if nemotron:
        # modal run bench/agentdojo/modal_run.py --nemotron --suite banking,travel --lanes 4
        # --tasks user_task_0 (smoke) restricts the user tasks. Results: agentdojo-results/<prefix>/<suite>/
        chosen = settings.split(",") if settings else list(NEMO_SETTINGS)
        jobs = []
        for su in suite.split(","):
            n = {"workspace": 40, "travel": 20, "banking": 16, "slack": 21}[su]
            ids = tasks.split(",") if tasks else [f"user_task_{i}" for i in range(n)]
            k = min(lanes, len(ids))
            jobs += [(su, i, ids[i::k], chosen, cost_cap, prefix) for i in range(k)]
        for res in run_nemotron.starmap(jobs):
            print(res, flush=True)
        return
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
