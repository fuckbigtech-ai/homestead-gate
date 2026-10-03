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


NANO4B_GGUF, NANO4B = "hf.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF:Q4_K_M", "nemotron-3-nano:4b"
items_image = image.add_local_file(HERE / "hosted.py", "/root/bench/agentdojo/hosted.py")


@app.function(gpu="L4", timeout=40 * 60, image=items_image)
def replay_items(items: list, prompt: str) -> dict:
    """Re-review pre-extracted items (replay.py --dump-items) with Nemotron 3 Nano 4B, set up as in the
    nano4b/ banking run: the NVIDIA GGUF pulled and copied to nemotron-3-nano:4b (no Modelfile), Ollama
    with a 16k context. No traces needed in the container."""
    import os, subprocess, time, urllib.request
    t0 = time.time()
    env = dict(os.environ, OLLAMA_CONTEXT_LENGTH="16384", OLLAMA_KEEP_ALIVE="60m")
    subprocess.Popen("ollama serve > /tmp/ollama.log 2>&1", shell=True, env=env)
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:11434/api/version", timeout=2); break
        except Exception:
            time.sleep(2)
    for _ in range(4):
        if subprocess.run(f"ollama pull {NANO4B_GGUF}", shell=True).returncode == 0:
            break
        time.sleep(60)
    else:
        raise SystemExit(f"could not pull {NANO4B_GGUF}")
    subprocess.run(f"ollama cp {NANO4B_GGUF} {NANO4B}", shell=True, check=True)
    meta = {"ollama": subprocess.run("ollama --version", shell=True, capture_output=True, text=True).stdout.strip(),
            "blobs": sorted(p.name for p in Path("/root/.ollama/models/blobs").iterdir())}
    Path("/tmp/items.json").write_text(json.dumps(items))
    t1 = time.time()
    r = subprocess.run(["python", "/root/bench/agentdojo/replay.py", "--items", "/tmp/items.json", "--prompt", prompt,
                        "--model", NANO4B, "--out", f"/tmp/replay_{prompt}.json"], capture_output=True, text=True)
    print(prompt, r.stdout[-600:], r.stderr[-600:], flush=True)
    rows = json.loads(Path(f"/tmp/replay_{prompt}.json").read_text()) if r.returncode == 0 else None
    return {"prompt": prompt, "rows": rows, "error": None if rows is not None else r.stderr[-2000:], "meta": meta,
            "setup_min": round((t1 - t0) / 60, 2), "total_min": round((time.time() - t0) / 60, 2)}


# Does thinking fix the local reviewers? Same items, same prompt v1, each item under each of replay.py's
# --think-modes (off = run_gate's exact request; on = think true, no format, 2048 tokens), one request at a
# time (a laptop serves one), model loaded before timing. The model blob is checked against the one the
# banking run used; a mismatch stops before any review. Rows are written to the volume as they come
# (agentdojo-results/replay_think/<model>.json), so a timeout keeps what finished.
#   modal run bench/agentdojo/modal_run.py --replay-items-file items.json --replay-think 4b,30b \
#       --think-modes off,on --replay-out DIR            (--probe 2: 2 items under on,on-json,template)
THINK_MODELS = {"4b": (NANO4B_GGUF, NANO4B, "be5d9a656a51"),
                "30b": ("nemotron-3-nano:30b", "nemotron-3-nano:30b", "a70437c41b3b")}
THINK_TIMEOUT_MIN = {"4b": 70, "30b": 45}       # the hard GPU-spend stop: L4 ~$0.93, L40S ~$1.46 at list price


def _replay_think(items: list, which: str, modes: list[str], probe: int, gpu: str) -> dict:
    import os, subprocess, time, urllib.request
    t0 = time.time()
    pull, name, blob = THINK_MODELS[which]
    sh = lambda c: subprocess.run(c, shell=True, capture_output=True, text=True).stdout
    env = dict(os.environ, OLLAMA_CONTEXT_LENGTH="16384", OLLAMA_KEEP_ALIVE="120m")
    env.pop("OLLAMA_NUM_PARALLEL", None)
    subprocess.Popen("ollama serve > /tmp/ollama.log 2>&1", shell=True, env=env)
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:11434/api/version", timeout=2); break
        except Exception:
            time.sleep(2)
    for _ in range(4):
        if subprocess.run(f"ollama pull {pull}", shell=True).returncode == 0:
            break
        time.sleep(60)
    else:
        raise SystemExit(f"could not pull {pull}")
    if name != pull:
        subprocess.run(f"ollama cp {pull} {name}", shell=True, check=True)
    blobs = sorted(p.name for p in Path("/root/.ollama/models/blobs").iterdir())
    meta = {"model": name, "gpu_requested": gpu, "ollama": sh("ollama --version").strip(),
            "gpu": sh("nvidia-smi --query-gpu=name,memory.total --format=csv,noheader").strip(), "blobs": blobs,
            "show": sh(f"ollama show {name}"), "modelfile": sh(f"ollama show --modelfile {name}")[-3000:]}
    if not any(b.startswith(f"sha256-{blob}") for b in blobs):
        return {"which": which, "meta": meta, "rows": None, "error": f"model blob {blob} not found: {blobs}"}
    subprocess.run(["curl", "-s", "http://127.0.0.1:11434/api/chat", "-d", json.dumps(
        {"model": name, "stream": False, "think": False, "messages": [{"role": "user", "content": "hi"}],
         "options": {"num_ctx": 16384, "num_predict": 8}})], capture_output=True)
    meta["vram_after_load"] = sh("nvidia-smi --query-gpu=memory.used --format=csv,noheader").strip()
    meta["ps"] = sh("ollama ps")
    print(json.dumps({k: v for k, v in meta.items() if k not in ("modelfile",)}, indent=1), flush=True)
    Path("/tmp/items.json").write_text(json.dumps(items))
    dest = f"/results/replay_think/{'probe_' if probe else ''}{which}.json"
    Path(dest).parent.mkdir(parents=True, exist_ok=True)
    left = THINK_TIMEOUT_MIN[which] - (time.time() - t0) / 60 - 6      # leave time to return the rows
    cmd = ["python", "/root/bench/agentdojo/replay.py", "--items", "/tmp/items.json", "--prompt", "v1", "--model", name,
           "--think-modes", ",".join(modes), "--deadline-min", f"{max(left, 1):.1f}", "--out", dest]
    if probe:
        cmd += ["--limit", str(probe)]
    t1 = time.time()
    p = subprocess.Popen(cmd, stdout=open("/tmp/replay.log", "w"), stderr=subprocess.STDOUT)
    while p.poll() is None:
        time.sleep(30)
        vol.commit()
    vol.commit()
    log = Path("/tmp/replay.log").read_text(errors="replace")
    print(log[-2500:], flush=True)
    rows = json.loads(Path(dest).read_text()) if Path(dest).exists() else None
    return {"which": which, "meta": meta, "rows": rows, "error": None if p.returncode == 0 else log[-3000:],
            "log_tail": log[-1500:], "ollama_log_tail": Path("/tmp/ollama.log").read_text(errors="replace")[-3000:],
            "setup_min": round((t1 - t0) / 60, 2), "total_min": round((time.time() - t0) / 60, 2)}


@app.function(gpu="L4", timeout=THINK_TIMEOUT_MIN["4b"] * 60, image=items_image, volumes={"/results": vol})
def replay_think_l4(items: list, which: str, modes: list[str], probe: int = 0) -> dict:
    return _replay_think(items, which, modes, probe, "L4")


@app.function(gpu="L40S", timeout=THINK_TIMEOUT_MIN["30b"] * 60, image=items_image, volumes={"/results": vol})
def replay_think_l40s(items: list, which: str, modes: list[str], probe: int = 0) -> dict:
    return _replay_think(items, which, modes, probe, "L40S")


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


# Full AgentDojo runs with the Nano 4B reviewer, thinking on (run_gate --gate-think) and/or off (the shipped
# request), on one L4. Same setup as the nano4b/ banking run and the thinking replay: the NVIDIA GGUF pulled and
# copied to nemotron-3-nano:4b (blob checked; a mismatch stops before any run), Ollama with a 16k context and one
# request at a time, brain Nemotron 3 Super on Token Factory with the guard prompt, prompt v1, model only.
# Every mode runs at the same time on the same tasks (LOCAL4B lanes each), so a cap or timeout still leaves matched
# think/off data. Each lane stops at `cost_cap` USD of brain spend and all lanes stop once the container's summed
# brain spend reaches `total_cap`; the function timeout is the hard GPU-spend stop.
#   modal run --detach bench/agentdojo/modal_run.py --suite banking --local4b think --total-cap 2.9
#   modal run --detach bench/agentdojo/modal_run.py --suite travel --local4b think,off --total-cap 5.0
# Traces: agentdojo-results/<LOCAL4B_PREFIX[mode]>/<suite>/laneNN/gate (think: nano4b_think/, off: nano4b/).
LOCAL4B_PREFIX = {"think": "nano4b_think", "off": "nano4b"}
LOCAL4B_TIMEOUT_MIN = {"banking": 150, "travel": 100, "smoke": 25}


def _local4b(suite: str, user_tasks: list[str], modes: list[str], lanes: int, cost_cap: float, total_cap: float,
             tag: str = "") -> dict:
    import os, subprocess, time, urllib.request
    t0 = time.time()
    roots = {m: f"/results/{LOCAL4B_PREFIX[m]}{tag}/{suite}" for m in modes}
    for r in roots.values():
        Path(r).mkdir(parents=True, exist_ok=True)
    log0 = f"{roots[modes[0]]}/ollama.log"
    env = dict(os.environ, OLLAMA_CONTEXT_LENGTH="16384", OLLAMA_KEEP_ALIVE="180m")
    env.pop("OLLAMA_NUM_PARALLEL", None)
    subprocess.Popen(f"ollama serve > {log0} 2>&1", shell=True, env=env)
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:11434/api/version", timeout=2); break
        except Exception:
            time.sleep(2)
    for _ in range(4):
        if subprocess.run(f"ollama pull {NANO4B_GGUF}", shell=True).returncode == 0:
            break
        time.sleep(60)
    else:
        raise SystemExit(f"could not pull {NANO4B_GGUF}")
    subprocess.run(f"ollama cp {NANO4B_GGUF} {NANO4B}", shell=True, check=True)
    sh = lambda c: subprocess.run(c, shell=True, capture_output=True, text=True).stdout
    blobs = sorted(p.name for p in Path("/root/.ollama/models/blobs").iterdir())
    info = {"ollama": sh("ollama --version").strip(), "gpu": sh("nvidia-smi --query-gpu=name,memory.total --format=csv,noheader").strip(),
            "gate_model": NANO4B, "pulled": NANO4B_GGUF, "blobs": blobs, "show": sh(f"ollama show {NANO4B}"),
            "modes": modes, "lanes_per_mode": lanes, "user_tasks": user_tasks, "cost_cap_per_lane": cost_cap,
            "total_cap": total_cap}
    if not any(b.startswith(f"sha256-{THINK_MODELS['4b'][2]}") for b in blobs):
        for r in roots.values():
            Path(f"{r}/env.json").write_text(json.dumps(info, indent=1))
        vol.commit()
        return {"error": f"model blob {THINK_MODELS['4b'][2]} not found", "blobs": blobs}
    subprocess.run(["curl", "-s", "http://127.0.0.1:11434/api/chat", "-d", json.dumps(
        {"model": NANO4B, "stream": False, "think": False, "messages": [{"role": "user", "content": "hi"}],
         "options": {"num_ctx": 16384, "num_predict": 8}})], capture_output=True)
    info["vram_after_load"] = sh("nvidia-smi --query-gpu=memory.used --format=csv,noheader").strip()
    info["ps"] = sh("ollama ps")
    for r in roots.values():
        Path(f"{r}/env.json").write_text(json.dumps(info, indent=1))
    print(json.dumps({k: v for k, v in info.items() if k != "blobs"}, indent=1), flush=True)
    vol.commit()
    t, procs = time.time(), []
    for mode in modes:
        for lane in range(lanes):
            mine = user_tasks[lane::lanes]
            if not mine:
                continue
            dest = f"{roots[mode]}/lane{lane:02d}/gate"
            Path(dest).mkdir(parents=True, exist_ok=True)
            procs.append(subprocess.Popen(
                ["python", "/root/bench/agentdojo/run_gate.py", "--suite", suite, "--out", dest, "--user-tasks", *mine,
                 *NEMO_COMMON, "--gate", NANO4B, "--gate-backend", "ollama", "--human", "none",
                 *(["--gate-think"] if mode == "think" else [])],
                stdout=open(f"{dest}/stdout.txt", "w"), stderr=subprocess.STDOUT,
                env=dict(os.environ, HG_LANE_COST_CAP_USD=str(cost_cap))))
    stopped = False
    while any(p.poll() is None for p in procs):
        time.sleep(60)
        vol.commit()
        usd, line = 0.0, []
        for mode, r in roots.items():
            runs = sum(1 for _ in Path(r).rglob("agentdojo_logs/**/*.json"))
            rows = [json.loads(l) for f in Path(r).rglob("gate_log.jsonl") for l in f.read_text().splitlines() if l]
            ev: dict = {}
            for u in Path(r).rglob("usage.json"):
                try:
                    j = json.loads(u.read_text())
                except Exception:
                    continue
                usd += j.get("usd_estimate", 0)
                for k, v in j.get("events", {}).items():
                    ev[k] = ev.get(k, 0) + v
            secs = sorted(x["secs"] for x in rows)
            line.append(f"{mode}: {runs} logs, {len(rows)} reviews ({sum(x['verdict'] == 'block' for x in rows)} block, "
                        f"median {secs[len(secs) // 2] if secs else 0}s), events {ev}")
        print(f"{suite} {round((time.time() - t) / 60)} min, ${usd:.3f} brain | " + " | ".join(line), flush=True)
        if usd >= total_cap and not stopped:
            print(f"TOTAL CAP ${total_cap} reached: terminating all lanes", flush=True)
            stopped = True
            for p in procs:
                p.terminate()
    vol.commit()
    return {"rc": [p.returncode for p in procs], "minutes": round((time.time() - t) / 60, 1),
            "setup_min": round((t - t0) / 60, 1), "total_cap_hit": stopped}


@app.function(image=local_image, gpu="L4", timeout=LOCAL4B_TIMEOUT_MIN["banking"] * 60, volumes={"/results": vol},
              secrets=[modal.Secret.from_name("nebius-token-factory")])
def local4b_banking(suite, user_tasks, modes, lanes, cost_cap, total_cap, tag=""):
    return _local4b(suite, user_tasks, modes, lanes, cost_cap, total_cap, tag)


@app.function(image=local_image, gpu="L4", timeout=LOCAL4B_TIMEOUT_MIN["travel"] * 60, volumes={"/results": vol},
              secrets=[modal.Secret.from_name("nebius-token-factory")])
def local4b_travel(suite, user_tasks, modes, lanes, cost_cap, total_cap, tag=""):
    return _local4b(suite, user_tasks, modes, lanes, cost_cap, total_cap, tag)


@app.function(image=local_image, gpu="L4", timeout=LOCAL4B_TIMEOUT_MIN["smoke"] * 60, volumes={"/results": vol},
              secrets=[modal.Secret.from_name("nebius-token-factory")])
def local4b_smoke(suite, user_tasks, modes, lanes, cost_cap, total_cap, tag="_smoke"):
    return _local4b(suite, user_tasks, modes, lanes, cost_cap, total_cap, tag)


@app.local_entrypoint()
def main(suite: str = "workspace", chunks: int = 4, smoke: bool = False, replay_prompts: str = "",
         gatebench_prompts: str = "", settings: str = "", split: str = "test", nemotron: bool = False,
         lanes: int = 4, cost_cap: float = 1.2, tasks: str = "", prefix: str = "nemotron", replay_items_file: str = "",
         replay_out: str = "", local_gate: str = "", total_cap: float = 3.6, replay_think: str = "",
         think_modes: str = "off,on", probe: int = 0, local4b: str = ""):
    if local4b:
        # --local4b think | off | think,off  (--smoke: prefixes get _smoke, 25-min timeout; --tasks restricts)
        n = {"workspace": 40, "travel": 20, "banking": 16, "slack": 21}[suite]
        ids = tasks.split(",") if tasks else [f"user_task_{i}" for i in range(n)]
        modes = local4b.split(",")
        assert all(m in LOCAL4B_PREFIX for m in modes), modes
        fn = local4b_smoke if smoke else {"banking": local4b_banking, "travel": local4b_travel}[suite]
        print(fn.remote(suite, ids, modes, lanes, cost_cap, total_cap, "_smoke" if smoke else ""), flush=True)
        return
    if replay_items_file and replay_think:
        its = json.loads(Path(replay_items_file).read_text())
        out = Path(replay_out or RUNS)
        out.mkdir(parents=True, exist_ok=True)
        modes = ("on,on-json,template" if probe else think_modes).split(",")
        fns = {"4b": replay_think_l4, "30b": replay_think_l40s}
        calls = [(w, fns[w].spawn(its, w, modes, probe)) for w in replay_think.split(",")]
        for w, c in calls:
            try:
                res = c.get()
            except Exception as e:                       # e.g. timeout: rows so far are on the volume
                print(w, "FAILED", type(e).__name__, str(e)[:500], flush=True)
                continue
            (out / f"replay_think_{'probe_' if probe else ''}{w}.json").write_text(json.dumps(res, indent=1))
            print(w, res["meta"].get("gpu"), res["meta"].get("ollama"), "setup", res.get("setup_min"), "min, total",
                  res.get("total_min"), "min", "ERROR " + res["error"][-800:] if res["error"] else "", flush=True)
            print(res.get("log_tail", ""), flush=True)
        return
    if replay_items_file:
        # Nano 4B re-review of items from `replay.py ... --dump-items F`, one L4 container per prompt:
        # modal run bench/agentdojo/modal_run.py --replay-items-file F --replay-prompts v1,v2,v5 --replay-out DIR
        its = json.loads(Path(replay_items_file).read_text())
        out = Path(replay_out or RUNS)
        out.mkdir(parents=True, exist_ok=True)
        for res in replay_items.map([its] * len(replay_prompts.split(",")), replay_prompts.split(",")):
            (out / f"replay4b_{res['prompt']}.json").write_text(json.dumps(res, indent=1))
            print(res["prompt"], res["meta"], "setup", res["setup_min"], "min, total", res["total_min"], "min",
                  "ERROR " + res["error"][-500:] if res["error"] else "", flush=True)
        return
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
