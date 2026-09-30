"""Run the AgentDojo defense benchmark on Modal GPUs, split by user task. Mirrors the Kaggle kernel:
same run_gate.py, same frozen reviewer prompt, qwen3.5:9b at 16k context as both agent and gate.

  modal run bench/agentdojo/modal_run.py --suite workspace --chunks 4           # full suite, 4 GPUs
  modal run bench/agentdojo/modal_run.py --suite workspace --smoke              # 1 task, gate only
  modal volume get agentdojo-results workspace ./results_workspace              # fetch results

Each chunk runs all three settings (no gate; gate, model only; gate + oracle human) on its slice
of user tasks and writes to the agentdojo-results volume, so a dead container loses one slice only.
"""
from pathlib import Path

import modal

HERE = Path(__file__).resolve().parent
MODEL, AGENT = "qwen3.5:9b", "qwen3.5-9b-agent16k"
SETTINGS = {"nogate": [], "gate": ["--gate", AGENT, "--human", "none"],
            "gate_oracle": ["--gate", AGENT, "--human", "oracle"]}

image = (modal.Image.debian_slim(python_version="3.12")
         .apt_install("curl", "zstd", "ca-certificates")
         .run_commands("curl -fsSL https://ollama.com/install.sh | sh")
         .pip_install("agentdojo==0.1.35", "openai")
         .add_local_file(HERE.parent / "review.py", "/root/bench/review.py")
         .add_local_file(HERE / "run_gate.py", "/root/bench/agentdojo/run_gate.py"))
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

@app.local_entrypoint()
def main(suite: str = "workspace", chunks: int = 4, smoke: bool = False):
    n = {"workspace": 40, "travel": 20, "banking": 16, "slack": 21}[suite]    # user tasks in v1.2.2
    ids = [f"user_task_{i}" for i in range(n)]
    if smoke:
        print(run_chunk.remote(suite, 99, ids[:1], ["gate"]))
        return
    slices = [ids[i::chunks] for i in range(chunks)]     # interleaved, so chunks take similar time
    for res in run_chunk.starmap([(suite, i, s, list(SETTINGS)) for i, s in enumerate(slices)]):
        print(res)
