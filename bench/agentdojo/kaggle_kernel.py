#!/usr/bin/env python3
"""Build a private Kaggle kernel (T4) that runs job.sh with this checkout's run_gate.py and review.py embedded.

  python kaggle_kernel.py NAME --run banking:16 --run slack:21 --settings gate_v5 [--out DIR]
  kaggle kernels push -p DIR/NAME

Results land in /kaggle/working/res/<suite>/<setting>/laneN/ and come back with `kaggle kernels output`.
"""
import argparse, base64, hashlib, json
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("--run", action="append", required=True, help="suite:n_user_tasks, repeatable")
    ap.add_argument("--settings", required=True, help="space- or comma-separated job.sh settings")
    ap.add_argument("--lanes", default="3")
    ap.add_argument("--out", default=str(Path.home() / "hg-runs" / "kaggle-kernels"))
    a = ap.parse_args()
    files = {"job.sh": HERE / "job.sh", "bench/agentdojo/run_gate.py": HERE / "run_gate.py",
             "bench/review.py": HERE.parent / "review.py"}
    blobs = {k: base64.b64encode(p.read_bytes()).decode() for k, p in files.items()}
    shas = {k: hashlib.sha256(p.read_bytes()).hexdigest()[:12] for k, p in files.items()}
    runs = [(s.split(":")[0], int(s.split(":")[1])) for s in a.run]
    settings = " ".join(a.settings.replace(",", " ").split())
    src = f'''"""homestead-gate x AgentDojo ({a.name}): {runs} settings={settings!r}. Files sha256: {shas}"""
import base64, os, subprocess
os.chdir("/kaggle/working")
for path, blob in {json.dumps(blobs)}.items():
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "wb").write(base64.b64decode(blob))
for suite, n in {runs!r}:
    tasks = " ".join(f"user_task_{{i}}" for i in range(n))
    subprocess.run(["bash", "job.sh"], env=dict(os.environ, SUITE=suite, TASKS=tasks, SETTINGS={settings!r},
                                                  LANES={a.lanes!r}, RES=f"/kaggle/working/res/{{suite}}"))
'''
    d = Path(a.out) / a.name
    d.mkdir(parents=True, exist_ok=True)
    (d / "kernel.py").write_text(src)
    (d / "kernel-metadata.json").write_text(json.dumps({
        "id": f"fuckbigtechai/homestead-gate-agentdojo-{a.name}", "title": f"homestead-gate agentdojo {a.name}",
        "code_file": "kernel.py", "language": "python", "kernel_type": "script", "is_private": True,
        "enable_gpu": True, "enable_internet": True, "accelerator": "nvidiaTeslaT4",
        "dataset_sources": [], "competition_sources": [], "kernel_sources": []}, indent=1))
    print(d, shas)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
