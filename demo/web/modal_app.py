"""Serve the web demo on Modal as a CPU web endpoint. NOT RUN YET: deploying is a human decision.

  modal secret create nebius-token-factory NEBIUS_API_KEY=...   # once, by a human
  modal deploy demo/web/modal_app.py                            # run from the repo root

The models run elsewhere (Nebius Token Factory), so this container needs no GPU. Sessions live in
memory, so there is exactly one container (max_containers=1); a second one would not know the
first one's sessions or rate limits. Email is always dry-run and payments are unsigned testnet
transactions, as in the local demo.
"""
from pathlib import Path

import modal

# Repo root (src/ and demo/ live here). Only meaningful on the deploying machine: inside the container this
# file is /root/modal_app.py and the code is already copied to /app.
ROOT = Path(__file__).resolve().parents[2] if modal.is_local() else Path("/app")
PORT = 8000

image = (modal.Image.debian_slim(python_version="3.12")
         .pip_install("homestead-memory>=0.4.0")
         .env({"PYTHONPATH": "/app/src:/app", "PYTHONUNBUFFERED": "1",
               "DEMO_REVIEWER": "tokenfactory"})
         .add_local_dir(ROOT / "src", "/app/src", ignore=["**/__pycache__"])
         .add_local_dir(ROOT / "demo" / "web", "/app/demo/web", ignore=["**/__pycache__"]))

app = modal.App("homestead-web-demo", image=image)


@app.function(secrets=[modal.Secret.from_name("nebius-token-factory")], cpu=1.0, memory=1024,
              max_containers=1, timeout=24 * 3600)
@modal.concurrent(max_inputs=100)
@modal.web_server(PORT, startup_timeout=60)
def web():
    import subprocess
    subprocess.Popen(["python", "-m", "demo.web.server", "--host", "0.0.0.0", "--port", str(PORT)], cwd="/app")
