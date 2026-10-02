"""Run the assistant's local reviewer (Nemotron 3 Nano 4B on Ollama) on a Modal GPU for demo recordings.

  modal run demo/modal_reviewer.py --minutes 30

Prints a temporary tunnel URL (random, gone when the function stops). Put it in the demo data dir's
policy.toml as `ollama_url` under [review]. Same model and prompt as on a laptop; only the speed
changes. In the product the reviewer runs on your own machine: this exists so a 3-minute video does
not spend 2 minutes waiting on a CPU.
"""
import modal

MODEL_SRC = "hf.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF:Q4_K_M"
MODEL = "nemotron-3-nano:4b"

image = (modal.Image.debian_slim(python_version="3.12")
         .apt_install("curl", "zstd", "ca-certificates")
         .run_commands("curl -fsSL https://ollama.com/install.sh | sh"))
app = modal.App("homestead-demo-reviewer", image=image)


@app.function(gpu="L4", timeout=3 * 3600)
def serve(minutes: int = 30):
    import subprocess, time, urllib.request
    subprocess.Popen("OLLAMA_HOST=0.0.0.0:11434 OLLAMA_KEEP_ALIVE=60m ollama serve > /tmp/ollama.log 2>&1", shell=True)
    for _ in range(60):
        try:
            urllib.request.urlopen("http://127.0.0.1:11434/api/version", timeout=2); break
        except Exception:
            time.sleep(2)
    subprocess.run(f"ollama pull {MODEL_SRC} && ollama cp {MODEL_SRC} {MODEL}", shell=True, check=True)
    subprocess.run(["ollama", "run", MODEL, "ok"], capture_output=True)          # load it once, warm
    with modal.forward(11434) as tunnel:
        print(f"REVIEWER_URL {tunnel.url}", flush=True)
        time.sleep(minutes * 60)


@app.local_entrypoint()
def main(minutes: int = 30):
    serve.remote(minutes)
