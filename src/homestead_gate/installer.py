"""Setup pieces behind `homestead-gate up` and `homestead-gate doctor`.

Ollama is only ever asked three read-only questions: /api/version (is it running),
/api/tags (which models are on disk, with their manifest digests) and /api/show (the
modelfile, whose FROM line names the weights blob; pin.py). None loads a model into memory. Downloading a
model happens only through pull(), which the CLI calls only when --pull is passed, and
which goes through `model-load-guard` first when that tool is on PATH.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from importlib import resources
from pathlib import Path
from typing import Callable

from .hardware import REVIEWERS
from .policy import Policy

WALLET_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")


def example_policy() -> str:
    return resources.files("homestead_gate").joinpath("policy.example.toml").read_text()


def valid_email(s: str) -> bool:
    return bool(re.fullmatch(r"[^@\s\"]+@[^@\s\"]+\.[^@\s\"]+", s or ""))


def valid_wallet(s: str) -> bool:
    return s == "" or bool(WALLET_RE.fullmatch(s))


def model_note(model: str) -> str:
    r = REVIEWERS.get(model)
    if not r:
        return "not measured by GateBench"
    return f"GateBench: {r.catch}, {r.false_blocks}"


def render_policy(email: str, wallet: str, model: str, example: str | None = None) -> str:
    """The example policy with the user's email, wallet and reviewer model filled in.
    The whole model line is rewritten, comment included, so it never states another
    model's benchmark numbers."""
    if not valid_email(email):
        raise ValueError(f"not an email address: {email!r}")
    if not valid_wallet(wallet):
        raise ValueError(f"not a wallet address (0x + 40 hex characters): {wallet!r}")
    text = example if example is not None else example_policy()
    text = text.replace("# homestead-gate policy. Copy to ~/.homestead-gate/policy.toml and edit.",
                        "# homestead-gate policy, written by `homestead-gate up`. Edit freely.", 1)
    subs = [
        (r"^email\s*=.*$", f"email  = {json.dumps(email)}                    # mail to yourself passes without asking"),
        (r"^wallet\s*=.*$", f"wallet = {json.dumps(wallet)}    # your own address (blank: none)"),
        (r"^model\s*=.*$", f"model = {json.dumps(model)}       # {model_note(model)}"),
        # The example allowlists a placeholder; a real policy starts with nobody allowlisted.
        (r'^allow = \["accountant@example\.com"\]', "allow = []"),
    ]
    for pat, line in subs:
        text, n = re.subn(pat, lambda _m, line=line: line, text, count=1, flags=re.M)
        if n != 1:
            raise ValueError(f"example policy has no line matching {pat}")
    return text


def write_policy(path: Path, email: str, wallet: str, model: str) -> Policy:
    """Write the policy, then load it back; the load is the validation."""
    text = render_policy(email, wallet, model)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".toml.tmp")
    tmp.write_text(text)
    Policy.load(tmp)
    tmp.replace(path)
    return Policy.load(path)


# ---- Ollama (read-only) ---------------------------------------------------------------

Opener = Callable[..., object]


def _get(url: str, opener: Opener | None, timeout: float = 3) -> dict | None:
    opener = opener or urllib.request.urlopen   # looked up per call so tests can swap it
    try:
        with opener(url, timeout=timeout) as r:
            return json.loads(r.read())
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return None


def ollama_version(base: str, opener: Opener | None = None) -> str | None:
    d = _get(base.rstrip("/") + "/api/version", opener)
    return None if d is None else str(d.get("version", "?"))


def ollama_models(base: str, opener: Opener | None = None) -> list[str] | None:
    d = _get(base.rstrip("/") + "/api/tags", opener)
    if d is None:
        return None
    return [m.get("name", "") for m in d.get("models", [])]


def _norm(tag: str) -> str:
    return tag if ":" in tag else tag + ":latest"


def model_present(model: str, installed: list[str]) -> bool:
    """Exact tag match. qwen3.5:9b is not qwen3.5:9b-q8_0 or a renamed copy: the reviewer
    GateBench measured is the tag, so only the tag counts."""
    return _norm(model) in {_norm(t) for t in installed}


def install_hint(system: str) -> str:
    if system == "Darwin":
        return "brew install ollama   (or the app from https://ollama.com/download), then: ollama serve"
    if system == "Linux":
        return "curl -fsSL https://ollama.com/install.sh | sh"
    return "download it from https://ollama.com/download"


# Where to fetch a reviewer so it is the exact file our numbers were measured on (MODEL_RISK.md): the Ollama
# library's nemotron-3-nano:4b is a different file from NVIDIA's GGUF, which the AgentDojo runs used.
MEASURED_SOURCE = {"nemotron-3-nano:4b": "hf.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF:Q4_K_M"}


def pull_command(model: str) -> str:
    src = MEASURED_SOURCE.get(model)
    return f"ollama pull {src} && ollama cp {src} {model}" if src else f"ollama pull {model}"


def size_note(model: str) -> str:
    r = REVIEWERS.get(model)
    return f"{r.weights_gb:g}GB download" if r else "size unknown"


def pull(model: str, *, which: Callable[[str], str | None] | None = None,
         call: Callable[[list[str]], int] | None = None, out=print) -> int:
    """Download the model. Only reached with --pull. Refuses if model-load-guard says no."""
    which, call = which or shutil.which, call or subprocess.call
    guard = which("model-load-guard")
    if guard:
        rc = call([guard, f"ollama pull {MEASURED_SOURCE.get(model, model)}"])
        if rc != 0:
            out(f"  model-load-guard refused (exit {rc}); not pulling. Free memory/disk and retry.")
            return rc
    else:
        out("  model-load-guard not on PATH; pulling without a headroom check.")
    if not which("ollama"):
        out("  ollama is not installed; cannot pull.")
        return 1
    src = MEASURED_SOURCE.get(model, model)
    rc = call(["ollama", "pull", src])
    if rc == 0 and src != model:
        rc = call(["ollama", "cp", src, model])        # same weights, the name the policy uses
    return rc


# ---- sandbox ------------------------------------------------------------------------------

def sandbox_backend(platform: str | None = None, which: Callable[[str], str | None] | None = None) -> tuple[bool, str]:
    platform, which = platform or sys.platform, which or shutil.which
    if platform == "darwin":
        return (True, "sandbox-exec") if which("sandbox-exec") else (False, "sandbox-exec not found")
    return False, f"not available on {platform} yet (Linux bubblewrap support is planned)"
