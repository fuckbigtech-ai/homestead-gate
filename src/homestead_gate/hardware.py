"""What machine is this, and which reviewer model fits on it.

Detection shells out to read-only system tools (sysctl, system_profiler, nvidia-smi,
/proc/meminfo). Nothing here loads or downloads a model.

The fit rule is a port of the minimal part of fuckbigtech.ai's estimator (src/lib/fit.mjs):

  usable memory  Apple Silicon: 2/3 of unified memory at 36GB and below, 3/4 above
                 (the macOS GPU wired limit). NVIDIA: the largest card's VRAM.
                 CPU only: 80% of RAM, leaving room for the OS.
  need           weights (download size) + KV cache for an 8K context + ~1GB runtime overhead.
  verdict        need/usable <= 0.8 comfortable, <= 1.0 tight, else it does not fit.

The reviewers are the ones GateBench measured on the frozen v0.1 test split (30 attacks,
30 legitimate look-alikes, M3 Pro 18GB). The 9B is preferred; the 4B fallback is Nemotron,
not Qwen 3.5 4B, because it false-blocked fewer legitimate requests (10% vs 13%) at the
same 30/30 catch rate.
"""
from __future__ import annotations

import platform
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable

OVERHEAD_GB = 1.0
GIB = 2 ** 30


@dataclass(frozen=True)
class Reviewer:
    model: str
    weights_gb: float     # download size
    kv_per_8k_gb: float
    catch: str            # GateBench v0.1 test split
    false_blocks: str
    secs: str             # p50 per review on an M3 Pro 18GB


# qwen3.5:9b: 6.6GB and 0.5GB KV per 8K from fuckbigtech.ai src/data/fit/models.json (q4).
# nemotron-3-nano:4b: not in models.json. 2.8GB is the size Ollama reports for the tag
# (2837597147 bytes, /api/tags, 2026-09-30). KV per 8K is not published; 0.3 is the value
# models.json uses for Qwen 3.5 4B. The fallback is accepted up to "tight" so a wrong KV
# guess cannot flip the 8GB Mac case.
QWEN_9B = Reviewer("qwen3.5:9b", 6.6, 0.5, "30/30 attacks", "0/30 false blocks", "~3.5s")
NEMOTRON_4B = Reviewer("nemotron-3-nano:4b", 2.8, 0.3, "30/30 attacks", "3/30 (10%) false blocks", "~2.3s")
REVIEWERS = {r.model: r for r in (QWEN_9B, NEMOTRON_4B)}

Runner = Callable[[list[str]], str]


def _run(cmd: list[str]) -> str:
    """Run a read-only system query; empty string if the tool is missing or fails."""
    if not shutil.which(cmd[0]):
        return ""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def detect(run: Runner = _run, system: str | None = None, machine: str | None = None) -> dict:
    """Return {os, arch, ram_gb, apple_silicon, chip, gpus: [{name, vram_gb}]}."""
    system = system or platform.system()
    arch = machine or platform.machine()
    hw: dict = {"os": system, "arch": arch, "ram_gb": 0.0, "apple_silicon": False, "chip": "", "gpus": []}
    if system == "Darwin":
        mem = run(["sysctl", "-n", "hw.memsize"])
        if mem.isdigit():
            hw["ram_gb"] = round(int(mem) / GIB, 1)
        # platform.machine() says x86_64 under Rosetta, so ask the kernel.
        hw["apple_silicon"] = run(["sysctl", "-n", "hw.optional.arm64"]) == "1"
        if hw["apple_silicon"]:
            hw["arch"] = "arm64"
        chip = run(["sysctl", "-n", "machdep.cpu.brand_string"])
        if not chip:
            m = re.search(r"Chip:\s*(.+)", run(["system_profiler", "SPHardwareDataType"]))
            chip = m.group(1).strip() if m else ""
        hw["chip"] = chip
    elif system == "Linux":
        m = re.search(r"MemTotal:\s+(\d+)\s*kB", run(["cat", "/proc/meminfo"]))
        if m:
            hw["ram_gb"] = round(int(m.group(1)) * 1024 / GIB, 1)
    out = run(["nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits"])
    for line in out.splitlines():
        name, _, mib = line.rpartition(",")
        try:
            hw["gpus"].append({"name": name.strip(), "vram_gb": round(float(mib) / 1024, 1)})
        except ValueError:
            continue
    return hw


def kind(hw: dict) -> str:
    if hw.get("apple_silicon"):
        return "apple"
    if hw.get("gpus"):
        return "gpu"
    return "cpu"


def usable_memory(hw: dict) -> float:
    """GB a model can use on this machine (fit.mjs usableMemory)."""
    k = kind(hw)
    if k == "apple":
        mem = hw["ram_gb"]
        return mem * (2 / 3 if mem <= 36 else 3 / 4)
    if k == "gpu":
        return max(g["vram_gb"] for g in hw["gpus"])
    return hw.get("ram_gb", 0) * 0.8


def need_gb(r: Reviewer, context_k: int = 8) -> float:
    return r.weights_gb + r.kv_per_8k_gb * (context_k / 8) + OVERHEAD_GB


def verdict(r: Reviewer, hw: dict) -> tuple[str, float, float]:
    """(comfortable | tight | no, need GB, usable GB)."""
    need, usable = need_gb(r), usable_memory(hw)
    ratio = need / usable if usable > 0 else float("inf")
    v = "comfortable" if ratio <= 0.8 else "tight" if ratio <= 1.0 else "no"
    return v, round(need, 1), round(usable, 1)


@dataclass
class Pick:
    model: str | None
    reason: str
    reviewer: Reviewer | None = None


def pick_reviewer(hw: dict) -> Pick:
    """qwen3.5:9b if it fits comfortably, else nemotron-3-nano:4b if it fits at all, else refuse."""
    v, need, usable = verdict(QWEN_9B, hw)
    if v == "comfortable":
        return Pick(QWEN_9B.model, f"fits comfortably ({need}GB needed of {usable}GB usable). "
                    f"GateBench: {QWEN_9B.catch}, {QWEN_9B.false_blocks}, {QWEN_9B.secs} per review.", QWEN_9B)
    v4, need4, _ = verdict(NEMOTRON_4B, hw)
    if v4 != "no":
        tight = " It is a tight fit: close other apps while the gate runs." if v4 == "tight" else ""
        return Pick(NEMOTRON_4B.model,
                    f"{QWEN_9B.model} needs {need}GB and only {usable}GB is usable here, so the smaller "
                    f"reviewer ({need4}GB). GateBench: {NEMOTRON_4B.catch}, but {NEMOTRON_4B.false_blocks} "
                    f"(legitimate requests sent to you for a yes), {NEMOTRON_4B.secs} per review.{tight}",
                    NEMOTRON_4B)
    return Pick(None, f"no measured reviewer fits: the smallest ({NEMOTRON_4B.model}) needs {need4}GB and this "
                f"machine has {usable}GB usable for a model. The gate needs a local reviewer that fits, "
                "so run it on a machine with more memory.")


def describe(hw: dict) -> str:
    bits = [f"{hw['os']} {hw['arch']}", f"{hw['ram_gb']:g}GB RAM"]
    if hw.get("chip"):
        bits.append(hw["chip"])
    for g in hw.get("gpus", []):
        bits.append(f"{g['name']} {g['vram_gb']:g}GB")
    return ", ".join(bits) + f" ({usable_memory(hw):.1f}GB usable for a model)"
