"""Which exact model file reviews, and has it changed since you pinned it.

The reviewer is chosen by an Ollama tag (qwen3.5:9b, nemotron-3-nano:4b). A tag is a name, not a
file: `ollama pull` of the same tag next month can bring different weights or a different chat
template, and nothing would say so. So the policy pins two digests, written by
`homestead-gate reviewer pin`:

  [review] digest           sha256 of the weights blob (the GGUF file). This is what the benchmark
                            runs checked (bench/agentdojo/RESULTS.md: "the blob was checked against
                            be5d9a656a51..."), so it is what MEASURED below is keyed on.
  [review] manifest_digest  sha256 of the Ollama manifest. It changes when the template, parameters
                            or system prompt baked into the tag change, even with the same weights.

Where they come from (Ollama 0.35.0, both read-only, neither loads a model):
  GET  /api/tags   each model's manifest digest (bare hex) and size.
  POST /api/show   the modelfile, whose FROM line is the weights blob path
                   (FROM /root/.ollama/models/blobs/sha256-<hex>; seen in the 30B run's env.json).

PinnedReviewer re-reads both immediately before every review. A reviewer that is unpinned, changed,
or cannot be identified gives the verdict "invalid", which the gate treats like block: the human
decides. --allow-unpinned-reviewer reviews anyway and says so in every gate.review receipt.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable

from .policy import Policy
from .reviewer import Verdict

_BLOB_RE = re.compile(r"sha256[-:]([0-9a-f]{64})")
OVERRIDE_FLAG = "--allow-unpinned-reviewer"

Opener = Callable[..., object]


@dataclass(frozen=True)
class Identity:
    model: str
    digest: str            # sha256:<hex> of the weights blob
    manifest_digest: str   # sha256:<hex> of the Ollama manifest
    size: int              # bytes, as /api/tags reports it


class PinError(Exception):
    """The reviewer model cannot be identified. kind: unreachable | absent | unreadable."""
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class Measured:
    model: str
    file: str       # what the file is
    backs: str      # which published numbers were measured on exactly this blob
    where: str      # the RESULTS section


# Only digests a run log or RESULTS.md records. Each entry names only the numbers whose runs used
# that blob. Deliberately absent: the Ollama library's nemotron-3-nano:4b (a different file from
# NVIDIA's GGUF; no run log in this repo records its blob), and the blob behind GateBench's M3 Pro
# numbers (that run did not record one).
MEASURED = {m_digest: m for m_digest, m in (
    ("sha256:be5d9a656a51922f24f1f09a759cebb694e1f5d9728bf0ef9f8c972c5a0b5ef2", Measured(
        "nemotron-3-nano:4b",
        "Nemotron 3 Nano 4B, NVIDIA's GGUF hf.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF:Q4_K_M",
        "AgentDojo Nano 4B rows: banking thinking off and on, travel held-out, thinking replays (Ollama 0.35.0)",
        "bench/agentdojo/RESULTS.md#nano-4b-with-thinking-full-runs-banking-dev-and-travel-held-out-2026-10-02")),
    ("sha256:a70437c41b3b0b768c48737e15f8160c90f13dc963f5226aabb3a160f708d1ce", Measured(
        "nemotron-3-nano:30b",
        "Nemotron 3 Nano 30B, Ollama library nemotron-3-nano:30b (Q4_K_M)",
        "AgentDojo local Nano 30B rows and its thinking replay (Ollama 0.35.0)",
        "bench/agentdojo/RESULTS.md#nano-30b-local-4-bit-ollama-2026-10-02")),
    ("sha256:dec52a44569a2a25341c4e4d3fee25846eed4f6f0b936278e3a3c900bb99d37c", Measured(
        "qwen3.5:9b",
        "Qwen 3.5 9B, Ollama library qwen3.5:9b",
        "AgentDojo Qwen 3.5 9B banking and Slack runs (Kaggle, 2026-09-30); GateBench Modal re-runs. "
        "The GateBench M3 Pro run did not record its blob",
        "bench/agentdojo/RESULTS.md#homestead-gate-on-agentdojo")),
)}


def measured_note(digest: str) -> str:
    m = MEASURED.get(digest)
    if not m:
        return "not a measured file: no published number was measured on these exact weights"
    return f"the exact file our published numbers were measured on: {m.backs} ({m.where})"


def short(digest: str) -> str:
    return (digest or "none")[:19] + ("..." if len(digest or "") > 19 else "")


# ---- reading the identity from Ollama --------------------------------------------------------

def _norm(tag: str) -> str:
    return tag if ":" in tag else tag + ":latest"


def _call(url: str, opener: Opener | None, body: dict | None, timeout: float):
    opener = opener or urllib.request.urlopen      # looked up per call so tests can swap it
    req = url if body is None else urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    with opener(req, timeout=timeout) as r:
        return json.loads(r.read())


def read_identity(base: str, model: str, opener: Opener | None = None, timeout: float = 5) -> Identity:
    """The model file behind a tag. Two read-only calls; neither loads the model."""
    base = base.rstrip("/")
    try:
        tags = _call(base + "/api/tags", opener, None, timeout)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        raise PinError("unreachable", f"Ollama is not answering at {base} ({e})") from e
    entry = next((m for m in tags.get("models", []) if _norm(m.get("name", "")) == _norm(model)), None)
    if entry is None:
        raise PinError("absent", f"{model} is not downloaded (ollama pull {model})")
    manifest = str(entry.get("digest", "")).removeprefix("sha256:")
    try:
        show = _call(base + "/api/show", opener, {"model": model}, timeout)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
        raise PinError("unreadable", f"Ollama would not describe {model} ({e})") from e
    blob = ""
    for line in str(show.get("modelfile", "")).splitlines():
        if line.strip().upper().startswith("FROM "):
            m = _BLOB_RE.search(line)
            if m:
                blob = m.group(1)
                break
    if not re.fullmatch(r"[0-9a-f]{64}", manifest) or not blob:
        raise PinError("unreadable", f"Ollama did not report the digests of {model} "
                                     "(no manifest digest in /api/tags or no FROM blob in /api/show)")
    return Identity(model, "sha256:" + blob, "sha256:" + manifest, int(entry.get("size", 0) or 0))


# ---- comparing it with the policy -------------------------------------------------------------

@dataclass(frozen=True)
class Check:
    state: str                  # ok | unpinned | mismatch | unreadable | unreachable | absent
    message: str
    identity: Identity | None = None

    @property
    def refuse(self) -> bool:
        """Refuse to start: the model is there to review, but it is not the pinned file (or no file is
        pinned, or it cannot be identified). unreachable/absent start fail-closed instead: nothing can
        review, so every request goes to the human until the pinned model answers."""
        return self.state in ("unpinned", "mismatch", "unreadable")


def pin_command(where: str) -> str:
    return f"homestead-gate reviewer pin {where}".rstrip()


def compare(policy: Policy, ident: Identity) -> Check:
    if not policy.review_digest:
        return Check("unpinned", f"{ident.model} is not pinned: the policy names no [review] digest", ident)
    bad = []
    if ident.digest != policy.review_digest:
        bad.append(f"weights {short(ident.digest)} (pinned {short(policy.review_digest)})")
    if policy.review_manifest_digest and ident.manifest_digest != policy.review_manifest_digest:
        bad.append(f"manifest {short(ident.manifest_digest)} (pinned {short(policy.review_manifest_digest)})")
    if bad:
        return Check("mismatch", f"{ident.model} is not the pinned model file: " + "; ".join(bad), ident)
    return Check("ok", f"{ident.model} is the pinned file {short(ident.digest)}", ident)


def check(policy: Policy, opener: Opener | None = None, *, model: str | None = None,
          url: str | None = None) -> Check:
    try:
        ident = read_identity(url or policy.ollama_url, model or policy.model, opener)
    except PinError as e:
        return Check(e.kind, str(e))
    return compare(policy, ident)


def refusal(c: Check, where: str) -> str:
    """The message for a refused start: what is wrong and how to re-pin on purpose."""
    return (f"reviewer: refusing to start. {c.message}.\n"
            f"  If you changed the model on purpose, re-pin it (prints model, digest and size, and records\n"
            f"  a new canary baseline):  {pin_command(where)}\n"
            f"  To run anyway, pass {OVERRIDE_FLAG}; every review receipt then records the override.")


# ---- writing the pin into the policy ----------------------------------------------------------

def _set_review_keys(text: str, values: dict[str, str], note: str) -> str:
    lines = text.splitlines()
    head = next((i for i, l in enumerate(lines) if re.match(r"^\s*\[review\]\s*(#.*)?$", l)), None)
    if head is None:
        lines += ["", "[review]"]
        head = len(lines) - 1
    end = next((i for i in range(head + 1, len(lines)) if re.match(r"^\s*\[", lines[i])), len(lines))
    after = next((i for i in range(head + 1, end) if re.match(r"^\s*model\s*=", lines[i])), head)
    for key, val in values.items():
        line = f"{key} = {json.dumps(val)}" + (f"   # {note}" if key == "digest" else "")
        hit = next((i for i in range(head + 1, end) if re.match(rf"^\s*{key}\s*=", lines[i])), None)
        if hit is not None:
            lines[hit], after = line, hit
            continue
        after += 1
        lines.insert(after, line)
        end += 1
    return "\n".join(lines) + "\n"


def write_pin(path: Path, ident: Identity, now: float | None = None) -> Policy:
    """Pin ident's digests in the policy's [review] table. Only those two lines change; the file
    keeps its permissions (a real-mail data dir's policy is 0600). The load is the validation."""
    path = Path(path)
    when = time.strftime("%Y-%m-%d", time.localtime(now))
    note = f"{ident.model} weights, pinned {when} (homestead-gate reviewer pin)"
    text = _set_review_keys(path.read_text(), {"digest": ident.digest,
                                               "manifest_digest": ident.manifest_digest}, note)
    mode = os.stat(path).st_mode & 0o777
    tmp = path.with_suffix(path.suffix + ".pin.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, mode)
    try:
        p = Policy.load(tmp)
        if p.review_digest != ident.digest:
            raise ValueError("pin did not round-trip")
    except Exception:
        tmp.unlink(missing_ok=True)
        raise
    os.replace(tmp, path)
    return Policy.load(path)


def describe_pin(ident: Identity) -> list[str]:
    gb = f"{ident.size / 1e9:.1f}GB" if ident.size else "size unknown"
    return [f"model:    {ident.model}  ({gb})",
            f"digest:   {ident.digest}",
            f"manifest: {ident.manifest_digest}",
            f"measured: {measured_note(ident.digest)}"]


# ---- the reviewer wrapper -----------------------------------------------------------------------

class PinnedReviewer:
    """Checks, immediately before every review, that the model about to answer is the pinned file.
    Not pinned, changed, or unidentifiable: the verdict is "invalid" (the human decides) without
    asking the model, unless override is set, in which case it reviews and the receipt says so."""

    def __init__(self, inner, policy: Policy, override: bool = False, opener: Opener | None = None):
        self.inner, self.policy, self.override, self.opener = inner, policy, override, opener
        self.model = getattr(inner, "model", policy.model)

    def review(self, prompt: str) -> Verdict:
        c = check(self.policy, self.opener, model=self.model, url=getattr(self.inner, "url", None))
        base = getattr(self.inner, "receipt_meta", lambda: {})()
        meta = {**base,
                "digest": c.identity.digest if c.identity else None,
                "manifest_digest": c.identity.manifest_digest if c.identity else None,
                "pinned_digest": self.policy.review_digest or None,
                "pin_state": c.state}
        if self.override:
            meta["pin_override"] = True
        if c.state != "ok" and not self.override:
            why = (f"model {self.model!r} is not installed (ollama pull {self.model})" if c.state == "absent"
                   else f"reviewer not used: {c.message}")
            return Verdict("invalid", why, "", self.model, 0.0, meta=meta)
        v = self.inner.review(prompt)
        return replace(v, meta={**v.meta, **meta})
