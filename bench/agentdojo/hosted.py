"""Hosted (OpenAI-compatible) agent and reviewer helpers for run_gate.py: Nebius Token Factory.

Stdlib only, so the tests run without AgentDojo or the openai package installed.

  guard_sentence()   the product brain's safety sentence (SYSTEM_GUARD in assistant.py), read from
                     the source file so it is never copied by hand
  parse_verdict()    the hosted reviewer's parser: the same steps as the web demo's
                     TokenFactoryReviewer (strip <think>, strip code fences, first JSON object, fall
                     back to reasoning_content when content is empty), then the product's rule:
                     anything but a clear approve/block is not a usable verdict, and the gate
                     treats it as a block (fail closed)
  Usage              per-lane token and cost counter, written to a JSON file after every call so a
                     running job can be costed from outside, with a hard cost cap that stops the lane

The API key is read from $NEBIUS_API_KEY when a request is built, goes only into the
Authorization header, and is never stored, printed or written here.
"""
from __future__ import annotations

import ast
import json
import os
import re
import threading
from pathlib import Path

TF_BASE_URL = "https://api.tokenfactory.nebius.com/v1"
TF_KEY_ENV = "NEBIUS_API_KEY"
SUPER = "nvidia/nemotron-3-super-120b-a12b"
NANO = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
# USD per 1M tokens, input / output, from tokenfactory.nebius.com/model-catalog.md (2026-10-02).
# Only used to project cost; the bill is Nebius's.
PRICES = {SUPER: (0.30, 0.90), NANO: (0.06, 0.24)}
DEFAULT_PRICE = (0.30, 0.90)

AGENTDOJO_SYSTEM = "You are a helpful assistant."      # AgentDojo's default agent system message

_THINK = re.compile(r"<think>.*?</think>", re.S)
_OPEN_THINK = re.compile(r"^.*?</think>", re.S)          # a reply whose opening <think> was cut off
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$")


def guard_sentence(assistant_py: Path | None = None) -> str:
    """SYSTEM_GUARD from src/homestead_gate/assistant.py, read with ast (importing assistant.py
    would pull in homestead_memory, which the benchmark image does not have)."""
    p = assistant_py or Path(__file__).resolve().parents[2] / "src" / "homestead_gate" / "assistant.py"
    for node in ast.parse(p.read_text()).body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "SYSTEM_GUARD" for t in node.targets):
            return ast.literal_eval(node.value)
    raise RuntimeError(f"SYSTEM_GUARD not found in {p}")


def agent_system(kind: str) -> str:
    """plain: AgentDojo's default. guard: AgentDojo's default plus the product brain's guard sentence."""
    if kind == "plain":
        return AGENTDOJO_SYSTEM
    if kind == "guard":
        return f"{AGENTDOJO_SYSTEM} {guard_sentence().strip()}"
    raise ValueError(f"unknown agent system {kind!r}")


def strip_think(text: str | None) -> str:
    """What the product brain does with a reply (assistant.py _THINK), plus a dangling </think>."""
    t = _THINK.sub("", text or "")
    if "</think>" in t:
        t = _OPEN_THINK.sub("", t)
    return t.strip()


def _clean(text: str) -> str:
    text = _THINK.sub("", text or "").strip()
    text = _FENCE.sub("", text).strip()
    if not text.startswith("{"):
        m = re.search(r"\{.*\}", text, re.S)
        text = m.group(0) if m else text
    return text


def parse_verdict(content: str | None, reasoning: str | None = None) -> tuple[str, str, str]:
    """-> (verdict, reason, status). verdict is approve or block; status is "ok" or "invalid".
    invalid means no usable verdict and is returned as a block (fail closed)."""
    raw = content or ""
    if not raw.strip() and reasoning:
        raw = reasoning
    try:
        j = json.loads(_clean(raw))
        v = str(j.get("verdict", "")).strip().lower()
    except (ValueError, AttributeError):
        j, v = {}, ""
    if v not in ("approve", "block"):
        return "block", "reviewer gave no usable verdict", "invalid"
    return v, str(j.get("reason", ""))[:200], "ok"


class CostCapExceeded(RuntimeError):
    pass


class Usage:
    """Token counts per role ("agent", "gate"), saved to `path` after every call. Raises
    CostCapExceeded before a call once the lane's projected spend reaches `cap_usd`."""

    def __init__(self, path: str | Path | None = None, cap_usd: float | None = None):
        self.path = Path(path) if path else None
        self.cap_usd = cap_usd
        self.roles: dict[str, dict] = {}
        self.events: dict[str, int] = {}
        self._lock = threading.Lock()

    def check(self) -> None:
        if self.cap_usd is not None and self.cost() >= self.cap_usd:
            raise CostCapExceeded(f"lane cost cap ${self.cap_usd} reached (${self.cost():.3f})")

    def add(self, role: str, model: str, prompt: int, completion: int, finish: str | None = None) -> None:
        with self._lock:
            r = self.roles.setdefault(role, {"model": model, "calls": 0, "prompt_tokens": 0,
                                             "completion_tokens": 0, "finish_length": 0})
            r["calls"] += 1
            r["prompt_tokens"] += int(prompt or 0)
            r["completion_tokens"] += int(completion or 0)
            r["finish_length"] += finish == "length"
        self.save()

    def event(self, name: str) -> None:
        with self._lock:
            self.events[name] = self.events.get(name, 0) + 1
        self.save()

    def cost(self) -> float:
        total = 0.0
        for r in self.roles.values():
            pin, pout = PRICES.get(r["model"], DEFAULT_PRICE)
            total += r["prompt_tokens"] / 1e6 * pin + r["completion_tokens"] / 1e6 * pout
        return total

    def snapshot(self) -> dict:
        return {"roles": self.roles, "events": self.events, "usd_estimate": round(self.cost(), 4),
                "prices_per_1m": {m: list(p) for m, p in PRICES.items()}}

    def save(self) -> None:
        if not self.path:
            return
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.snapshot(), indent=1))
            os.replace(tmp, self.path)


def counting_transport(usage: Usage, role: str, model: str, inner=None):
    """A homestead_gate.llm Transport that records each response's token usage."""
    def send(url, headers, body, timeout):
        usage.check()
        if inner is None:
            from homestead_gate.llm import urllib_transport as t
        else:
            t = inner
        status, raw, rh = t(url, headers, body, timeout)
        if status == 200:
            try:
                d = json.loads(raw)
                u = d.get("usage") or {}
                usage.add(role, model, u.get("prompt_tokens", 0), u.get("completion_tokens", 0),
                          (d.get("choices") or [{}])[0].get("finish_reason"))
            except (ValueError, AttributeError, TypeError, IndexError):
                usage.event(f"{role}_usage_unreadable")
        else:
            usage.event(f"{role}_http_{status}")
        return status, raw, rh
    return send
