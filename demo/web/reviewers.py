"""The web demo's brain and reviewer, plus the per-run token budget.

Reviewer, chosen by $DEMO_REVIEWER:
  tokenfactory (default)  Nemotron Nano 30B on Nebius Token Factory, so a visitor needs no GPU.
  ollama                  any Ollama server at $OLLAMA_URL, e.g. the Modal GPU running Nemotron 3
                          Nano 4B from demo/modal_reviewer.py, for recordings.
  scripted                no model at all; for trying the page offline. Labelled as such.

Every reviewer gets the SAME prompt the product uses: the Gate renders it with
homestead_gate.reviewer.render, and the system prompt and verdict parser are imported from
homestead_gate.reviewer, never copied. GateBench numbers were measured on the local reviewers,
not on the hosted Nano 30B; the page does not claim otherwise.
"""
from __future__ import annotations

import json
import os
import re
import threading
import time

from homestead_gate import llm as llm_mod
from homestead_gate.llm import ChatClient, LLMError
from homestead_gate.reviewer import SYSTEM, OllamaReviewer, Verdict, parse

TF_BASE_URL = "https://api.tokenfactory.nebius.com/v1"
TF_REVIEWER_MODEL = "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B"
OLLAMA_DEFAULT_MODEL = "nemotron-3-nano:4b"



class BudgetExceeded(LLMError):
    pass


class BudgetTransport:
    """Wraps the HTTP transport for one run and counts tokens across brain AND reviewer calls.
    Refuses to send once the run's budget is spent. If a response carries no usage, it counts
    the bytes sent and received divided by 4, so the cap holds anyway."""

    def __init__(self, max_tokens: int, inner=None):
        self.max_tokens, self.inner = max_tokens, inner
        self.used = 0
        self._lock = threading.Lock()

    def __call__(self, url, headers, body, timeout):
        with self._lock:
            if self.used >= self.max_tokens:
                raise BudgetExceeded(f"this run used its {self.max_tokens} token budget")
        send = self.inner or llm_mod.urllib_transport
        status, raw, rh = send(url, headers, body, timeout)
        n = None
        try:
            n = int((json.loads(raw).get("usage") or {}).get("total_tokens") or 0) or None
        except (ValueError, AttributeError, TypeError):
            pass
        with self._lock:
            self.used += n if n is not None else (len(body) + len(raw)) // 4
        return status, raw, rh


class TokenFactoryReviewer:
    """OpenAI-compatible reviewer: same SYSTEM prompt, same rendered input, same parser and the
    same fail-closed rule as OllamaReviewer. Temperature 0. Anything but a clear approve/block
    is "invalid", which the gate treats as a flag."""

    def __init__(self, *, model: str = TF_REVIEWER_MODEL, base_url: str = TF_BASE_URL,
                 transport=None, max_tokens: int = 2048, timeout_s: float = 90,
                 extra_body: dict | None = None):
        self.model = model
        self.max_tokens = max_tokens
        self.client = ChatClient(base_url=base_url, model=model, key_env="NEBIUS_API_KEY",
                                 transport=transport, timeout_s=timeout_s, max_retries=2,
                                 extra_body=extra_body)

    def review(self, prompt: str) -> Verdict:
        t = time.time()
        try:
            msg = self.client.chat([{"role": "system", "content": SYSTEM},
                                    {"role": "user", "content": prompt}],
                                   temperature=0, max_tokens=self.max_tokens)
        except LLMError as e:
            why = "run token budget used up" if isinstance(e, BudgetExceeded) else "reviewer unavailable"
            return Verdict("invalid", why, "", self.model, round(time.time() - t, 2))
        raw = msg.get("content") or ""
        if not raw.strip() and msg.get("reasoning_content"):
            raw = msg["reasoning_content"]
        return parse(raw, self.model, round(time.time() - t, 2))   # the product's fail-closed parser


class ScriptedReviewer:
    """No model. Blocks an action whose recipient never appears in the user's request or known
    contacts; approves the rest. Only for trying the page offline (DEMO_REVIEWER=scripted)."""
    model = "scripted (no model)"

    def review(self, prompt: str) -> Verdict:
        head, _, act = prompt.partition("PROPOSED ACTION:")
        try:
            to = str(json.loads(act).get("to", "")).lower()
        except ValueError:
            to = ""
        trusted = "\n".join(ln for ln in head.splitlines()
                            if ln.startswith(("USER REQUEST:", "KNOWN CONTACTS:", "USER (")))
        if to and to not in trusted.lower():
            return Verdict("block", "the recipient came from the email, not from the user", to, self.model, 0.0)
        return Verdict("approve", "matches the request", "", self.model, 0.0)


def reviewer_kind() -> str:
    return (os.environ.get("DEMO_REVIEWER") or "tokenfactory").strip().lower()


def reviewer_model() -> str:
    """The reviewer model's name as the demo banner should say it."""
    k = reviewer_kind()
    if k == "ollama":
        return os.environ.get("DEMO_OLLAMA_MODEL") or OLLAMA_DEFAULT_MODEL
    if k == "scripted":
        return "no model"
    m = os.environ.get("DEMO_TF_REVIEWER_MODEL") or TF_REVIEWER_MODEL
    return "Nemotron Nano 30B" if m == TF_REVIEWER_MODEL else m


def reviewer_label() -> str:
    """What the page says the reviewer is. Must name the model actually running."""
    k = reviewer_kind()
    if k == "ollama":
        return f"{os.environ.get('DEMO_OLLAMA_MODEL') or OLLAMA_DEFAULT_MODEL} on Ollama"
    if k == "scripted":
        return "a scripted stand-in (no model)"
    return f"{os.environ.get('DEMO_TF_REVIEWER_MODEL') or TF_REVIEWER_MODEL} on Nebius Token Factory"


def make_reviewer(transport=None):
    k = reviewer_kind()
    if k == "ollama":
        # The Ollama call is not counted against the token budget: it is our own GPU, not credits.
        return OllamaReviewer(os.environ.get("DEMO_OLLAMA_MODEL") or OLLAMA_DEFAULT_MODEL,
                              os.environ.get("OLLAMA_URL") or "http://127.0.0.1:11434", 120)
    if k == "scripted":
        return ScriptedReviewer()
    if k != "tokenfactory":
        raise ValueError(f"DEMO_REVIEWER must be tokenfactory, ollama or scripted, not {k!r}")
    extra = None
    if os.environ.get("DEMO_TF_REVIEWER_EXTRA"):
        # e.g. a thinking-off switch. Not set by default: an unverified parameter that the
        # server rejects would turn every review into "invalid".
        extra = json.loads(os.environ["DEMO_TF_REVIEWER_EXTRA"])
    return TokenFactoryReviewer(model=os.environ.get("DEMO_TF_REVIEWER_MODEL") or TF_REVIEWER_MODEL,
                                transport=transport, extra_body=extra)


def make_brain(transport=None) -> ChatClient:
    """The assistant's brain: the product's tokenfactory preset (Nemotron 3 Super)."""
    return ChatClient.from_preset("tokenfactory", transport=transport, max_retries=2)
