"""A minimal OpenAI-compatible chat client with tool calling, for the assistant's cloud brain.

Stdlib only (urllib), like the rest of the gate. Two presets:

  nim           NVIDIA's hosted endpoint, Nemotron 3 Super. Key from $NVIDIA_API_KEY.
  tokenfactory  Nebius Token Factory. It speaks the same OpenAI chat API, but we have no
                account yet, so its base URL and model are placeholders. Set them with
                $HG_TOKENFACTORY_BASE_URL and $HG_TOKENFACTORY_MODEL (or --base-url / --llm-model)
                and the key with $NEBIUS_API_KEY. The client refuses to send anything while a
                placeholder is still in place.

The key is read when a request is built and goes only into the Authorization header. It is
never stored on the client, printed, logged, put in an exception or written to a receipt.
Pass `api_key=` a callable to fetch it from a credential store instead of the environment.

Retries: 429 and 5xx (and connection errors) are retried with exponential backoff, honouring
Retry-After when the server sends one. Any other HTTP error is raised at once.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

TODO = "TODO"     # marks a value we do not know yet; the client will not send while one is set


@dataclass(frozen=True)
class Backend:
    name: str
    base_url: str
    model: str
    key_env: str
    base_url_env: str | None = None     # env var that overrides base_url (read at use, not import)
    model_env: str | None = None


PRESETS = {
    "nim": Backend("nim", "https://integrate.api.nvidia.com/v1",
                   "nvidia/nemotron-3-super-120b-a12b", "NVIDIA_API_KEY"),
    # TODO(token-factory): fill in once the Nebius account exists. Both values are placeholders.
    "tokenfactory": Backend("tokenfactory", f"{TODO}-token-factory-base-url", f"{TODO}-token-factory-model",
                            "NEBIUS_API_KEY", base_url_env="HG_TOKENFACTORY_BASE_URL",
                            model_env="HG_TOKENFACTORY_MODEL"),
}


class LLMError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


# (url, headers, body bytes, timeout) -> (status, response bytes, headers). Tests replace it.
Transport = Callable[[str, dict, bytes, float], tuple[int, bytes, dict]]


def urllib_transport(url: str, headers: dict, body: bytes, timeout: float) -> tuple[int, bytes, dict]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read() or b"", dict(e.headers or {})


def _retry_after(headers: dict) -> float | None:
    for k, v in headers.items():
        if k.lower() == "retry-after":
            try:
                return max(0.0, float(v))
            except (TypeError, ValueError):
                return None
    return None


class ChatClient:
    def __init__(self, *, base_url: str, model: str, api_key: str | Callable[[], str] | None = None,
                 key_env: str | None = None, transport: Transport | None = None,
                 timeout_s: float = 120, max_retries: int = 4, backoff_s: float = 1.0,
                 sleep: Callable[[float], None] = time.sleep, extra_body: dict | None = None):
        self.base_url, self.model = base_url.rstrip("/"), model
        # Hold a way to GET the key, never the key itself, so it cannot end up in vars(), a
        # repr, a pickle or a traceback's locals of some unrelated frame.
        if callable(api_key):
            self._key_fn = api_key
        elif api_key is not None:
            self._key_fn = (lambda k=api_key: k)
        elif key_env:
            self._key_fn = lambda: os.environ.get(key_env, "")
        else:
            self._key_fn = lambda: ""
        self.key_env = key_env
        self.transport, self.timeout_s = transport, timeout_s     # None: urllib_transport, looked up per call
        self.max_retries, self.backoff_s, self.sleep = max_retries, backoff_s, sleep
        self.extra_body = dict(extra_body or {})

    @classmethod
    def from_preset(cls, name: str, *, base_url: str | None = None, model: str | None = None,
                    api_key: str | Callable[[], str] | None = None, **kw) -> "ChatClient":
        if name not in PRESETS:
            raise ValueError(f"unknown backend {name!r}; choose one of {', '.join(PRESETS)}")
        p = PRESETS[name]
        env_url = os.environ.get(p.base_url_env, "") if p.base_url_env else ""
        env_model = os.environ.get(p.model_env, "") if p.model_env else ""
        return cls(base_url=base_url or env_url or p.base_url, model=model or env_model or p.model,
                   api_key=api_key,
                   key_env=p.key_env, **kw)

    def __repr__(self) -> str:
        return f"ChatClient(base_url={self.base_url!r}, model={self.model!r})"

    def check_ready(self) -> None:
        """Refuse before any request when config is a placeholder or the key is missing."""
        if TODO in self.base_url or TODO in self.model:
            raise LLMError("backend not configured: base URL or model is still a TODO placeholder "
                           "(set --base-url and --llm-model, or HG_TOKENFACTORY_BASE_URL and "
                           "HG_TOKENFACTORY_MODEL)")
        if not self._key_fn():
            raise LLMError(f"no API key: set ${self.key_env}" if self.key_env else "no API key")

    def chat(self, messages: list[dict], tools: list[dict] | None = None, *,
             temperature: float = 0.2, max_tokens: int = 1024) -> dict:
        """One chat completion. Returns choices[0].message (role, content, maybe tool_calls)."""
        self.check_ready()
        payload: dict[str, Any] = {"model": self.model, "messages": messages,
                                   "temperature": temperature, "max_tokens": max_tokens, **self.extra_body}
        if tools:
            payload["tools"], payload["tool_choice"] = tools, "auto"
        body = json.dumps(payload).encode()
        url = f"{self.base_url}/chat/completions"
        attempt = 0
        while True:
            headers = {"Content-Type": "application/json", "Accept": "application/json",
                       "Authorization": f"Bearer {self._key_fn()}"}
            try:
                send = self.transport or urllib_transport
                status, raw, rh = send(url, headers, body, self.timeout_s)
            except (urllib.error.URLError, TimeoutError, OSError) as e:
                status, raw, rh, neterr = 0, b"", {}, type(e).__name__
            else:
                neterr = None
            del headers   # nothing below may see the key
            if status == 200:
                try:
                    return json.loads(raw)["choices"][0]["message"]
                except (ValueError, KeyError, IndexError, TypeError) as e:
                    raise LLMError(f"unexpected response shape ({type(e).__name__})", status) from None
            retryable = neterr is not None or status == 429 or 500 <= status < 600
            if not retryable or attempt >= self.max_retries:
                why = f"network error {neterr}" if neterr else f"HTTP {status}: {self._excerpt(raw)}"
                raise LLMError(f"chat request failed after {attempt + 1} attempt(s): {why}", status or None)
            wait = _retry_after(rh)
            self.sleep(wait if wait is not None else self.backoff_s * (2 ** attempt))
            attempt += 1

    def _excerpt(self, raw: bytes) -> str:
        """A short, key-scrubbed slice of an error body. Some servers echo the header back."""
        text = raw[:300].decode("utf-8", "replace").replace("\n", " ")
        key = self._key_fn()
        return text.replace(key, "[redacted]") if key else text
