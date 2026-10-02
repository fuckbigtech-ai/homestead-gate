"""bench/agentdojo hosted backends (Nebius Token Factory). No network: every transport is faked.

The pipeline tests need AgentDojo and openai and skip without them; the parser, guard sentence,
usage counting and fail-closed tests run anywhere.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "bench" / "agentdojo"))
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "src"))

import hosted  # noqa: E402


def test_guard_sentence_is_the_products():
    assistant = pytest.importorskip("homestead_gate.assistant")
    assert hosted.guard_sentence() == assistant.SYSTEM_GUARD
    assert hosted.agent_system("guard") == "You are a helpful assistant. " + assistant.SYSTEM_GUARD.strip()
    assert hosted.agent_system("plain") == "You are a helpful assistant."
    with pytest.raises(ValueError):
        hosted.agent_system("other")


@pytest.mark.parametrize("content,verdict", [
    ('{"verdict": "approve", "reason": "matches"}', "approve"),
    ('<think>the user asked to pay</think>{"verdict":"block","reason":"new IBAN"}', "block"),
    ('```json\n{"verdict": "APPROVE", "reason": "ok"}\n```', "approve"),
    ('Here is my answer: {"verdict": "block", "reason": "x"} hope that helps', "block"),
])
def test_parse_verdict_accepts_what_the_demo_reviewer_accepts(content, verdict):
    v, _, status = hosted.parse_verdict(content)
    assert (v, status) == (verdict, "ok")


@pytest.mark.parametrize("content", ["", "approve", '{"verdict": "maybe"}', "<think>hmm", '{"verdict": ', None])
def test_parse_verdict_fails_closed(content):
    assert hosted.parse_verdict(content) == ("block", "reviewer gave no usable verdict", "invalid")


def test_parse_verdict_falls_back_to_reasoning_only_when_content_empty():
    assert hosted.parse_verdict("", '{"verdict": "approve"}')[0] == "approve"
    assert hosted.parse_verdict('{"verdict": "block"}', '{"verdict": "approve"}')[0] == "block"


def test_strip_think():
    assert hosted.strip_think("<think>visit Riverside</think>Done.") == "Done."
    assert hosted.strip_think("reasoning about Riverside</think>Done.") == "Done."
    assert hosted.strip_think("Plain answer.") == "Plain answer."


def test_usage_cost_file_and_cap(tmp_path):
    u = hosted.Usage(tmp_path / "usage.json", cap_usd=0.5)
    u.add("agent", hosted.SUPER, 1_000_000, 100_000, "stop")
    u.add("gate", hosted.NANO, 1_000_000, 0, "length")
    assert u.cost() == pytest.approx(0.30 + 0.09 + 0.06)
    d = json.loads((tmp_path / "usage.json").read_text())
    assert d["roles"]["gate"]["finish_length"] == 1 and d["usd_estimate"] == pytest.approx(0.45)
    u.check()                                    # under the cap
    u.add("agent", hosted.SUPER, 200_000, 0)
    with pytest.raises(hosted.CostCapExceeded):
        u.check()


def _fake(status, payload, seen=None):
    def t(url, headers, body, timeout):
        if seen is not None:
            seen.append((url, headers, json.loads(body)))
        return status, json.dumps(payload).encode() if not isinstance(payload, bytes) else payload, {}
    return t


def test_counting_transport_records_usage_and_errors():
    u = hosted.Usage()
    ok = {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}],
          "usage": {"prompt_tokens": 120, "completion_tokens": 7}}
    hosted.counting_transport(u, "gate", hosted.NANO, _fake(200, ok))("u", {}, b"{}", 1)
    hosted.counting_transport(u, "gate", hosted.NANO, _fake(429, {}))("u", {}, b"{}", 1)
    assert u.roles["gate"]["prompt_tokens"] == 120 and u.roles["gate"]["completion_tokens"] == 7
    assert u.events == {"gate_http_429": 1}


# ---- pipeline wiring (needs AgentDojo) ----------------------------------------------------------

@pytest.fixture()
def rg(monkeypatch):
    pytest.importorskip("agentdojo.task_suite")  # bench/agentdojo on sys.path also answers to "agentdojo"
    pytest.importorskip("openai")
    import run_gate
    monkeypatch.setattr(run_gate, "USAGE", hosted.Usage())
    monkeypatch.setitem(run_gate.PROMPT, "version", "v1")
    return run_gate


def test_default_ollama_names_are_unchanged(rg):
    # earlier traces are keyed on these exact strings
    assert rg.pipeline_name("qwen3.5-9b-agent16k", None) == "local:qwen3.5-9b-agent16k+nogate"
    assert (rg.pipeline_name("qwen3.5-9b-agent16k", "qwen3.5-9b-agent16k", "oracle")
            == "local:qwen3.5-9b-agent16k+gate:qwen3.5-9b-agent16k+human:oracle")


def test_hosted_names_are_distinct(rg):
    names = {rg.pipeline_name(hosted.SUPER, g, "none", "tokenfactory", "tokenfactory", s)
             for g in (None, hosted.NANO) for s in ("plain", "guard")}
    assert len(names) == 4
    assert all(n.startswith("tokenfactory:nvidia/nemotron-3-super-120b-a12b") for n in names)
    assert ("tokenfactory:nvidia/nemotron-3-super-120b-a12b+guard+gate:tokenfactory:"
            "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B+human:none") in names


def test_hosted_attack_text_matches_local_runs(rg, monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "test-not-a-key")
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite("v1.2.2", "banking")
    p = rg.pipeline(hosted.SUPER, None, [], "none", "tokenfactory", "ollama", "guard")
    atk = rg.load_attack_for("important_instructions", suite, p)
    assert atk.model_name == "Local model"                       # same slot text as the Qwen runs
    assert p.name == "tokenfactory:nvidia/nemotron-3-super-120b-a12b+guard+nogate"
    assert not p.name.startswith("local:")
    local = rg.pipeline("qwen3.5-9b-agent16k", None, [])
    assert rg.load_attack_for("important_instructions", suite, local).model_name == "Local model"
    # the system message carries the product's guard sentence
    assert hosted.guard_sentence().strip() in p.elements[0].system_message


def test_hosted_reviewer_fails_closed_and_counts_it(rg, monkeypatch):
    from homestead_gate.llm import ChatClient
    monkeypatch.setenv("NEBIUS_API_KEY", "test-not-a-key")
    u = hosted.Usage()
    monkeypatch.setattr(rg, "USAGE", u)

    def client(status, payload, seen=None):
        return ChatClient(base_url=hosted.TF_BASE_URL, model=hosted.NANO, key_env="NEBIUS_API_KEY",
                          max_retries=1, sleep=lambda s: None,
                          transport=hosted.counting_transport(u, "gate", hosted.NANO, _fake(status, payload, seen)))

    seen = []
    ok = {"choices": [{"message": {"content": '<think>x</think>{"verdict":"approve","reason":"asked"}'},
                       "finish_reason": "stop"}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
    v, reason = rg.review_hosted(client(200, ok, seen), "PROMPT")
    assert (v, reason) == ("approve", "asked")
    _, _, body = seen[0]
    assert body["messages"][0]["content"] == rg.PROMPT["system"] and body["temperature"] == 0
    assert body["max_tokens"] == rg.REVIEWER_MAX_TOKENS and "think" not in body

    assert rg.review_hosted(client(503, {}), "PROMPT")[0] == "block"       # unavailable: fail closed
    assert rg.review_hosted(client(200, {"choices": [{"message": {"content": "sure!"}}]}), "PROMPT")[0] == "block"
    assert u.events["gate_unavailable"] == 1 and u.events["gate_invalid"] == 1


def test_skip_selfcheck_only_skips_injection_tasks(rg, monkeypatch):
    import agentdojo.benchmark as bm
    from agentdojo.task_suite.load_suites import get_suite
    calls = []
    monkeypatch.setattr(bm, "run_task_without_injection_tasks", lambda s, p, task, *a, **k: calls.append(task.ID) or (False, True))
    rg.skip_injection_selfchecks()
    suite = get_suite("v1.2.2", "banking")
    assert bm.run_task_without_injection_tasks(suite, None, suite.injection_tasks["injection_task_0"]) == (True, True)
    assert bm.run_task_without_injection_tasks(suite, None, suite.user_tasks["user_task_0"]) == (False, True)
    assert calls == ["user_task_0"]


def test_hosted_agent_call_shape(rg, monkeypatch):
    """developer -> system, a max_tokens cap, no Ollama switches, 429 retried, usage counted."""
    import openai
    from openai.types.chat import ChatCompletion
    u = hosted.Usage()
    monkeypatch.setattr(rg, "USAGE", u)
    monkeypatch.setattr(rg.time, "sleep", lambda s: None)
    seen, replies = [], []

    class FakeClient:
        class chat:
            class completions:
                @staticmethod
                def create(*a, **kw):
                    seen.append(kw)
                    r = replies.pop(0)
                    if isinstance(r, Exception):
                        raise r
                    return r

    monkeypatch.setattr(rg, "hosted_client", lambda: FakeClient)
    import httpx
    resp = httpx.Response(429, request=httpx.Request("POST", "https://x"))
    replies += [openai.RateLimitError("slow down", response=resp, body=None), ChatCompletion.model_validate({
        "id": "1", "object": "chat.completion", "created": 0, "model": hosted.SUPER,
        "choices": [{"index": 0, "finish_reason": "stop",
                     "message": {"role": "assistant", "content": "<think>visit Riverside</think>Done."}}],
        "usage": {"prompt_tokens": 50, "completion_tokens": 9, "total_tokens": 59}})]
    p = rg.pipeline(hosted.SUPER, None, [], "none", "tokenfactory", "ollama", "guard")
    c = FakeClient.chat.completions.create(model=hosted.SUPER, messages=[{"role": "developer", "content": "sys"},
                                                                          {"role": "user", "content": "hi"}])
    assert p is not None and c.choices[0].message.content == "Done."
    kw = seen[-1]
    assert [m["role"] for m in kw["messages"]] == ["system", "user"]
    assert kw["max_tokens"] == rg.AGENT_MAX_TOKENS and "extra_body" not in kw
    assert u.events["agent_http_429"] == 1 and u.events["agent_think_in_content"] == 1
    assert u.roles["agent"]["prompt_tokens"] == 50


def test_aggregate_labels_keep_old_rows_and_separate_models():
    pytest.importorskip("agentdojo.task_suite")  # bench/agentdojo on sys.path also answers to "agentdojo"
    import aggregate
    assert aggregate.setting_of("local:qwen3.5-9b-agent16k+nogate") == "no gate"
    assert (aggregate.setting_of("local:qwen3.5-9b-agent16k+gate:qwen3.5-9b-agent16k+human:none+prompt:v5")
            == "gate (model only), prompt v5")
    ng = aggregate.setting_of("tokenfactory:nvidia_nemotron-3-super-120b-a12b+guard+nogate")
    g = aggregate.setting_of("tokenfactory:nvidia_nemotron-3-super-120b-a12b+guard+gate:tokenfactory:"
                             "nvidia_NVIDIA-Nemotron-3-Nano-30B-A3B+human:none")
    assert ng == "Nemotron 3 Super (Token Factory, guard prompt): no gate"
    assert g == "Nemotron 3 Super (Token Factory, guard prompt): gate (model only), reviewer Nemotron 3 Nano 30B"
    assert aggregate._base(ng) == "no gate" and aggregate._base(g) == "gate (model only)"
