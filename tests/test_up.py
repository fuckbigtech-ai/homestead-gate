"""`homestead-gate up` / `doctor` and the hardware fit. Fakes only: no network, no model,
no subprocess. Every test that runs the CLI goes through the `env` fixture, which makes any
Ollama call other than /api/version, /api/tags and /api/show (none loads a model), and any
subprocess, fail the test."""
import io
import json
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from homestead_memory.core import ledger as hl

from homestead_gate import cli, hardware, installer, pin
from homestead_gate.cli import main as cli_main
from homestead_gate.policy import Policy

ROOT = Path(__file__).resolve().parents[1]
WALLET = "0x" + "1" * 40


def write_pinned(env, model, email="me@example.com"):
    """An existing policy whose reviewer was pinned against what the fake Ollama has on disk."""
    installer.write_policy(env.pol, email, "", model)
    env.ollama.tags = [model]
    return pin.write_pin(env.pol, pin.read_identity("http://127.0.0.1:11434", model))


def mac(gb, chip="Apple M3 Pro"):
    return {"os": "Darwin", "arch": "arm64", "ram_gb": gb, "apple_silicon": True, "chip": chip, "gpus": []}


def nvidia(vram, ram=32):
    return {"os": "Linux", "arch": "x86_64", "ram_gb": ram, "apple_silicon": False, "chip": "",
            "gpus": [{"name": "NVIDIA GeForce RTX 4080", "vram_gb": vram}]}


# ---- hardware fit ---------------------------------------------------------------------------

def test_8gb_mac_gets_nemotron_with_its_false_block_rate():
    p = hardware.pick_reviewer(mac(8))
    assert p.model == "nemotron-3-nano:4b"
    assert "10%" in p.reason and "false blocks" in p.reason
    assert hardware.verdict(hardware.QWEN_9B, mac(8)) == ("no", 8.1, 5.3)
    assert hardware.verdict(hardware.NEMOTRON_4B, mac(8)) == ("comfortable", 4.1, 5.3)


def test_18gb_mac_gets_the_9b():
    p = hardware.pick_reviewer(mac(18))
    assert p.model == "qwen3.5:9b"
    assert hardware.verdict(hardware.QWEN_9B, mac(18)) == ("comfortable", 8.1, 12.0)


def test_16gb_nvidia_gets_the_9b():
    assert hardware.pick_reviewer(nvidia(16)).model == "qwen3.5:9b"
    assert hardware.usable_memory(nvidia(16)) == 16


def test_4gb_refuses():
    for hw in (mac(4), nvidia(4, ram=8), {"os": "Linux", "arch": "x86_64", "ram_gb": 4,
                                          "apple_silicon": False, "chip": "", "gpus": []}):
        p = hardware.pick_reviewer(hw)
        assert p.model is None and "no measured reviewer fits" in p.reason


def test_usable_memory_rule_matches_fit_mjs():
    assert hardware.usable_memory(mac(36)) == pytest.approx(24.0)       # 2/3 at 36GB and below
    assert hardware.usable_memory(mac(48)) == pytest.approx(36.0)       # 3/4 above
    cpu = {"os": "Linux", "arch": "x86_64", "ram_gb": 10, "apple_silicon": False, "gpus": []}
    assert hardware.usable_memory(cpu) == pytest.approx(8.0)


def test_nemotron_accepted_when_tight():
    # need 4.1 vs usable 4.67 on a 7GB Mac: ratio 0.88, tight but it fits.
    p = hardware.pick_reviewer(mac(7))
    assert p.model == "nemotron-3-nano:4b" and "tight" in p.reason


def fake_runner(answers):
    calls = []

    def run(cmd):
        calls.append(cmd)
        return answers.get(" ".join(cmd), "")
    return run, calls


def test_detect_apple_silicon():
    run, _ = fake_runner({"sysctl -n hw.memsize": "19327352832", "sysctl -n hw.optional.arm64": "1",
                          "sysctl -n machdep.cpu.brand_string": "Apple M3 Pro"})
    hw = hardware.detect(run, system="Darwin", machine="x86_64")     # Rosetta says x86_64
    assert hw["ram_gb"] == 18.0 and hw["apple_silicon"] and hw["arch"] == "arm64"
    assert hw["chip"] == "Apple M3 Pro" and hw["gpus"] == []


def test_detect_chip_falls_back_to_system_profiler():
    run, calls = fake_runner({"sysctl -n hw.memsize": str(8 * 2 ** 30), "sysctl -n hw.optional.arm64": "1",
                              "system_profiler SPHardwareDataType": "Hardware:\n      Chip: Apple M1\n"})
    hw = hardware.detect(run, system="Darwin", machine="arm64")
    assert hw["chip"] == "Apple M1" and hw["ram_gb"] == 8.0
    assert ["system_profiler", "SPHardwareDataType"] in calls


def test_detect_linux_nvidia():
    run, _ = fake_runner({"cat /proc/meminfo": "MemTotal:       32768000 kB\n",
                          "nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits":
                              "NVIDIA GeForce RTX 4080, 16376\nNVIDIA GeForce RTX 3060, 12288"})
    hw = hardware.detect(run, system="Linux", machine="x86_64")
    assert hw["ram_gb"] == 31.2
    assert hw["gpus"] == [{"name": "NVIDIA GeForce RTX 4080", "vram_gb": 16.0},
                          {"name": "NVIDIA GeForce RTX 3060", "vram_gb": 12.0}]
    assert hardware.pick_reviewer(hw).model == "qwen3.5:9b"


# ---- policy writing --------------------------------------------------------------------------

def test_packaged_example_is_the_repo_example():
    assert installer.example_policy() == (ROOT / "policy.example.toml").read_text()


def test_render_policy_fills_fields_and_loads(tmp_path):
    p = installer.write_policy(tmp_path / "policy.toml", "me@example.com", WALLET, "nemotron-3-nano:4b")
    assert (p.user_email, p.user_wallet, p.model) == ("me@example.com", WALLET, "nemotron-3-nano:4b")
    text = (tmp_path / "policy.toml").read_text()
    model_line = next(l for l in text.splitlines() if l.startswith("model"))
    assert "10%" in model_line and "0/30 false blocks" not in model_line   # never another model's numbers
    assert p.email_allow == [] and "accountant@example.com" not in text   # no placeholder allowlist
    assert "daily_auto_value_eth = 0.035" in text and p.max_value_eth == 0.05


def test_render_policy_rejects_bad_input():
    with pytest.raises(ValueError):
        installer.render_policy("not-an-email", "", "qwen3.5:9b")
    with pytest.raises(ValueError):
        installer.render_policy("me@example.com", "0x123", "qwen3.5:9b")
    with pytest.raises(ValueError):   # quotes cannot break out of the TOML string
        installer.render_policy('me"@x.com', "", "qwen3.5:9b")


def test_model_present_is_exact():
    tags = ["qwen3.5-9b-gatebench:latest", "qwen3.5:9b-q8_0", "nemotron-3-nano:4b", "llama3"]
    assert not installer.model_present("qwen3.5:9b", tags)
    assert installer.model_present("nemotron-3-nano:4b", tags)
    assert installer.model_present("llama3:latest", tags) and installer.model_present("llama3", tags)


# ---- pull ------------------------------------------------------------------------------------

def test_pull_goes_through_the_guard_and_stops_on_refusal():
    calls = []
    rc = installer.pull("qwen3.5:9b", which=lambda n: f"/bin/{n}",
                        call=lambda c: (calls.append(c), 1)[1], out=lambda s: None)
    assert rc == 1 and calls == [["/bin/model-load-guard", "ollama pull qwen3.5:9b"]]


def test_pull_after_guard_allows():
    calls = []
    rc = installer.pull("qwen3.5:9b", which=lambda n: f"/bin/{n}",
                        call=lambda c: (calls.append(c), 0)[1], out=lambda s: None)
    assert rc == 0 and calls[-1] == ["ollama", "pull", "qwen3.5:9b"]


def test_pull_without_guard_says_so():
    calls, said = [], []
    installer.pull("qwen3.5:9b", which=lambda n: None if n == "model-load-guard" else f"/bin/{n}",
                   call=lambda c: (calls.append(c), 0)[1], out=said.append)
    assert calls == [["ollama", "pull", "qwen3.5:9b"]] and "model-load-guard not on PATH" in said[0]


# ---- the CLI, with fakes ---------------------------------------------------------------------

from fake_ollama import FakeOllama  # noqa: E402  (/api/version, /api/tags, /api/show; nothing that loads)


@pytest.fixture
def env(tmp_path, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError(f"no subprocess in tests: {a}")
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "call", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(cli, "HOME", tmp_path / "home")
    monkeypatch.setattr(hardware, "detect", lambda *a, **k: mac(18))
    ollama = FakeOllama()
    monkeypatch.setattr(urllib.request, "urlopen", ollama)
    served = []
    monkeypatch.setattr(cli, "_serve", lambda policy, a, task, smtp=None: served.append((policy, task)) or 0)
    monkeypatch.setattr(installer, "sandbox_backend", lambda: (True, "sandbox-exec"))

    class E:
        pass
    e = E()
    e.pol, e.led, e.ollama, e.served, e.mp = tmp_path / "policy.toml", tmp_path / "ledger", ollama, served, monkeypatch
    e.args = ["--policy", str(e.pol), "--ledger", str(e.led)]
    return e


def test_dry_run_writes_nothing_and_prints_the_pull_command(env, capsys):
    rc = cli_main(["up", "--yes", "--email", "t@example.com", "--dry-run", *env.args])
    out = capsys.readouterr().out
    assert rc == 0 and not env.pol.exists() and env.served == []
    assert "ollama pull qwen3.5:9b  (6.6GB download)" in out and "Apple M3 Pro" in out
    assert all(u.endswith(("/api/version", "/api/tags")) for u in env.ollama.urls)


def test_pull_is_ignored_in_a_dry_run(env, capsys, monkeypatch):
    monkeypatch.setattr(installer, "pull", lambda m: pytest.fail("pulled in a dry run"))
    assert cli_main(["up", "--yes", "--email", "t@example.com", "--dry-run", "--pull", *env.args]) == 0
    assert "--pull ignored in a dry run" in capsys.readouterr().out


def test_up_yes_writes_policy_and_starts(env, capsys):
    env.ollama.tags = ["qwen3.5:9b"]
    rc = cli_main(["up", "--yes", "--email", "t@example.com", "--wallet", WALLET, "--task", "email me", *env.args])
    assert rc == 0
    p = Policy.load(env.pol)
    assert (p.user_email, p.user_wallet, p.model) == ("t@example.com", WALLET, "qwen3.5:9b")
    assert env.served and env.served[0][1] == "email me"
    assert "WARNING" not in capsys.readouterr().out


def test_up_picks_nemotron_on_8gb(env, capsys):
    env.mp.setattr(hardware, "detect", lambda *a, **k: mac(8))
    cli_main(["up", "--yes", "--email", "t@example.com", "--task", "x", *env.args])
    assert Policy.load(env.pol).model == "nemotron-3-nano:4b"
    out = capsys.readouterr().out
    assert "10%" in out and ("ollama pull hf.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF:Q4_K_M && ollama cp "
            "hf.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF:Q4_K_M nemotron-3-nano:4b  (2.8GB download)") in out and "WARNING" in out


def test_up_refuses_on_4gb(env, capsys):
    env.mp.setattr(hardware, "detect", lambda *a, **k: mac(4))
    assert cli_main(["up", "--yes", "--email", "t@example.com", "--task", "x", *env.args]) == 1
    assert not env.pol.exists() and env.served == []
    assert "refusing" in capsys.readouterr().err


def test_up_refuses_a_forced_model_that_does_not_fit(env, capsys):
    env.mp.setattr(hardware, "detect", lambda *a, **k: mac(4))
    assert cli_main(["up", "--yes", "--email", "t@example.com", "--task", "x", "--model", "qwen3.5:9b",
                     *env.args]) == 1
    assert not env.pol.exists() and env.served == []


def test_up_refuses_an_existing_policy_model_that_does_not_fit(env, capsys):
    installer.write_policy(env.pol, "me@example.com", "", "qwen3.5:9b")   # copied from a bigger machine
    env.ollama.tags = ["qwen3.5:9b"]
    env.mp.setattr(hardware, "detect", lambda *a, **k: mac(8))
    assert cli_main(["up", "--task", "x", *env.args]) == 1
    assert env.served == []
    assert "Use nemotron-3-nano:4b instead" in capsys.readouterr().err


def test_up_unmeasured_model_is_not_fit_checked(env, capsys):
    env.ollama.tags = ["llama3:latest"]
    assert cli_main(["up", "--yes", "--email", "t@example.com", "--task", "x", "--model", "llama3",
                     *env.args]) == 0
    assert "fit unknown for llama3" in capsys.readouterr().out


def test_up_interactive(env, monkeypatch):
    env.ollama.tags = ["qwen3.5:9b"]
    answers = iter(["me@example.com", "", "summarize my inbox"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    assert cli_main(["up", *env.args]) == 0
    assert Policy.load(env.pol).user_email == "me@example.com"
    assert env.served[0][1] == "summarize my inbox"


def test_up_yes_needs_email_and_task(env):
    assert cli_main(["up", "--yes", "--task", "x", *env.args]) == 2
    assert cli_main(["up", "--yes", "--email", "t@example.com", *env.args]) == 2
    assert cli_main(["up", "--yes", "--email", "nope", "--task", "x", *env.args]) == 2
    assert not env.pol.exists() and env.served == []


def test_up_with_existing_policy_keeps_it(env, capsys):
    write_pinned(env, "nemotron-3-nano:4b")
    assert cli_main(["up", "--task", "x", *env.args]) == 0
    assert env.served[0][0].model == "nemotron-3-nano:4b"
    assert "the pick would be qwen3.5:9b" in capsys.readouterr().out


def test_up_with_invalid_policy_fails(env):
    env.pol.write_text("[evm]\nchain_id = 1\n")
    assert cli_main(["up", "--task", "x", *env.args]) == 1
    assert env.served == []


def test_up_pull_flag_pulls_then_rechecks(env, monkeypatch, capsys):
    pulled = []

    def fake_pull(model):
        pulled.append(model)
        env.ollama.tags.append(model)
        return 0
    monkeypatch.setattr(installer, "pull", fake_pull)
    assert cli_main(["up", "--yes", "--email", "t@example.com", "--task", "x", "--pull", *env.args]) == 0
    assert pulled == ["qwen3.5:9b"] and "downloaded" in capsys.readouterr().out


def test_up_without_pull_never_pulls(env, monkeypatch):
    monkeypatch.setattr(installer, "pull", lambda m: pytest.fail("pulled without --pull"))
    assert cli_main(["up", "--yes", "--email", "t@example.com", "--task", "x", *env.args]) == 0


def test_up_ollama_missing_prints_install(env, capsys, monkeypatch):
    env.ollama.up = False
    monkeypatch.setattr(cli.shutil, "which", lambda n: None)
    cli_main(["up", "--yes", "--email", "t@example.com", "--dry-run", *env.args])
    out = capsys.readouterr().out
    assert "not installed. Install it: brew install ollama" in out


# ---- doctor ----------------------------------------------------------------------------------

def test_doctor_all_good(env, capsys):
    write_pinned(env, "qwen3.5:9b")
    hl.append("gate.test", target="x", summary="one", vault=env.led, agent="t", phase=hl.PHASE_PRE)
    rc = cli_main(["doctor", *env.args])
    out = capsys.readouterr().out
    assert rc == 0 and "all good" in out and "1 receipts, chain verifies" in out


def test_doctor_catches_every_problem(env, capsys):
    hl.append("gate.test", target="x", summary="one", vault=env.led, agent="t", phase=hl.PHASE_PRE)
    lf = env.led / hl.LEDGER_REL
    lf.write_text(lf.read_text().replace('"one"', '"two"'))
    env.mp.setattr(installer, "sandbox_backend", lambda: (False, "not available on linux yet"))
    rc = cli_main(["doctor", *env.args])
    out = capsys.readouterr().out
    assert rc == 1
    for name in ("policy", "model", "ledger", "sandbox"):
        assert any(l.strip().startswith("FAIL") and name in l for l in out.splitlines()), name


def test_sandbox_backend_by_os():
    assert installer.sandbox_backend("darwin", lambda n: "/usr/bin/sandbox-exec") == (True, "sandbox-exec")
    assert installer.sandbox_backend("darwin", lambda n: None)[0] is False
    assert installer.sandbox_backend("linux", lambda n: "/x")[0] is False


def test_the_4b_is_fetched_as_the_measured_nvidia_file():
    src = "hf.co/nvidia/NVIDIA-Nemotron-3-Nano-4B-GGUF:Q4_K_M"
    assert installer.pull_command("nemotron-3-nano:4b") == f"ollama pull {src} && ollama cp {src} nemotron-3-nano:4b"
    assert installer.pull_command("qwen3.5:9b") == "ollama pull qwen3.5:9b"
    calls = []
    rc = installer.pull("nemotron-3-nano:4b", which=lambda n: "/x/ollama" if n == "ollama" else None,
                        call=lambda argv: calls.append(argv) or 0, out=lambda s: None)
    assert rc == 0 and calls == [["ollama", "pull", src], ["ollama", "cp", src, "nemotron-3-nano:4b"]]
