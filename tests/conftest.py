"""Test-wide guard: no test may ever reach a real credential store.

Added 2026-09-30 after a background agent's experiment created a real macOS keychain and popped
password dialogs on the owner's screen. Any attempt to run `security` or `secret-tool` from a test
now fails loudly instead of touching the machine's keychain.
"""
import subprocess

import pytest

_FORBIDDEN = {"security", "secret-tool"}
_real_run, _real_popen = subprocess.run, subprocess.Popen


def _argv0(args):
    a = args[0] if isinstance(args, (list, tuple)) and args else (args.split()[0] if isinstance(args, str) and args else "")
    return str(a).rsplit("/", 1)[-1]


@pytest.fixture(autouse=True)
def _no_real_keychain(monkeypatch):
    def guarded_run(args, *a, **kw):
        if _argv0(args) in _FORBIDDEN:
            raise AssertionError(f"test tried to run the real credential store: {_argv0(args)}")
        return _real_run(args, *a, **kw)

    def guarded_popen(args, *a, **kw):
        if _argv0(args) in _FORBIDDEN:
            raise AssertionError(f"test tried to run the real credential store: {_argv0(args)}")
        return _real_popen(args, *a, **kw)

    monkeypatch.setattr(subprocess, "run", guarded_run)
    monkeypatch.setattr(subprocess, "Popen", guarded_popen)


# Test-wide guard: no test may ever reach a real Ollama (2026-10-04). Running a model on the
# owner's laptop can take it down, and the reviewer-pin work added Ollama calls to paths the
# suite already exercises (doctor, assistant start, --imap-setup). Anything aimed at port 11434
# fails as "connection refused" unless a test installs its own fake urlopen. The guard stands
# down only for the explicit opt-in HG_MODEL_TESTS=1 (the `model` marker, meant for a GPU box);
# never set it on the owner's laptop.
import os
import urllib.error
import urllib.request

_real_urlopen = urllib.request.urlopen


@pytest.fixture(autouse=True)
def _no_real_ollama(monkeypatch):
    if os.environ.get("HG_MODEL_TESTS") == "1":
        return

    def guarded_urlopen(url, *a, **kw):
        target = getattr(url, "full_url", url)
        if ":11434" in str(target):
            raise urllib.error.URLError("tests never reach a real Ollama (conftest guard)")
        return _real_urlopen(url, *a, **kw)

    monkeypatch.setattr(urllib.request, "urlopen", guarded_urlopen)
