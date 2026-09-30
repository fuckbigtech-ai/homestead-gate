import argparse
import sys
import types
from pathlib import Path

import pytest

from homestead_gate import adapters, credstore
from homestead_gate.cli import cmd_up
from homestead_gate.sandbox import profile
from test_gate import ME, make_gate, records

PASSWORD = "S3cret-app-password-xyz"


class FakeStore:
    """Stands in for `security` / `secret-tool`. The real ones are unreachable (conftest)."""
    def __init__(self):
        self.items, self.calls = {}, []

    def run(self, args, *a, **kw):
        self.calls.append(list(args))
        tool, verb = args[0], args[1]
        user = args[args.index("-a") + 1] if "-a" in args else args[args.index("user") + 1]
        if verb in ("add-generic-password", "store"):
            self.items[user] = PASSWORD          # what the human typed into the OS prompt
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if verb in ("find-generic-password", "lookup"):
            pw = self.items.get(user)
            return types.SimpleNamespace(returncode=0 if pw else 44, stdout=(pw or "") + "\n", stderr="")
        if verb in ("delete-generic-password", "clear"):
            self.items.pop(user, None)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")
        raise AssertionError(args)


@pytest.fixture
def store(tmp_path, monkeypatch):
    fake = FakeStore()
    monkeypatch.setattr(credstore, "HOME", tmp_path / "gatehome")
    monkeypatch.setattr(credstore, "CONFIG", tmp_path / "gatehome" / "smtp.toml")
    monkeypatch.setattr(credstore, "subprocess", types.SimpleNamespace(run=fake.run))
    monkeypatch.setattr(credstore.shutil, "which", lambda name: f"/usr/bin/{name}")
    return fake


def test_real_keychain_is_unreachable_from_tests(tmp_path, monkeypatch):
    monkeypatch.setattr(credstore, "CONFIG", tmp_path / "smtp.toml")
    (tmp_path / "smtp.toml").write_text('host = "h"\nport = 587\nuser = "me@example.com"\nstarttls = true\n')
    monkeypatch.setattr(credstore.shutil, "which", lambda name: f"/usr/bin/{name}")
    with pytest.raises(AssertionError, match="real credential store"):
        credstore.load_smtp()


def test_store_load_roundtrip_password_never_in_argv(store):
    credstore.store_smtp("smtp.example.com", 587, ME)
    assert credstore.load_smtp()["password"] == PASSWORD
    assert not any(PASSWORD in " ".join(c) for c in store.calls)
    if sys.platform == "darwin":
        add = next(c for c in store.calls if "add-generic-password" in c)
        assert add[-1] == "-w" and "-T" in add          # interactive prompt, access limited to the gate


def test_config_is_private_and_has_no_password(store):
    credstore.store_smtp("smtp.example.com", 587, ME)
    assert (credstore.CONFIG.stat().st_mode & 0o777) == 0o600
    assert PASSWORD not in credstore.CONFIG.read_text()


def test_status_never_shows_password(store):
    credstore.store_smtp("smtp.example.com", 587, ME)
    s = credstore.status()
    assert PASSWORD not in s and "stored" in s


def test_clear_removes_everything(store):
    credstore.store_smtp("smtp.example.com", 587, ME)
    credstore.clear()
    assert credstore.load_smtp() is None and not store.items


def test_no_backend_refuses_instead_of_plaintext(tmp_path, monkeypatch):
    monkeypatch.setattr(credstore, "HOME", tmp_path)
    monkeypatch.setattr(credstore, "CONFIG", tmp_path / "smtp.toml")
    monkeypatch.setattr(credstore.shutil, "which", lambda name: None)
    with pytest.raises(credstore.CredentialError):
        credstore.store_smtp("smtp.example.com", 587, ME)
    assert not (tmp_path / "smtp.toml").exists()


class FakeSMTP:
    sent: list = []

    def __init__(self, host, port, timeout=30):
        self.host = host

    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self): pass
    def login(self, user, pw): self.user, self.pw = user, pw
    def send_message(self, msg): FakeSMTP.sent.append(msg)


def test_live_send_only_after_both_yeses(tmp_path, monkeypatch, store):
    FakeSMTP.sent = []
    monkeypatch.setattr(adapters.smtplib, "SMTP", FakeSMTP)
    credstore.store_smtp("smtp.example.com", 587, ME)
    smtp = credstore.load_smtp()
    g, _ = make_gate(tmp_path, verdict="block", answers=("n",))
    g.smtp, g.live = smtp, True
    r = g.submit({"action": {"type": "email", "to": "stranger@example.net", "subject": "s", "body": "b"}})
    assert r["status"] == "denied" and FakeSMTP.sent == []            # model flagged, human said no
    r = g.submit({"action": {"type": "email", "to": ME, "subject": "s", "body": "b"}})
    assert r["status"] == "executed" and len(FakeSMTP.sent) == 1         # to self: policy allows
    assert FakeSMTP.sent[0]["From"] == ME
    ledger_text = (tmp_path / "l" / ".hsm" / "ledger.jsonl").read_text()
    assert PASSWORD not in ledger_text and "smtp.example.com" in ledger_text


def _up_args(tmp_path, **kw):
    pol = tmp_path / "policy.toml"
    pol.write_text(f'[user]\nemail = "{kw.pop("policy_email", ME)}"\n')
    return argparse.Namespace(policy=str(pol), ledger=str(tmp_path / "l"), port=0, task="t", live=True, **kw)


def test_up_live_refuses_without_credentials(tmp_path, store):
    assert cmd_up(_up_args(tmp_path)) == 2


def test_up_live_refuses_when_sender_is_not_the_user(tmp_path, store):
    credstore.store_smtp("smtp.example.com", 587, "someone-else@example.com")
    assert cmd_up(_up_args(tmp_path)) == 2


def test_sandbox_hides_gate_smtp_settings(tmp_path):
    p = profile(home=tmp_path, gate_home=tmp_path / ".homestead-gate", ledger=tmp_path / "l", ports=[6000])
    assert f'(deny file-read* (literal "{tmp_path}/.homestead-gate/smtp.toml"))' in p
