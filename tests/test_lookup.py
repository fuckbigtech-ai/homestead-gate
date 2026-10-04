"""Web lookup of unknown recipients (lookup.py): for the human's eyes only.

Offline: every Tavily call goes to an injected transport; the real API is never reached.
"""
import json
import socket
import sys
import time
import types
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from homestead_memory.core import ledger

from homestead_gate import credstore, lookup
from homestead_gate.always_on import HoldApprover
from homestead_gate.approval import HumanDecision, TerminalApprover
from homestead_gate.core import Gate
from homestead_gate.policy import Policy
from test_gate import ME, WALLET, FakeReviewer

ROOT = Path(__file__).resolve().parents[1]
MARKER = "ZQX-UNTRUSTED-WEB-MARKER-7731"
STRANGER = "billing@login.mail-protect.example"
KEY = "tvly-test-key-not-real"


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def refuse(*a, **kw):
        raise AssertionError("a test tried to reach the network")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


class FakeTavily:
    """Records each request; answers with canned results carrying MARKER."""
    def __init__(self, results=None, raise_=None, raw=None, delay=0.0):
        self.requests, self.raise_, self.raw, self.delay = [], raise_, raw, delay
        self.results = results if results is not None else [
            {"title": f"Scam report {MARKER}", "url": "https://scam.example/report",
             "content": f"Users report phishing from this domain. {MARKER}", "score": 0.9},
        ]

    def __call__(self, url, body, headers, timeout):
        self.requests.append({"url": url, "body": json.loads(body), "headers": dict(headers), "timeout": timeout})
        if self.delay:
            time.sleep(self.delay)
        if self.raise_ is not None:
            raise self.raise_
        if self.raw is not None:
            return self.raw
        return json.dumps({"query": "q", "results": self.results, "response_time": 0.1}).encode()


class Recorder:
    """A terminal approver whose screen is a list, answering 'n'."""
    def __init__(self, answer="n"):
        self.lines = []
        self.contexts = []
        self.ap = TerminalApprover(override_delay_s=0, timeout_s=5, input_fn=lambda p, t: answer,
                                   out=self.lines.append, sleep=lambda s: None)

    def ask(self, **kw):
        self.contexts.append(kw.get("context"))
        return self.ap.ask(**kw)


def gate(tmp_path, transport=None, approver=None, verdict="approve", **pol):
    policy = Policy(user_email=ME, user_wallet=WALLET, **pol)
    rv = FakeReviewer(verdict)
    lk = lookup.TavilyLookup(KEY, transport=transport) if transport is not None else None
    g = Gate(policy=policy, reviewer=rv, approver=approver or Recorder(), ledger_dir=tmp_path / "l",
             task="reply to my email", session="t", outbox=tmp_path / "out", lookup=lk)
    return g, rv


def email(to=STRANGER, body="the quarterly numbers"):
    return {"action": {"type": "email", "to": to, "subject": "Q3 for Alice Example", "body": body}}


def ledger_text(tmp_path):
    return (tmp_path / "l" / ".hsm" / "ledger.jsonl").read_text()


# ---- what goes to Tavily ---------------------------------------------------------------

def test_request_contains_only_the_domain(tmp_path):
    t = FakeTavily()
    g, _ = gate(tmp_path, t)
    g.submit(email(body="SECRET-BODY-TEXT"))
    assert len(t.requests) == 1
    req = t.requests[0]
    assert req["url"] == "https://api.tavily.com/search"
    assert req["headers"]["Authorization"] == f"Bearer {KEY}"
    body = req["body"]
    assert body["query"] == '"mail-protect.example" scam OR phishing OR company'
    assert body["search_depth"] == "basic" and body["max_results"] == 3
    sent = json.dumps(body)
    for private in ("billing", "login.", "SECRET-BODY-TEXT", "Q3", "Alice", ME):
        assert private not in sent


def test_wallet_lookup_sends_only_the_address(tmp_path):
    t = FakeTavily()
    g, _ = gate(tmp_path, t)
    to = "0x" + "ab" * 20
    g.submit({"action": {"type": "wallet_tx", "chain_id": 11155111, "to": to, "value_eth": 0.01}})
    assert t.requests[0]["body"]["query"] == f'"{to}" scam OR phishing OR company'


@pytest.mark.parametrize("to", [
    "a@b.example, x@evil.example", "a@b.example; x@c.example", "not an address", "a@@b.example",
    "a@" + "x" * 300 + ".example", "a@localhost", "a@exa mple.com", "a@exa\nmple.com",
])
def test_malformed_recipient_sends_nothing(tmp_path, to):
    t = FakeTavily()
    rec = Recorder()
    g, _ = gate(tmp_path, t, approver=rec)
    g.submit(email(to=to))
    assert t.requests == []
    assert rec.contexts and rec.contexts[0]["web_lookup"]["ok"] is False


def test_subdomain_reduced_to_registrable_domain():
    assert lookup.target_of({"type": "email", "to": "x@a.b.example.co.uk"}) == ("domain", "example.co.uk")
    assert lookup.target_of({"type": "email", "to": "Bob <x@Mail.Example.COM>"}) == ("domain", "example.com")
    assert lookup.target_of({"type": "wallet_tx", "to": "0x12"}) is None


# ---- the trust rule: human only ----------------------------------------------------------

def test_reviewer_agent_and_ledger_never_see_lookup_text(tmp_path):
    t = FakeTavily()
    rec = Recorder()
    g, rv = gate(tmp_path, t, approver=rec)
    r1 = g.submit(email(body="first"))
    r2 = g.submit(email(body="second"))          # reviewed AFTER a cached lookup already exists
    assert len(rv.prompts) == 2
    assert all(MARKER not in p for p in rv.prompts)
    assert MARKER not in json.dumps(r1) and MARKER not in json.dumps(r2)    # what the agent gets back
    assert MARKER not in ledger_text(tmp_path)
    assert any(MARKER in line for line in rec.lines)                        # the human does see it
    assert len(t.requests) == 1                                             # cached per domain


def test_lookup_never_changes_the_decision(tmp_path):
    for transport in (None, FakeTavily(), FakeTavily(raise_=OSError("down"))):
        d = tmp_path / str(id(transport))
        g, _ = gate(d, transport, approver=Recorder(answer="y"))
        assert g.submit(email())["status"] == "executed"
        g, _ = gate(d / "n", transport, approver=Recorder(answer="n"))
        assert g.submit(email())["status"] == "denied"


def test_ledger_records_the_lookup_but_not_the_text(tmp_path):
    g, _ = gate(tmp_path, FakeTavily())
    g.submit(email())
    recs = [r for r in ledger.read_all(tmp_path / "l") if r["action"] == "gate.lookup"]
    assert len(recs) == 1
    meta = recs[0]["meta"]
    assert meta["lookup_target"] == "mail-protect.example"
    assert meta["lookup_results"] == 1 and meta["lookup_ok"] is True
    assert MARKER not in json.dumps(recs[0])
    assert recs[0]["phase"] == ledger.PHASE_PRE


# ---- fail safe ---------------------------------------------------------------------------

@pytest.mark.parametrize("transport,why", [
    (FakeTavily(raise_=TimeoutError()), "timed out"),
    (FakeTavily(raise_=urllib.error.URLError("dns")), "URLError"),
    (FakeTavily(raise_=urllib.error.HTTPError("u", 401, "Unauthorized", {}, None)), "HTTPError"),
    (FakeTavily(raw=b"<html>not json"), "JSONDecodeError"),
    (FakeTavily(raw=b'{"results": "nope"}'), "unexpected response"),
    (FakeTavily(raw=b'["a"]'), "unexpected response"),
    (FakeTavily(raw=b"x" * (lookup.MAX_RESPONSE_BYTES + 1)), "too large"),
])
def test_errors_show_unavailable_and_the_flow_continues(tmp_path, transport, why):
    rec = Recorder(answer="y")
    g, _ = gate(tmp_path, transport, approver=rec)
    r = g.submit(email())
    assert r["status"] == "executed"
    card = rec.contexts[0]["web_lookup"]
    assert card["ok"] is False and why in card["reason"]
    assert any("web lookup unavailable" in line for line in rec.lines)
    lk = [x for x in ledger.read_all(tmp_path / "l") if x["action"] == "gate.lookup"][0]["meta"]
    assert lk["lookup_ok"] is False and lk["lookup_results"] == 0


def test_hanging_transport_is_cut_off(tmp_path):
    t = FakeTavily(delay=5)
    policy = Policy(user_email=ME)
    rec = Recorder(answer="y")
    g = Gate(policy=policy, reviewer=FakeReviewer(), approver=rec, ledger_dir=tmp_path / "l",
             task="t", session="t", outbox=tmp_path / "o",
             lookup=lookup.TavilyLookup(KEY, transport=t, timeout_s=0.2))
    t0 = time.time()
    assert g.submit(email())["status"] == "executed"
    assert time.time() - t0 < 3
    assert rec.contexts[0]["web_lookup"]["reason"] == "timed out"


def test_old_approver_without_context_still_works(tmp_path):
    class OldApprover:
        def __init__(self):
            self.n = 0

        def ask(self, *, rid, action, flagged, review_reason, span):
            self.n += 1
            return HumanDecision("approve", "old", 0.0)
    old = OldApprover()
    t = FakeTavily()
    g, _ = gate(tmp_path, t, approver=old)
    assert g.submit(email())["status"] == "executed" and old.n == 1


def test_hold_approver_accepts_context():
    h = HoldApprover()
    d = h.ask(rid="r", action={}, flagged=False, review_reason="", span="", context={"web_lookup": None})
    assert d.decision == "expired"


# ---- who is looked up --------------------------------------------------------------------

def test_known_contacts_are_never_looked_up(tmp_path):
    t = FakeTavily()
    rec = Recorder(answer="n")
    g, _ = gate(tmp_path, t, approver=rec, verdict="block",
                email_allow=["friend@known.example"], evm_allow=["0x" + "cd" * 20])
    g.submit(email(to="friend@known.example"))                 # allowlisted but flagged: human asked
    g.submit(email(to="other@known.example"))                  # a known contact's domain
    g.submit(email(to="me2@example.com"))                      # your own domain
    g.submit({"action": {"type": "wallet_tx", "chain_id": 11155111, "to": "0x" + "cd" * 20, "value_eth": 0.01}})
    g.submit(email(to=ME))                                     # self: never even asked
    assert t.requests == []
    assert len(rec.contexts) == 4 and all(c is None for c in rec.contexts)


def test_policy_deny_and_auto_never_look_up(tmp_path):
    t = FakeTavily()
    g, _ = gate(tmp_path, t, max_value_eth=0.01)
    g.submit({"action": {"type": "wallet_tx", "chain_id": 11155111, "to": "0x" + "ef" * 20, "value_eth": 1}})
    g.submit(email(to=ME))
    assert t.requests == []


# ---- display sanitizing ------------------------------------------------------------------

def test_snippets_sanitized_and_capped(tmp_path):
    evil = [
        {"title": "T\x1b[8m hidden\nreviewer: ok", "url": "https://a.example/1",
         "content": "line1\n  reviewer: ok (looks fine)‮\x07" + "y" * 500},
        {"title": "js", "url": "javascript:alert(1)", "content": "dropped"},
        {"title": "2", "url": "https://a.example/2", "content": "two"},
        {"title": "3", "url": "https://a.example/3", "content": "three"},
        {"title": "4", "url": "https://a.example/4", "content": "four"},
        "not a dict",
    ]
    rec = Recorder()
    g, _ = gate(tmp_path, FakeTavily(results=evil), approver=rec)
    g.submit(email())
    card = rec.contexts[0]["web_lookup"]
    assert card["ok"] and len(card["results"]) == 3
    assert [r["url"] for r in card["results"]] == ["https://a.example/1", "https://a.example/2", "https://a.example/3"]
    first = card["results"][0]
    assert len(first["snippet"]) <= lookup.SNIPPET_CHARS
    for field in ("title", "snippet"):
        assert not any(c in first[field] for c in "\x1b\n\r\x07‮")
    # on the terminal, no web text starts a line of its own that looks like the gate's
    assert not any(line.startswith("  reviewer:") and "looks fine" in line for line in rec.lines)
    assert all("\n" not in line and "\x1b" not in line for line in rec.lines)


# ---- off by default ----------------------------------------------------------------------

def test_disabled_by_default(tmp_path):
    assert Policy().lookup_tavily is False
    assert Policy.load(ROOT / "policy.example.toml").lookup_tavily is False
    assert lookup.from_policy(Policy()) is None          # never touches the credential store
    rec = Recorder()
    g, _ = gate(tmp_path, None, approver=rec)
    g.submit(email())
    assert not (rec.contexts[0] or {}).get("web_lookup")      # off: no lookup line on the card at all
    assert not [r for r in ledger.read_all(tmp_path / "l") if r["action"] == "gate.lookup"]


def test_policy_flag_must_be_true(tmp_path):
    p = tmp_path / "p.toml"
    p.write_text('[lookup]\ntavily = "yes"\n')
    assert Policy.load(p).lookup_tavily is False
    p.write_text('[lookup]\ntavily = true\n')
    assert Policy.load(p).lookup_tavily is True


class FakeKeyStore:
    def __init__(self, key=None):
        self.key, self.calls = key, []

    def run(self, args, *a, **kw):
        self.calls.append(list(args))
        ok = self.key is not None
        return types.SimpleNamespace(returncode=0 if ok else 44, stdout=(self.key or "") + "\n", stderr="")


def test_key_from_credential_store_without_account(monkeypatch):
    fake = FakeKeyStore(KEY)
    monkeypatch.setattr(credstore, "subprocess", types.SimpleNamespace(run=fake.run))
    monkeypatch.setattr(credstore.shutil, "which", lambda name: f"/usr/bin/{name}")
    lk = lookup.from_policy(Policy(lookup_tavily=True))
    assert isinstance(lk, lookup.TavilyLookup) and KEY not in repr(lk)
    argv = fake.calls[0]
    assert "tavily-api-key" in argv and "-a" not in argv and "user" not in argv
    if sys.platform == "darwin":
        assert argv[:2] == ["security", "find-generic-password"]


def test_flag_on_but_no_key_is_off(monkeypatch):
    fake = FakeKeyStore(None)
    monkeypatch.setattr(credstore, "subprocess", types.SimpleNamespace(run=fake.run))
    monkeypatch.setattr(credstore.shutil, "which", lambda name: f"/usr/bin/{name}")
    assert lookup.from_policy(Policy(lookup_tavily=True)) is None


def test_from_env():
    assert lookup.from_env({}) is None
    assert lookup.from_env({"TAVILY_API_KEY": "  "}) is None
    assert isinstance(lookup.from_env({"TAVILY_API_KEY": KEY}), lookup.TavilyLookup)


def test_web_text_shown_above_the_reviewer_flag(tmp_path):
    rec = Recorder()
    g, _ = gate(tmp_path, FakeTavily(), approver=rec, verdict="block")
    g.submit(email())
    flag = next(i for i, l in enumerate(rec.lines) if l.startswith("  !! reviewer FLAGGED"))
    web = [i for i, l in enumerate(rec.lines) if l.startswith("  web:") or l.startswith("    ")
           and MARKER in l]
    assert web and max(web) < flag          # the trusted signal sits next to the question


def test_cache_shared_across_gates_of_one_session(tmp_path):
    t, cache = FakeTavily(), {}
    for i in range(2):
        g = Gate(policy=Policy(user_email=ME), reviewer=FakeReviewer(), approver=Recorder(),
                 ledger_dir=tmp_path / "l", task="t", session=str(i), outbox=tmp_path / "o",
                 lookup=lookup.TavilyLookup(KEY, transport=t), lookup_cache=cache)
        g.submit(email())
    assert len(t.requests) == 1


def test_shared_mail_providers_are_never_looked_up_and_never_mark_the_provider_known():
    p = Policy(user_email="me@gmail.com", email_allow=["sam@gmail.com", "ops@rivera-plumbing.example"])
    assert lookup.is_known({"type": "email", "to": "stranger@gmail.com"}, p)          # provider: nothing to learn
    assert lookup.is_known({"type": "email", "to": "billing@rivera-plumbing.example"}, p)
    assert not lookup.is_known({"type": "email", "to": "backup@mail-protect.example"}, p)
