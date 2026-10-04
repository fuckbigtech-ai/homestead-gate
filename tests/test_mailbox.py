"""Your real inbox, read-only. No network, no real keychain, no model loads: a fake IMAP server
that fails on anything that could change the mailbox, and a fake credential store."""
import imaplib
import json
import re
import socket
import types
import urllib.request
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path

import pytest

from homestead_gate import always_on, credstore, mailbox
from homestead_gate import assistant as asst
from homestead_gate import cli
from homestead_gate import skills as sk
from homestead_gate.cli import main as cli_main
from homestead_gate.llm import ChatClient
from test_assistant import KEY, FakeReviewer, ScriptedLLM, call, calls, done

PASSWORD = "abcd efgh ijkl mnop"            # how Google shows an app password
USER, HOST = "owner@gmail.com", "imap.gmail.com"
NOW = datetime(2026, 10, 2, 9, 0)


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    def refuse(*a, **kw):
        raise AssertionError("a test tried to reach the network")
    monkeypatch.setattr(imaplib, "IMAP4_SSL", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    monkeypatch.delenv("HSM_VAULT", raising=False)


# ---- fakes ------------------------------------------------------------------------------

class FakeStore:
    """Stands in for `security` / `secret-tool`, keyed by (service, user). The real ones are
    unreachable (conftest)."""
    def __init__(self):
        self.items, self.calls = {}, []

    def run(self, args, *a, **kw):
        self.calls.append(list(args))
        verb = args[1]
        if "-s" in args:
            service, user = args[args.index("-s") + 1], args[args.index("-a") + 1]
        else:
            service, user = args[args.index("service") + 1], args[args.index("user") + 1]
        ok = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        if verb in ("add-generic-password", "store"):
            self.items[(service, user)] = PASSWORD          # what the human typed into the OS prompt
            return ok
        if verb in ("find-generic-password", "lookup"):
            pw = self.items.get((service, user))
            return types.SimpleNamespace(returncode=0 if pw else 44, stdout=(pw or "") + "\n", stderr="")
        if verb in ("delete-generic-password", "clear"):
            self.items.pop((service, user), None)
            return ok
        raise AssertionError(args)


@pytest.fixture
def store(tmp_path, monkeypatch):
    fake = FakeStore()
    monkeypatch.setattr(credstore, "HOME", tmp_path / "gatehome")
    monkeypatch.setattr(credstore, "CONFIG", tmp_path / "gatehome" / "smtp.toml")
    monkeypatch.setattr(credstore, "subprocess", types.SimpleNamespace(run=fake.run))
    monkeypatch.setattr(credstore.shutil, "which", lambda name: f"/usr/bin/{name}")
    return fake


class FakeIMAP:
    """An IMAP server that only allows reading. Anything that could change the mailbox fails."""
    def __init__(self, messages=None, uidvalidity=777, password="abcdefghijklmnop"):
        self.messages = dict(messages or {})          # uid -> raw bytes
        self.uidvalidity, self.password = uidvalidity, password
        self.selected = self.searches = None
        self.searches, self.fetches, self.log = [], [], []

    def __call__(self, host, port):                  # the connect factory
        self.log.append(("connect", host, port))
        return self

    def login(self, user, password):
        self.log.append(("login", user))
        if password != self.password:
            # a server that echoes what it was sent: the password must still not leak
            raise imaplib.IMAP4.error(f"[AUTHENTICATIONFAILED] Invalid credentials for {password}")
        return "OK", [b"logged in"]

    def select(self, mailbox="INBOX", readonly=False):
        assert readonly is True, "the mailbox must be opened with EXAMINE"
        self.selected = mailbox
        return "OK", [str(len(self.messages)).encode()]

    def response(self, code):
        assert code == "UIDVALIDITY"
        return code, [str(self.uidvalidity).encode()]

    def uid(self, command, *args):
        if command == "SEARCH":
            self.searches.append(args)
            crit = [a for a in args if a is not None]
            uids = sorted(self.messages)
            if crit[0] == "UID":
                lo = int(crit[1].split(":")[0])
                # real servers: `n:*` always includes the newest message, even below n
                uids = sorted({u for u in uids if u >= lo} | ({max(uids)} if uids else set()))
            return "OK", [" ".join(map(str, uids)).encode()]
        if command == "FETCH":
            uid, spec = int(args[0]), args[1]
            self.fetches.append(spec)
            assert "BODY.PEEK[" in spec, "fetch must not set \\Seen"
            raw = self.messages.get(uid)
            if raw is None:
                return "OK", [None]
            return "OK", [(f"1 (UID {uid} BODY[]<0> {{{len(raw)}}}".encode(), raw), b")"]
        raise AssertionError(f"UID {command} is not a read")

    def logout(self):
        self.log.append(("logout",))
        return "BYE", [b""]

    def _write(self, *a, **kw):
        raise AssertionError("a write-like IMAP command was sent")
    store = copy = move = expunge = append = delete = close = rename = create = _write


def msg(uid, subject="Hello", body="Plain body.", sender="Dana Okafor <dana@friends.example>", html=None,
        attachment=None, message_id=None):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, USER, subject
    m["Date"] = "Thu, 01 Oct 2026 10:00:00 +0000"
    m["Message-ID"] = message_id or f"<m{uid}@friends.example>"
    if body is not None:
        m.set_content(body)
        if html:
            m.add_alternative(html, subtype="html")
    elif html:
        m.set_content(html, subtype="html")
    if attachment:
        m.add_attachment(b"%PDF-1.4 secret bytes", maintype="application", subtype="pdf", filename=attachment)
    return m.as_bytes()


def config(**kw):
    return mailbox.ImapConfig(host=HOST, user=USER, **kw)


def inbox(data):
    return json.loads((Path(data) / "inbox.json").read_text())


def fresh(tmp_path):
    data = tmp_path / "mail"
    mailbox.prepare_data_dir(data, USER, "fake")
    mailbox.write_config(data, config())
    return data


# ---- parsing ----------------------------------------------------------------------------

def test_plain_message():
    e = mailbox.parse_message(msg(1, body="Dinner at 7?\n\n\n\nSee you."), "imap-1-1")
    assert e["from"] == "dana@friends.example" and e["name"] == "Dana Okafor"
    assert e["subject"] == "Hello" and e["date"].startswith("2026-10-01")
    assert e["body"] == "Dinner at 7?\n\nSee you." and e["attachments"] == []
    assert e["message_id"] == "<m1@friends.example>" and e["source"] == "imap"


def test_html_only_is_stripped_to_text():
    html = ("<html><head><style>p{color:red}</style><title>t</title></head><body><p>Your order "
            "&amp; receipt</p><script>alert(1)</script><!-- hidden note --><ul><li>one</li><li>two</li></ul></body></html>")
    e = mailbox.parse_message(msg(2, body=None, html=html), "imap-1-2")
    assert "Your order & receipt" in e["body"] and "- one" in e["body"] and "- two" in e["body"]
    for gone in ("<p>", "color:red", "alert(1)", "hidden note"):
        assert gone not in e["body"]


def test_multipart_prefers_plain_and_drops_attachments():
    raw = msg(3, body="The plain version.", html="<p>The HTML version.</p>", attachment="invoice-104.pdf")
    e = mailbox.parse_message(raw, "imap-1-3")
    assert e["body"].startswith("The plain version.") and "HTML version" not in e["body"]
    assert e["attachments"] == ["invoice-104.pdf"]
    assert "invoice-104.pdf" in e["body"] and "secret bytes" not in e["body"] and "JVBER" not in e["body"]


def test_encoded_headers_are_decoded():
    raw = (b"From: =?utf-8?b?Sm9zw6kgR2FyY8OtYQ==?= <jose@example.es>\r\n"
           b"Subject: =?utf-8?q?Caf=C3=A9_ma=C3=B1ana=3F?=\r\n"
           b"Date: Thu, 01 Oct 2026 10:00:00 +0000\r\nMessage-ID: <x@y>\r\n"
           b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
           + "¿Nos vemos?".encode())
    e = mailbox.parse_message(raw, "imap-1-4")
    assert e["name"] == "José García" and e["from"] == "jose@example.es"
    assert e["subject"] == "Café mañana?" and e["body"] == "¿Nos vemos?"


def test_oversized_body_is_capped_with_a_note():
    e = mailbox.parse_message(msg(5, body="x" * 20000), "imap-1-5")
    assert len(e["body"]) < mailbox.BODY_MAX + 100
    assert f"{20000 - mailbox.BODY_MAX} more characters cut" in e["body"]
    e = mailbox.parse_message(msg(6, body="short"), "imap-1-6", cut_short=True)
    assert "only the first" in e["body"]


# ---- sync -------------------------------------------------------------------------------

def test_first_sync_takes_recent_mail_up_to_the_cap(tmp_path):
    data = fresh(tmp_path)
    server = FakeIMAP({u: msg(u, subject=f"m{u}") for u in range(1, 61)}, password="abcdefghijklmnop")
    r = mailbox.sync(data, config(), PASSWORD, connect=server, now=NOW)
    assert server.searches[0][-2:] == ("SINCE", "29-Sep-2026")
    assert len(r.new) == 50 and r.not_fetched == 10
    assert [m["id"] for m in inbox(data)][:2] == ["imap-777-11", "imap-777-12"]      # the newest 50
    st = mailbox.load_state(data)
    assert st["uidvalidity"] == 777 and st["last_uid"] == 60
    assert server.selected == '"INBOX"' and server.log[-1] == ("logout",)


def test_resync_fetches_only_new_mail_and_never_duplicates(tmp_path):
    data = fresh(tmp_path)
    server = FakeIMAP({1: msg(1), 2: msg(2)}, password="abcdefghijklmnop")
    assert len(mailbox.sync(data, config(), PASSWORD, connect=server, now=NOW).new) == 2
    server.fetches.clear()
    r = mailbox.sync(data, config(), PASSWORD, connect=server, now=NOW)
    assert r.new == [] and server.fetches == []              # `3:*` still matched uid 2; filtered out
    assert server.searches[-1][-2:] == ("UID", "3:*")
    server.messages[3] = msg(3, subject="new one")
    r = mailbox.sync(data, config(), PASSWORD, connect=server, now=NOW)
    assert [m["subject"] for m in r.new] == ["new one"]
    (data / mailbox.STATE_FILE).unlink()                     # lost state: everything is seen again
    r = mailbox.sync(data, config(), PASSWORD, connect=server, now=NOW)
    assert r.new == [] and r.duplicates == 3
    assert len(inbox(data)) == 3


def test_uidvalidity_change_resets_without_doubling_the_inbox(tmp_path):
    data = fresh(tmp_path)
    server = FakeIMAP({1: msg(1), 2: msg(2)}, password="abcdefghijklmnop")
    mailbox.sync(data, config(), PASSWORD, connect=server, now=NOW)
    # the server renumbers: same messages, new uids, new uidvalidity, plus one new message
    renumbered = FakeIMAP({10: msg(1), 11: msg(2), 12: msg(3, subject="after the reset")},
                          uidvalidity=900, password="abcdefghijklmnop")
    r = mailbox.sync(data, config(), PASSWORD, connect=renumbered, now=NOW)
    assert r.reset and [m["subject"] for m in r.new] == ["after the reset"] and r.duplicates == 2
    assert renumbered.searches[0][-2] == "SINCE"             # started over from the window
    assert [m["id"] for m in inbox(data)] == ["imap-777-1", "imap-777-2", "imap-900-12"]
    assert mailbox.load_state(data) | {"last_sync": ""} == {
        "account": config().account, "uidvalidity": 900, "last_uid": 12, "last_sync": ""}


def test_one_unreadable_message_does_not_stop_the_sync(tmp_path, monkeypatch):
    data = fresh(tmp_path)
    real = mailbox.parse_message

    def flaky(raw, mid, **kw):
        if mid.endswith("-2"):
            raise ValueError("broken")
        return real(raw, mid, **kw)
    monkeypatch.setattr(mailbox, "parse_message", flaky)
    r = mailbox.sync(data, config(), PASSWORD, connect=FakeIMAP({1: msg(1), 2: msg(2), 3: msg(3)},
                                                                password="abcdefghijklmnop"), now=NOW)
    assert [m["subject"] for m in r.new] == ["Hello", "(could not be read)", "Hello"]


# ---- read-only --------------------------------------------------------------------------

def test_read_only_at_the_protocol_level(tmp_path):
    data = fresh(tmp_path)
    server = FakeIMAP({1: msg(1, attachment="a.pdf")}, password="abcdefghijklmnop")
    mailbox.sync(data, config(), PASSWORD, connect=server, now=NOW)      # FakeIMAP asserts EXAMINE + PEEK
    assert server.fetches and all(f.startswith("(BODY.PEEK[]<0.") for f in server.fetches)
    for command in ("STORE", "COPY", "MOVE", "EXPUNGE"):
        with pytest.raises(mailbox.MailboxError, match="read-only"):
            mailbox._uid(server, command, "1", "+FLAGS", "(\\Deleted)")
    src = Path(mailbox.__file__).read_text()
    # every method the code calls on the connection, anywhere: only the read path
    assert set(re.findall(r"\bconn\.(\w+)\(", src)) == {"login", "select", "response", "uid", "logout"}
    assert "readonly=True" in src and "readonly=False" not in src


# ---- credentials ------------------------------------------------------------------------

def answers(monkeypatch, *values):
    it = iter(values)
    monkeypatch.setattr(cli, "_ask", lambda prompt: next(it))


def test_setup_then_sync_password_never_on_disk_or_screen(tmp_path, monkeypatch, store, capsys, caplog):
    data = tmp_path / "mail"
    answers(monkeypatch, "", USER)                             # host default imap.gmail.com
    assert cli_main(["assistant", "--data", str(data), "--imap-setup"]) == 0
    add = next(c for c in store.calls if c[1] in ("add-generic-password", "store"))
    assert credstore.IMAP_SERVICE in add and PASSWORD not in " ".join(add)
    cfg = mailbox.load_config(data)
    assert (cfg.host, cfg.user, cfg.port, cfg.mailbox) == (HOST, USER, 993, "INBOX")
    assert (data.stat().st_mode & 0o777) == 0o700 and ((data / "policy.toml").stat().st_mode & 0o777) == 0o600

    server = FakeIMAP({1: msg(1)}, password="abcdefghijklmnop")        # spaces dropped for Gmail
    monkeypatch.setattr(mailbox, "default_connect", server)
    assert cli_main(["assistant", "--data", str(data), "--sync"]) == 0
    assert "1 new message from INBOX on imap.gmail.com" in capsys.readouterr().out

    server.password = "something-else"                         # login refused; the server echoes it
    assert cli_main(["assistant", "--data", str(data), "--sync"]) == 1
    out = capsys.readouterr()
    assert mailbox.APP_PASSWORDS in out.err and "2-Step Verification" in out.err
    assert "Invalid credentials for ***" in out.err                    # the echo was scrubbed

    secrets = (PASSWORD, PASSWORD.replace(" ", ""))
    for root in (data, credstore.HOME):
        for f in (p for p in Path(root).rglob("*") if p.is_file()) if Path(root).exists() else []:
            text = f.read_bytes().decode("utf-8", "replace")
            assert not any(s in text for s in secrets), f
    assert not any(s in out.out + out.err + caplog.text for s in secrets)
    assert not any(s in " ".join(c) for c in store.calls for s in secrets)


def test_imap_password_can_never_turn_on_live_email(tmp_path, monkeypatch, store):
    data = tmp_path / "mail"
    answers(monkeypatch, "", USER)
    assert cli_main(["assistant", "--data", str(data), "--imap-setup"]) == 0
    monkeypatch.setattr(mailbox, "default_connect", FakeIMAP({1: msg(1)}, password="abcdefghijklmnop"))
    assert cli_main(["assistant", "--data", str(data), "--sync"]) == 0
    # a different keychain entry: the sender's credentials are still absent, so --live refuses
    assert not credstore.CONFIG.exists() and credstore.load_smtp() is None
    assert {k[0] for k in store.items} == {credstore.IMAP_SERVICE}
    assert "smtp" not in (data / "policy.toml").read_text().lower()
    smtp, rc = cli._live_smtp(asst.load_policy(data))
    assert smtp is None and rc == 2


def test_setup_refuses_the_demo_inbox_and_demo_mail_refuses_a_real_one(tmp_path, monkeypatch, store, capsys):
    demo = tmp_path / "demo"
    asst.seed(demo, model="fake")
    answers(monkeypatch, "", USER)
    assert cli_main(["assistant", "--data", str(demo), "--imap-setup"]) == 2
    assert "demo's fake inbox" in capsys.readouterr().err
    assert mailbox.load_config(demo) is None and store.items == {}

    real = fresh(tmp_path)
    assert cli_main(["assistant", "--data", str(real), "--demo-new-mail"]) == 2
    assert inbox(real) == []


def test_sync_errors_are_clear(tmp_path, monkeypatch, store, capsys):
    data = tmp_path / "mail"
    assert cli_main(["assistant", "--data", str(data), "--sync"]) == 2
    assert "--imap-setup" in capsys.readouterr().err
    answers(monkeypatch, "", USER)
    cli_main(["assistant", "--data", str(data), "--imap-setup"])

    def down(host, port):
        raise OSError("nodename nor servname provided")
    monkeypatch.setattr(mailbox, "default_connect", down)
    assert cli_main(["assistant", "--data", str(data), "--sync"]) == 1
    assert "could not reach imap.gmail.com:993" in capsys.readouterr().err
    with pytest.raises(AssertionError, match="network"):          # the guard: no real connection ever
        mailbox.sync(data, config(), PASSWORD, connect=lambda h, p: imaplib.IMAP4_SSL(h, p))


# ---- always on --------------------------------------------------------------------------

def brain(*turns):
    return ChatClient.from_preset("nim", api_key=KEY, transport=ScriptedLLM(*turns), sleep=lambda s: None)


def test_watch_pass_on_real_mail_and_continues_when_the_network_is_down(tmp_path):
    data = fresh(tmp_path)
    server = FakeIMAP({1: msg(1, subject="Dinner Saturday?", body="Are we still on for 7?")},
                      password="abcdefghijklmnop")
    skill = sk.load_skills(data)["summarize"]
    notes = []
    p = always_on.run_pass(data, skill, llm=brain(calls(call("list_inbox")), calls(call("read_email", id="imap-777-1")),
                                                 done("Dana asks about dinner.")),
                           reviewer=FakeReviewer(), log=lambda s: None, notify_fn=lambda a, b: notes.append(b),
                           sync=lambda: mailbox.sync(data, config(), PASSWORD, connect=server, now=NOW))
    assert p.error is None and not p.sync_failed and "1 new message" in p.sync
    assert [m["id"] for m in p.new_mail] == ["imap-777-1"]
    brief = (data / "brief.md").read_text()
    assert "Mail sync: 1 new message" in brief and "dana@friends.example: Dinner Saturday?" in brief
    for demo in ("example.com", "rivera", "mail-protect", "msg-00"):
        assert demo not in brief and demo not in json.dumps(inbox(data))

    # next pass: the network is down, and one message arrived before it went (already in inbox.json)
    items = inbox(data) + [mailbox.parse_message(msg(2, subject="Earlier"), "imap-777-2")]
    (data / "inbox.json").write_text(json.dumps(items))

    def down():
        raise mailbox.MailboxError("network", "could not reach imap.gmail.com:993: timed out")
    p = always_on.run_pass(data, skill, llm=brain(calls(call("list_inbox")), done("One more.")),
                           reviewer=FakeReviewer(), log=lambda s: None, notify_fn=lambda a, b: notes.append(b),
                           sync=down)
    assert p.sync_failed and p.error is None and [m["id"] for m in p.new_mail] == ["imap-777-2"]
    brief = (data / "brief.md").read_text()
    assert "**Mail sync failed:** could not reach" in brief and "used the inbox as it was" in brief
    assert "The run did not finish" not in brief and "imap-777-2" in json.dumps(always_on.load_state(data))
    assert notes[-1].startswith("mail sync failed") and "gmail" not in notes[-1]   # counts only, no account


def test_unanswered_keychain_dialog_fails_the_sync_not_the_pass(tmp_path, monkeypatch, store):
    data = fresh(tmp_path)
    store.items[(credstore.IMAP_SERVICE, USER)] = PASSWORD

    def hangs(args, *a, **kw):
        assert kw.get("timeout"), "a keychain read without a timeout can hang an unattended pass"
        raise credstore.TimeoutExpired(args, kw["timeout"])
    monkeypatch.setattr(credstore, "subprocess", types.SimpleNamespace(run=hangs))
    notes = []
    p = always_on.run_pass(data, sk.load_skills(data)["summarize"], llm=brain(), reviewer=FakeReviewer(),
                           log=lambda s: None, notify_fn=lambda a, b: notes.append(b),
                           sync=lambda: mailbox.sync_configured(data, connect=FakeIMAP()))
    assert p.sync_failed and "did not answer within" in p.sync and p.error is None and not p.skipped
    assert notes == ["mail sync failed, see the brief; 0 new, 0 done, 0 waiting for you"]


def test_a_real_inbox_gets_the_thinking_reviewer(tmp_path):
    """Code review M4: --imap-setup data dirs silently ran the reviewer with thinking off."""
    from homestead_gate.policy import Policy
    data = tmp_path / "mail"
    mailbox.prepare_data_dir(data, USER, "nemotron-3-nano:4b")
    assert Policy.load(data / "policy.toml").review_think is True


# ---- code review follow-ups (2026-10-04) --------------------------------------------------
def test_an_encoded_display_name_cannot_pose_as_a_known_address():
    raw = (b"From: =?utf-8?q?sam=40rivera-plumbing.example?= <attacker@evil.example>\r\n"
           b"Subject: invoice\r\nDate: Thu, 01 Oct 2026 10:00:00 +0000\r\nMessage-ID: <s@y>\r\n\r\npay me")
    e = mailbox.parse_message(raw, "imap-1-9")
    assert e["from"] == "attacker@evil.example"
    assert "display name only" in e["name"] and "attacker@evil.example" in e["name"]


def test_terminal_control_characters_are_stripped():
    raw = (b"From: Dana <dana@friends.example>\r\nSubject: =?utf-8?q?hi=1B[8mhidden=1B[0m?=\r\n"
           b"Date: Thu, 01 Oct 2026 10:00:00 +0000\r\nMessage-ID: <c@y>\r\n\r\nbody\x1b[2Jclear\x07")
    e = mailbox.parse_message(raw, "imap-1-10")
    assert "\x1b" not in e["subject"] and "\x1b" not in e["body"] and "\x07" not in e["body"]


def test_messages_without_a_message_id_are_not_doubled_after_a_renumbering():
    a = {"from": "x@y", "date": "2026-10-01 10:00", "subject": "s", "body": "b", "message_id": ""}
    assert mailbox._dedupe_key(a) == mailbox._dedupe_key(dict(a, id="imap-2-1"))
    assert mailbox._dedupe_key(a) != mailbox._dedupe_key(dict(a, subject="t"))


def test_a_bad_number_in_imap_config_is_a_config_error(tmp_path):
    data = tmp_path / "mail"
    data.mkdir()
    (data / "policy.toml").write_text('[imap]\nhost = "imap.gmail.com"\nuser = "o@gmail.com"\nport = "nine"\n')
    with pytest.raises(mailbox.MailboxError) as e:
        mailbox.load_config(data)
    assert e.value.kind == "config"


def test_the_inbox_keeps_only_the_newest_entries(tmp_path, monkeypatch):
    monkeypatch.setattr(mailbox, "INBOX_KEEP", 3)
    data = fresh(tmp_path)
    (data / "inbox.json").write_text(json.dumps([{"id": f"old-{i}", "message_id": f"<o{i}>"} for i in range(3)]))
    imap = FakeIMAP({1: msg(1), 2: msg(2)})
    mailbox.sync(data, config(), PASSWORD, connect=lambda h, p: imap, now=NOW)
    ids = [m["id"] for m in inbox(data)]
    assert len(ids) == 3 and ids[0] == "old-2" and ids[-1].endswith("-2")
