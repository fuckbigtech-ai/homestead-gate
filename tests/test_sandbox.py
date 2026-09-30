import http.client
import shutil
import socket
import subprocess
import sys
import threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from homestead_gate.egress import host_allowed, make_proxy, serve_in_background
from homestead_gate.sandbox import profile

darwin = pytest.mark.skipif(sys.platform != "darwin" or not shutil.which("sandbox-exec"),
                            reason="macOS sandbox-exec only")


@pytest.mark.parametrize("host,ok", [
    ("api.anthropic.com", True), ("API.anthropic.com.", True), ("evil.com", False),
    ("api.anthropic.com.evil.com", False), ("x.githubusercontent.com", True), ("githubusercontent.com", False),
])
def test_host_allowlist(host, ok):
    assert host_allowed(host, ["api.anthropic.com", "*.githubusercontent.com"]) is ok


@pytest.fixture
def proxy():
    denied = []
    srv = make_proxy(["api.anthropic.com"], lambda h, why: denied.append((h, why)))
    serve_in_background(srv)
    yield srv.server_address[1], denied
    srv.shutdown()


def test_proxy_refuses_unlisted_host(proxy):
    port, denied = proxy
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("CONNECT", "evil.example:443")
    assert c.getresponse().status == 403 and denied[-1][0] == "evil.example"


def test_proxy_refuses_non_443_and_plain_http(proxy):
    port, denied = proxy
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("CONNECT", "api.anthropic.com:22")
    assert c.getresponse().status == 403
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    c.request("GET", "http://api.anthropic.com/?leak=secret")
    assert c.getresponse().status == 403 and len(denied) == 2


def test_profile_shape(tmp_path):
    p = profile(home=tmp_path, gate_home=tmp_path / ".homestead-gate", ledger=tmp_path / "l", ports=[6000, 11434])
    assert "(deny network-outbound)" in p
    assert '(remote ip "localhost:6000")' in p and '(remote ip "localhost:11434")' in p
    assert f'(deny file-read* (subpath "{tmp_path}/.ssh"))' in p
    assert f'(deny file-write* (subpath "{tmp_path}/.homestead-gate"))' in p


# ---- real sandbox on macOS --------------------------------------------------------------

def _sandboxed(tmp_path, code, ports):
    prof = profile(home=tmp_path, gate_home=tmp_path / "gate", ledger=tmp_path / "gate" / "ledger", ports=ports)
    sb = tmp_path / "p.sb"
    sb.write_text(prof)
    return subprocess.run(["sandbox-exec", "-f", str(sb), sys.executable, "-c", code],
                          capture_output=True, text=True, timeout=30)


@darwin
def test_sandbox_blocks_direct_internet(tmp_path):
    r = _sandboxed(tmp_path, "import socket; socket.create_connection(('1.1.1.1', 443), timeout=5)", [6000])
    assert r.returncode != 0 and ("Operation not permitted" in r.stderr or "PermissionError" in r.stderr)


@darwin
def test_sandbox_allows_listed_loopback_port_only(tmp_path):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    code = f"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:{port}/', timeout=5).read())"
    assert _sandboxed(tmp_path, code, [port]).returncode == 0
    assert _sandboxed(tmp_path, code, [port + 1 if port < 65535 else port - 1]).returncode != 0
    srv.shutdown()


@darwin
def test_sandbox_hides_secrets_and_protects_gate(tmp_path):
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "id_ed25519").write_text("KEY")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".env").write_text("SECRET=1")
    (proj / "notes.txt").write_text("fine")
    (tmp_path / "gate").mkdir()
    read = _sandboxed(tmp_path, f"open({str(tmp_path / '.ssh' / 'id_ed25519')!r}).read()", [6000])
    env = _sandboxed(tmp_path, f"open({str(proj / '.env')!r}).read()", [6000])
    ok = _sandboxed(tmp_path, f"print(open({str(proj / 'notes.txt')!r}).read())", [6000])
    write = _sandboxed(tmp_path, f"open({str(tmp_path / 'gate' / 'policy.toml')!r}, 'w').write('x')", [6000])
    assert read.returncode != 0 and env.returncode != 0 and write.returncode != 0
    assert ok.returncode == 0 and "fine" in ok.stdout


@darwin
def test_sandbox_cannot_patch_gate_code_or_escape_via_services(tmp_path):
    import homestead_gate.approval as ap
    target = ap.__file__
    before = open(target).read()
    r = _sandboxed(tmp_path, f"open({target!r}, 'a').write('# pwned')", [6000])
    assert r.returncode != 0 and open(target).read() == before
    lsopen = subprocess.run(["sandbox-exec", "-f", _write_profile(tmp_path), "/usr/bin/open", "-g", "-j",
                             "https://example.invalid/?probe"], capture_output=True, text=True, timeout=30)
    assert lsopen.returncode != 0


@darwin
def test_sandbox_blocks_unix_sockets_and_dns(tmp_path):
    import os
    sock_path = f"/tmp/hg-{os.getpid()}.sock"
    srv = socket.socket(socket.AF_UNIX)
    srv.bind(sock_path)
    srv.listen(1)
    try:
        r = _sandboxed(tmp_path, f"import socket; s=socket.socket(socket.AF_UNIX); s.connect({sock_path!r})", [6000])
        assert r.returncode != 0
    finally:
        srv.close()
        os.unlink(sock_path)
    dns = _sandboxed(tmp_path, "import socket; socket.getaddrinfo('example.com', 443)", [6000])
    assert dns.returncode != 0


def _write_profile(tmp_path):
    sb = tmp_path / "q.sb"
    sb.write_text(profile(home=tmp_path, gate_home=tmp_path / "gate", ledger=tmp_path / "gate" / "l", ports=[6000]))
    return str(sb)


# ---- Linux: bubblewrap ------------------------------------------------------------------

import os  # noqa: E402

from homestead_gate import sandbox as sbx  # noqa: E402

linux = pytest.mark.skipif(not sys.platform.startswith("linux") or sbx.bwrap_problem() is not None,
                           reason="Linux with working bubblewrap only")


def _layout(tmp_path):
    """A fake home, project and gate under tmp_path. Secrets sit next to readable controls."""
    home, proj, gate = tmp_path / "home", tmp_path / "proj", tmp_path / "gate"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "id_ed25519").write_text("KEY")
    (home / ".config" / "gh").mkdir(parents=True)
    (home / ".config" / "gh" / "hosts.yml").write_text("TOKEN")
    (home / ".netrc").write_text("NETRC")
    (home / ".bashrc").write_text("# rc")
    (home / "notes.txt").write_text("home-ok")
    (proj / "sub").mkdir(parents=True)
    (proj / ".env").write_text("SECRET=1")
    (proj / "sub" / ".env.local").write_text("SECRET=2")
    (proj / "notes.txt").write_text("fine")
    (proj / ".git" / "hooks").mkdir(parents=True)
    (proj / ".git" / "config").write_text("[core]\n")
    gate.mkdir()
    (gate / "policy.toml").write_text("p")
    return home, proj, gate


def _lx(tmp_path, code, ports=(6000,), cwd=None, **kw):
    home, proj, gate = tmp_path / "home", tmp_path / "proj", tmp_path / "gate"
    with sbx.linux_sandbox([sys.executable, "-c", code], home=home, gate_home=gate, ledger=gate / "ledger",
                           ports=list(ports), cwd=cwd or proj, **kw) as argv:
        return subprocess.run(argv, capture_output=True, text=True, timeout=60)


def _ok(r, expect=None):
    assert r.returncode == 0, r.stderr
    if expect is not None:
        assert r.stdout.strip() == expect, (r.stdout, r.stderr)


def test_bwrap_args_shape(tmp_path):
    home, proj, gate = _layout(tmp_path)
    a = sbx.bwrap_args(["agent"], home=home, gate_home=gate, ledger=gate / "l", cwd=proj,
                       sock_dir=tmp_path / "s", ports=[6000, 11434], env_files=[proj / ".env"])
    s = " ".join(a)
    for flag in ("--unshare-all", "--die-with-parent", "--new-session", "--cap-drop ALL", "--ro-bind / /"):
        assert flag in s
    assert "--share-net" not in s
    assert f"--bind {proj} {proj}" in s
    assert f"--tmpfs {home / '.ssh'} --remount-ro {home / '.ssh'}" in s
    empty = tmp_path / "s" / "empty"
    assert f"--ro-bind {empty} {home / '.netrc'}" in s and f"--ro-bind {empty} {proj / '.env'}" in s
    # read-only re-binds come after the writable project bind, or the project would win
    assert s.index(f"--bind {proj} {proj}") < s.index(f"--ro-bind {proj / '.git' / 'hooks'}")
    assert s.index(f"--bind {proj} {proj}") < s.index(f"--ro-bind {gate} {gate}")
    assert a[-1] == "agent" and "6000,11434" in a


def test_linux_run_fails_closed_without_bwrap(monkeypatch, tmp_path):
    monkeypatch.setattr(sbx.sys, "platform", "linux")
    monkeypatch.setattr(sbx.shutil, "which", lambda _: None)

    def boom(*a, **k):
        raise AssertionError("must not start anything")
    monkeypatch.setattr(sbx.subprocess, "Popen", boom)
    monkeypatch.setattr(sbx.subprocess, "call", boom)
    rc = sbx.run(["true"], allow_hosts=[], gate_port=6000, model_port=11434,
                 gate_home=tmp_path, ledger=tmp_path / "l")
    assert rc == 2


def test_linux_refuses_cwd_containing_home(tmp_path):
    assert sbx.cwd_problem(tmp_path, tmp_path / "home") is not None
    assert sbx.cwd_problem(tmp_path / "home", tmp_path / "home") is not None
    assert sbx.cwd_problem(tmp_path / "proj", tmp_path / "home") is None


@linux
def test_linux_sandbox_starts_and_is_confined(tmp_path):
    _layout(tmp_path)
    _ok(_lx(tmp_path, "print('alive')"), "alive")
    code = ("import os\nst=dict(l.split(':',1) for l in open('/proc/self/status'))\n"
            "print(st['NoNewPrivs'].strip(), st['CapEff'].strip(), "
            f"os.path.exists('/proc/{os.getpid()}'))")
    _ok(_lx(tmp_path, code), "1 0000000000000000 False")   # no_new_privs, no caps, host pids hidden


@linux
def test_linux_blocks_direct_internet(tmp_path):
    _layout(tmp_path)
    code = ("import socket\ntry:\n socket.create_connection(('1.1.1.1', 443), timeout=5); print('open')\n"
            "except OSError as e:\n print(type(e).__name__, e.errno)")
    r = _lx(tmp_path, code)
    _ok(r)
    assert r.stdout.split()[0] == "OSError" and int(r.stdout.split()[1]) == 101   # ENETUNREACH


@linux
def test_linux_blocks_dns(tmp_path):
    _layout(tmp_path)
    code = ("import socket\ntry:\n socket.getaddrinfo('example.com', 443); print('resolved')\n"
            "except socket.gaierror:\n print('gaierror')")
    _ok(_lx(tmp_path, code), "gaierror")


@linux
def test_linux_allows_listed_loopback_port_only(tmp_path):
    _layout(tmp_path)

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")

        def log_message(self, *a):
            pass
    listed, unlisted = HTTPServer(("127.0.0.1", 0), H), HTTPServer(("127.0.0.1", 0), H)
    for s in (listed, unlisted):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    lp, up = listed.server_address[1], unlisted.server_address[1]
    try:
        code = ("import urllib.request\n"
                f"print(urllib.request.urlopen('http://127.0.0.1:{lp}/', timeout=5).read().decode())\n"
                "try:\n"
                f" urllib.request.urlopen('http://127.0.0.1:{up}/', timeout=5); print('open')\n"
                "except OSError as e:\n print(type(getattr(e, 'reason', e)).__name__)")
        r = _lx(tmp_path, code, ports=[lp])
        _ok(r)
        assert r.stdout.split() == ["ok", "ConnectionRefusedError"], r.stdout
    finally:
        listed.shutdown(); unlisted.shutdown()


@linux
def test_linux_egress_proxy_reachable_and_enforcing(tmp_path):
    _layout(tmp_path)
    srv = make_proxy(["api.anthropic.com"])
    serve_in_background(srv)
    port = srv.server_address[1]
    try:
        code = (f"import http.client\nc=http.client.HTTPConnection('127.0.0.1', {port}, timeout=5)\n"
                "c.request('CONNECT', 'evil.example:443'); print(c.getresponse().status)")
        _ok(_lx(tmp_path, code, ports=[port]), "403")
    finally:
        srv.shutdown()


@linux
def test_linux_hides_secrets_but_not_everything(tmp_path):
    home, proj, _ = _layout(tmp_path)

    def read(p):
        return (f"try:\n print(repr(open({str(p)!r}).read()))\nexcept OSError as e:\n"
                " print(type(e).__name__)")
    for p, want in [(home / "notes.txt", "'home-ok'"), (proj / "notes.txt", "'fine'"),
                    (home / ".ssh" / "id_ed25519", "FileNotFoundError"),
                    (home / ".config" / "gh" / "hosts.yml", "FileNotFoundError"),
                    (home / ".netrc", "''"), (proj / ".env", "''"), (proj / "sub" / ".env.local", "''")]:
        _ok(_lx(tmp_path, read(p)), want)


@linux
def test_linux_blocks_unix_sockets(tmp_path):
    home, _, _ = _layout(tmp_path)
    paths = [str(home / "agent.sock"), f"/tmp/hg-{os.getpid()}.sock"]
    socks = []
    try:
        for p in paths:
            s = socket.socket(socket.AF_UNIX)
            s.bind(p)
            s.listen(1)
            socks.append(s)
            c = socket.socket(socket.AF_UNIX)
            c.connect(p)            # control: reachable from the host
            c.close()
        for p in paths:
            code = (f"import socket\ns=socket.socket(socket.AF_UNIX)\ntry:\n s.connect({p!r}); print('open')\n"
                    "except OSError as e:\n print(type(e).__name__)")
            r = _lx(tmp_path, code)
            _ok(r)
            assert r.stdout.strip() != "open", p
    finally:
        for s in socks:
            s.close()
        for p in paths:
            if os.path.exists(p):
                os.unlink(p)


@linux
def test_linux_write_rules(tmp_path):
    home, proj, gate = _layout(tmp_path)

    def write(p):
        return (f"try:\n open({str(p)!r}, 'a').write('x'); print('wrote')\nexcept OSError as e:\n"
                " print(type(e).__name__, e.errno)")
    _ok(_lx(tmp_path, write(proj / "new.txt")), "wrote")
    _ok(_lx(tmp_path, write("/tmp/scratch.txt")), "wrote")
    for p in (home / "x.txt", home / ".bashrc", gate / "policy.toml", proj / ".git" / "config",
              proj / ".git" / "hooks" / "pre-commit"):
        r = _lx(tmp_path, write(p))
        _ok(r)
        assert r.stdout.split()[0] == "OSError" and int(r.stdout.split()[1]) == 30, (p, r.stdout)  # EROFS
    assert (gate / "policy.toml").read_text() == "p"
    # tmp_path is under /tmp, which is a fresh tmpfs inside: a write there lands in the
    # sandbox's own memory and never reaches the host
    _ok(_lx(tmp_path, write(tmp_path / "outside.txt")))
    assert not (tmp_path / "outside.txt").exists()
    # a repo without a hooks directory must not let the agent create one
    (proj / ".git" / "hooks").rmdir()
    r = _lx(tmp_path, write(proj / ".git" / "hooks" / "pre-commit"))
    _ok(r)
    assert r.stdout.split()[0] == "OSError", r.stdout
    assert not (proj / ".git" / "hooks" / "pre-commit").exists()


@linux
def test_linux_cannot_patch_gate_code_even_from_its_repo(tmp_path):
    _layout(tmp_path)
    import homestead_gate.approval as ap
    target = ap.__file__
    before = open(target).read()
    repo = Path(target).resolve().parents[2]      # an editable install sits inside this cwd
    code = (f"try:\n open({target!r}, 'a').write('# pwned'); print('wrote')\nexcept OSError as e:\n"
            " print(type(e).__name__)")
    _ok(_lx(tmp_path, code, cwd=repo), "OSError")
    assert open(target).read() == before
