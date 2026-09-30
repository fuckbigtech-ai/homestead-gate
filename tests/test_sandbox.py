import http.client
import shutil
import socket
import subprocess
import sys
import threading
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
