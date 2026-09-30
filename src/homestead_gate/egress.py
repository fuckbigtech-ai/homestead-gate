"""Allowlisting HTTPS proxy: the sandboxed agent's only road to the internet.

The sandbox lets the agent open connections to loopback and nothing else, so it cannot
reach any host directly. This proxy, on loopback, tunnels CONNECT requests to hosts on
the allowlist (for example api.anthropic.com, so Claude Code can still think) and refuses
everything else. Plain-HTTP requests are refused outright: nothing an agent needs should
travel unencrypted, and a plain request is the easiest way to smuggle data in a URL.

Every refusal is reported through `on_deny`, which `run` writes to the receipts ledger.
"""
from __future__ import annotations

import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable


def host_allowed(host: str, allow: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for a in allow:
        a = a.lower()
        if a.startswith("*."):
            if host.endswith(a[1:]) and host != a[2:]:
                return True
        elif host == a:
            return True
    return False


def make_proxy(allow: list[str], on_deny: Callable[[str, str], None] = lambda h, why: None,
               port: int = 0) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def _refuse(self, target: str, why: str):
            on_deny(target, why)
            self.send_error(403, f"homestead-gate: {why}")

        def do_CONNECT(self):  # noqa: N802
            host, _, port_s = self.path.rpartition(":")
            if not host or port_s != "443":
                return self._refuse(self.path, "only port 443 is tunnelled")
            if not host_allowed(host, allow):
                return self._refuse(host, "host not on the allowlist")
            try:
                upstream = socket.create_connection((host, 443), timeout=15)
            except OSError as e:
                return self.send_error(502, f"upstream: {e}")
            self.send_response(200, "Connection Established")
            self.end_headers()
            conns = [self.connection, upstream]
            try:
                while True:
                    ready, _, err = select.select(conns, [], conns, 300)
                    if err or not ready:
                        break
                    for s in ready:
                        data = s.recv(65536)
                        if not data:
                            return
                        (upstream if s is self.connection else self.connection).sendall(data)
            except OSError:
                pass
            finally:
                upstream.close()

        def _plain(self):
            self._refuse(self.path[:200], "plain http is not allowed")

        do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = _plain  # noqa: N815

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    return srv


def serve_in_background(srv: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return t
