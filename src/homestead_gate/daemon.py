"""Loopback HTTP front door for agents. One route: POST /v1/request.

There is no approve route, on purpose (see approval.py). Requests carrying an Origin
header are refused, because that header means a browser page is making the call, and
no web page has any business asking a local gate to send mail.

The call blocks until the request is executed, denied or expires, so an agent sees one
answer per action and never has to poll.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import Gate

MAX_BODY = 256 * 1024


def make_server(gate: Gate, host: str = "127.0.0.1", port: int = 6000) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError("the gate only listens on loopback")

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, code: int, obj: dict) -> None:
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):  # noqa: N802
            if self.path != "/v1/request":
                return self._reply(404, {"error": "only POST /v1/request exists"})
            if self.headers.get("Origin"):
                return self._reply(403, {"error": "browser requests are refused"})
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_BODY:
                return self._reply(413 if n > MAX_BODY else 400, {"error": "bad body size"})
            try:
                req = json.loads(self.rfile.read(n))
                assert isinstance(req, dict) and isinstance(req.get("action"), dict)
            except (ValueError, AssertionError):
                return self._reply(400, {"error": "body must be JSON with an 'action' object"})
            res = gate.submit(req)
            self._reply(200, res)

        def do_GET(self):  # noqa: N802
            if self.path == "/v1/health":
                return self._reply(200, {"ok": True})
            self._reply(404, {"error": "not found"})

        def log_message(self, *a):  # keep the approval terminal readable
            pass

    return ThreadingHTTPServer((host, port), Handler)
