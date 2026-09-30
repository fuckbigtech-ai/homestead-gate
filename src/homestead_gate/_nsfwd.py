"""Loopback bridge for the Linux sandbox. Standard library only: it runs inside bubblewrap.

The agent runs in its own network namespace (`bwrap --unshare-net`), which has a loopback
interface and nothing else: no route out, no DNS, and none of the host's loopback ports.
The gate, the local model and the egress proxy live on the HOST loopback, so they are
bridged in through unix sockets, one per allowed port:

  host   `serve_unix(dir/<port>, port)`: accept on a unix socket, connect to 127.0.0.1:<port>.
  inside `python _nsfwd.py <dir> <port,port,...> -- <agent>`: listen on 127.0.0.1:<port> in
         the namespace, forward each connection to <dir>/<port>, then run the agent.

The inner listeners are bound before the agent starts, so the ports are there from its
first instruction. Only the listed ports exist inside; everything else is refused.
"""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import sys
import threading


def pump(a: socket.socket, b: socket.socket) -> None:
    """Copy bytes both ways until both sides are done, then close both."""
    def one_way(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    t = threading.Thread(target=one_way, args=(b, a), daemon=True)
    t.start()
    one_way(a, b)
    t.join()
    a.close()
    b.close()


def _accept_loop(listener: socket.socket, connect) -> None:
    while True:
        try:
            conn, _ = listener.accept()
        except OSError:
            return              # listener closed
        try:
            upstream = connect()
        except OSError:
            conn.close()
            continue
        threading.Thread(target=pump, args=(conn, upstream), daemon=True).start()


def serve_unix(path: str, port: int) -> socket.socket:
    """Host side: a unix socket at `path` that forwards to 127.0.0.1:<port>."""
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(64)

    def connect():
        return socket.create_connection(("127.0.0.1", port), timeout=15)
    threading.Thread(target=_accept_loop, args=(srv, connect), daemon=True).start()
    return srv


def _serve_tcp(sock_dir: str, port: int) -> list[socket.socket]:
    """Inside the namespace: 127.0.0.1:<port> (and ::1 when present) -> <sock_dir>/<port>."""
    path = os.path.join(sock_dir, str(port))

    def connect():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
        return s
    out = []
    for fam, addr in ((socket.AF_INET, ("127.0.0.1", port)), (socket.AF_INET6, ("::1", port))):
        try:
            s = socket.socket(fam, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(addr)
            s.listen(64)
        except OSError:
            if fam == socket.AF_INET:
                raise           # IPv4 loopback is required; IPv6 is a convenience
            continue
        threading.Thread(target=_accept_loop, args=(s, connect), daemon=True).start()
        out.append(s)
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 4 or argv[2] != "--":
        print("usage: _nsfwd.py <sock-dir> <port,port> -- <cmd>", file=sys.stderr)
        return 2
    sock_dir, ports = argv[0], [int(p) for p in argv[1].split(",") if p]
    cmd = argv[3:]
    for p in ports:
        _serve_tcp(sock_dir, p)
    try:
        child = subprocess.Popen(cmd)
    except OSError as e:
        print(f"homestead-gate run: cannot start {cmd[0]!r}: {e}", file=sys.stderr)
        return 127
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda s, _f: child.send_signal(s))
    rc = child.wait()
    return 128 - rc if rc < 0 else rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
