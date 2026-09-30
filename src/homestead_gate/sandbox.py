"""`homestead-gate run -- <agent>`: make the gate the agent's only way out (macOS).

The gate only means something if the agent cannot go around it. So the agent runs under
the macOS sandbox (sandbox-exec) with a profile generated here:

  network   outbound only to loopback: the gate, the local model, and the egress proxy.
            No direct internet, no unix sockets (so no ssh-agent, no docker.sock).
  secrets   credential stores are unreadable: ~/.ssh, cloud CLIs, keychains, .env files,
            package-registry tokens, git credentials.
  the gate  the gate's policy, receipts and outbox are read-only to the agent, and shell
            startup files and LaunchAgents cannot be written, so the agent cannot plant
            something that runs later outside the sandbox.

Linux support (bubblewrap) is a later milestone. sandbox-exec is deprecated by Apple but
still ships and is what Chrome and others use; if it ever disappears, `run` refuses to
start rather than running the agent unconfined.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SECRET_READ = [
    ".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker", ".netrc", ".npmrc", ".pypirc",
    ".git-credentials", ".password-store", ".config/gh", ".config/gcloud", ".config/stripe",
    ".config/op", "Library/Keychains",
]
NO_WRITE = [".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile", "Library/LaunchAgents"]


def _q(p: str | Path) -> str:
    return '"' + str(p).replace("\\", "\\\\").replace('"', '\\"') + '"'


def profile(*, home: Path, gate_home: Path, ledger: Path, ports: list[int],
            extra_secret: list[str] = (), allow_read: list[str] = ()) -> str:
    lines = ["(version 1)", "(allow default)", "", ";; network: loopback only, and only these ports",
             "(deny network-outbound)"]
    lines += [f'(allow network-outbound (remote ip "localhost:{p}"))' for p in sorted(set(ports))]
    lines += ["", ";; credential stores"]
    for rel in SECRET_READ + list(extra_secret):
        path = Path(rel).expanduser()
        path = path if path.is_absolute() else home / rel
        lines.append(f"(deny file-read* (subpath {_q(path)}))")
    lines.append('(deny file-read* (regex #"/\\.env$"))')
    lines.append('(deny file-read* (regex #"/\\.env\\.[^/]+$"))')
    lines += ["", ";; the gate's own state, and anything that runs later outside the sandbox"]
    for p in {gate_home, ledger}:
        lines.append(f"(deny file-write* (subpath {_q(p)}))")
    for rel in NO_WRITE:
        lines.append(f"(deny file-write* (subpath {_q(home / rel)}))")
    if allow_read:
        lines += ["", ";; owner-granted exceptions"]
        lines += [f"(allow file-read* (subpath {_q(Path(p).expanduser().resolve())}))" for p in allow_read]
    return "\n".join(lines) + "\n"


def run(cmd: list[str], *, allow_hosts: list[str], gate_port: int, model_port: int,
        gate_home: Path, ledger: Path, allow_read: list[str] = (), pass_env: list[str] = (),
        on_deny=None) -> int:
    if sys.platform != "darwin":
        print("homestead-gate run: macOS only for now (Linux via bubblewrap is next). "
              "Refusing to run the agent unconfined.", file=sys.stderr)
        return 2
    if not shutil.which("sandbox-exec"):
        print("homestead-gate run: sandbox-exec not found. Refusing to run the agent unconfined.",
              file=sys.stderr)
        return 2
    from .egress import make_proxy, serve_in_background

    proxy = make_proxy(allow_hosts, on_deny or (lambda h, why: None))
    serve_in_background(proxy)
    pport = proxy.server_address[1]
    prof = profile(home=Path.home(), gate_home=gate_home, ledger=ledger,
                   ports=[gate_port, model_port, pport], allow_read=allow_read)
    with tempfile.NamedTemporaryFile("w", suffix=".sb", delete=False) as f:
        f.write(prof)
    env = dict(os.environ)
    url = f"http://127.0.0.1:{pport}"
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        env[k] = url
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
    env["HOMESTEAD_GATE_URL"] = f"http://127.0.0.1:{gate_port}"
    for k in list(env):          # don't hand the agent credentials through its environment
        if any(s in k.upper() for s in ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "PRIVATE_KEY")) \
                and k not in pass_env:
            env.pop(k)
    print(f"homestead-gate run: sandboxed. internet only via {', '.join(allow_hosts) or 'nothing'}; "
          f"gate on :{gate_port}.", file=sys.stderr)
    try:
        return subprocess.call(["sandbox-exec", "-f", f.name, *cmd], env=env)
    finally:
        proxy.shutdown()
        os.unlink(f.name)
