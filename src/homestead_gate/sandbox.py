"""`homestead-gate run -- <agent>`: make the gate the agent's only way out (macOS, Linux).

The gate only means something if the agent cannot go around it. So the agent runs under
the macOS sandbox (sandbox-exec) with a profile generated here:

  network   outbound only to loopback: the gate, the local model, and the egress proxy.
            No direct internet, no DNS, no unix sockets (so no ssh-agent, no docker.sock).
  secrets   credential stores are unreadable: ~/.ssh, cloud CLIs, keychains, .env files,
            package-registry tokens, git credentials.
  the gate  the gate's policy, receipts, outbox and its own code are read-only to the agent.
  later     known places that run code later outside the sandbox are read-only: shell
            startup files, LaunchAgents, ~/bin and ~/.local/bin, git config and this repo's
            .git/hooks, Claude Code settings and hooks. A denylist, so known places only.
  services  no LaunchServices (`open`) and no Apple Events, which would start things
            outside the sandbox.

sandbox-exec is deprecated by Apple but still ships and is what Chrome and others use; if
it ever disappears, `run` refuses to start rather than running the agent unconfined.

Linux uses bubblewrap (bwrap) instead, with the same aims where Linux allows. See
`linux_sandbox` for the design and the README for what it does not cover. If bwrap is
missing or cannot create namespaces on this kernel, `run` refuses to start.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

SECRET_READ = [
    ".ssh", ".aws", ".gnupg", ".azure", ".kube", ".docker", ".netrc", ".npmrc", ".pypirc",
    ".git-credentials", ".password-store", ".config/gh", ".config/gcloud", ".config/stripe",
    ".config/op", "Library/Keychains",
]
# Places that run code LATER, outside the sandbox. A denylist on top of (allow default), so
# it covers the known ones, not every possible one; the README says so.
NO_WRITE = [".zshrc", ".zprofile", ".zshenv", ".bashrc", ".bash_profile", ".profile", "Library/LaunchAgents",
            ".local/bin", "bin", ".gitconfig", ".config/git",
            ".claude/settings.json", ".claude/settings.local.json", ".claude/hooks"]


def own_code_paths() -> list[Path]:
    """The gate's own code, found at runtime: patch approval.py and the next `up` approves
    everything. Covers this package, homestead-memory, and the interpreter's environment."""
    import homestead_memory
    from . import __file__ as me
    paths = {Path(me).resolve().parent, Path(homestead_memory.__file__).resolve().parent,
             Path(sys.prefix).resolve()}
    return sorted(paths)


def _q(p: str | Path) -> str:
    return '"' + str(p).replace("\\", "\\\\").replace('"', '\\"') + '"'


def profile(*, home: Path, gate_home: Path, ledger: Path, ports: list[int],
            extra_secret: list[str] = (), allow_read: list[str] = ()) -> str:
    lines = ["(version 1)", "(allow default)", "", ";; network: loopback only, and only these ports",
             "(deny network-outbound)"]
    lines += [f'(allow network-outbound (remote ip "localhost:{p}"))' for p in sorted(set(ports))]
    # system services that would start something OUTSIDE the sandbox on the agent's behalf:
    # LaunchServices (`open https://...?data` hands the URL to your unsandboxed browser) and
    # Apple Events (`tell application "Mail" to send`, which would skip the gate entirely).
    lines += ["", ";; no launching apps or URLs, no Apple Events", "(deny lsopen)", "(deny appleevent-send)"]
    lines += ["", ";; credential stores"]
    for rel in SECRET_READ + list(extra_secret):
        path = Path(rel).expanduser()
        path = path if path.is_absolute() else home / rel
        lines.append(f"(deny file-read* (subpath {_q(path)}))")
    # the gate's own sender settings (host/user; the password is in the OS store, not here)
    lines.append(f"(deny file-read* (literal {_q(Path(gate_home) / 'smtp.toml')}))")
    lines.append('(deny file-read* (regex #"/\\.env$"))')
    lines.append('(deny file-read* (regex #"/\\.env\\.[^/]+$"))')
    lines += ["", ";; the gate's own state, and anything that runs later outside the sandbox"]
    for p in sorted({Path(gate_home), Path(ledger), *own_code_paths()}):
        lines.append(f"(deny file-write* (subpath {_q(p)}))")
    for p in (Path.cwd() / ".git" / "hooks", Path.cwd() / ".git" / "config"):
        lines.append(f"(deny file-write* (subpath {_q(p.resolve())}))")
    for rel in NO_WRITE:
        lines.append(f"(deny file-write* (subpath {_q(home / rel)}))")
    if allow_read:
        lines += ["", ";; owner-granted exceptions"]
        lines += [f"(allow file-read* (subpath {_q(Path(p).expanduser().resolve())}))" for p in allow_read]
    return "\n".join(lines) + "\n"


def _agent_env(proxy_port: int, gate_port: int, pass_env: list[str]) -> dict[str, str]:
    env = dict(os.environ)
    url = f"http://127.0.0.1:{proxy_port}"
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        env[k] = url
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
    env["HOMESTEAD_GATE_URL"] = f"http://127.0.0.1:{gate_port}"
    for k in list(env):          # don't hand the agent credentials through its environment
        if any(s in k.upper() for s in ("TOKEN", "SECRET", "PASSWORD", "API_KEY", "PRIVATE_KEY")) \
                and k not in pass_env:
            env.pop(k)
    return env


# ---- Linux: bubblewrap ------------------------------------------------------------------
#
# Design (the README lists what it does not cover):
#
#   network  `--unshare-all` gives the agent its own network namespace: a loopback
#            interface and nothing else. No route out, no DNS (resolv.conf points at a
#            resolver that does not exist in there), no host loopback ports, and no
#            abstract unix sockets (those are per namespace). The gate, model and egress
#            proxy are bridged in through unix sockets, one per port (see _nsfwd.py); a
#            small forwarder inside listens on 127.0.0.1:<port> before the agent starts.
#   files    `/` is mounted read-only. Fresh, empty tmpfs over /tmp, /var/tmp and /run
#            (and /var/run when it is a real directory), which hides the host's unix
#            sockets there: docker.sock, the D-Bus and systemd --user buses (which can
#            start programs outside the sandbox), gpg-agent and ssh-agent. Any other live
#            unix socket the kernel lists at launch is covered with an empty file. Writable:
#            the current directory, $TMPDIR and --allow-write paths, and nothing else.
#            Credential stores are covered with an empty read-only tmpfs (directories) or
#            an empty read-only file (files). bwrap cannot match a pattern, so .env files are found at
#            launch (the current directory tree and the top of $HOME) and covered one by
#            one.
#   the gate its state, its code, this repo's .git/hooks and .git/config, and the places
#            that run code later are bound read-only again after the writable binds, so a
#            writable parent cannot expose them.
#   process  new pid, ipc, uts, user and cgroup namespaces (the agent cannot see or signal
#            your other processes), all capabilities dropped, no_new_privs (bwrap always
#            sets it), a new session (no typing into your terminal with TIOCSTI), and the
#            sandbox dies with the gate.

LINUX_SECRET_READ = [".local/share/keyrings", ".config/hub", ".cargo/credentials",
                     ".cargo/credentials.toml"]
# Trees replaced by an empty tmpfs inside the sandbox. They hold the host's unix sockets.
LINUX_TMPFS = ["/tmp", "/var/tmp", "/run", "/var/run"]
BRIDGE_IN = "/run/homestead-gate"
_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
              ".pytest_cache", ".cache"}


def _under(p: Path, root: Path) -> bool:
    return p == root or root in p.parents


def _tmpfs_trees() -> list[Path]:
    # On most distros /var/run is a symlink to /run; mounting over the link would be wrong.
    return [Path(t) for t in LINUX_TMPFS if Path(t).is_dir() and not Path(t).is_symlink()]


def _find_env_files(roots: list[Path], max_dirs: int = 20000) -> list[Path]:
    """`.env` and `.env.*` under each root, skipping VCS, dependency and cache trees."""
    found, seen = [], 0
    for root in roots:
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in _SKIP_DIRS]
            seen += 1
            if seen > max_dirs:
                print(f"homestead-gate run: stopped looking for .env files after {max_dirs} "
                      "directories; ones deeper in are readable.", file=sys.stderr)
                return found
            found += [Path(d) / f for f in files if f == ".env" or f.startswith(".env.")]
    return found


def _live_unix_sockets() -> list[Path]:
    """Filesystem unix sockets the kernel knows about in this network namespace."""
    out = set()
    try:
        with open("/proc/net/unix") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 8 and parts[7].startswith("/"):
                    out.add(Path(os.path.realpath(parts[7])))   # /var/run/x is /run/x
    except OSError:
        pass
    import stat
    live = []
    for p in sorted(out):
        try:
            if stat.S_ISSOCK(os.lstat(p).st_mode):
                live.append(p)
        except OSError:
            pass
    return live


def bwrap_args(cmd: list[str], *, home: Path, gate_home: Path, ledger: Path, cwd: Path,
               sock_dir: Path, ports: list[int], tmpdir: str | None = None,
               allow_read: list[str] = (), allow_write: list[str] = (), extra_secret: list[str] = (),
               env_files: list[Path] = (), sockets: list[Path] = ()) -> list[str]:
    """The full bwrap command line. Later mounts cover earlier ones, so the order matters."""
    home, cwd = Path(home), Path(cwd)
    a = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
         "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc"]
    trees = _tmpfs_trees()
    for t in trees:
        a += ["--tmpfs", str(t)]
    rebound: list[Path] = []
    if home.is_dir():                    # home is visible read-only even if it lives in /tmp
        a += ["--ro-bind", str(home), str(home)]
        rebound.append(home)
    a += ["--ro-bind", str(sock_dir), BRIDGE_IN]
    # writable: the project, $TMPDIR, owner-granted paths
    writable = [cwd]
    if tmpdir:
        td = Path(tmpdir).resolve()
        if td.is_dir() and td not in trees:   # $TMPDIR=/tmp means the fresh tmpfs, not the host's
            writable.append(td)
    writable += [Path(p).expanduser().resolve() for p in allow_write]
    for w in writable:
        if w.exists():
            a += ["--bind", str(w), str(w)]
            rebound.append(w)
    # read-only again: the gate, its code, and places that run code later
    ro = {Path(gate_home), Path(ledger), *own_code_paths()}
    ro |= {home / rel for rel in NO_WRITE}
    git = cwd / ".git"
    ro |= {git / "hooks", git / "config"}
    for p in sorted(ro):
        if p.exists():
            a += ["--ro-bind", str(p), str(p)]

    def visible(p: Path) -> bool:
        hidden = any(_under(p, t) for t in trees) and not any(_under(p, r) for r in rebound)
        return not hidden and p.exists()

    # credential stores, .env files, live sockets: covered. Files get an empty read-only
    # file (bwrap mounts binds nodev, so /dev/null itself would not open).
    empty = Path(sock_dir) / "empty"
    for rel in SECRET_READ + LINUX_SECRET_READ + list(extra_secret):
        p = Path(rel).expanduser()
        p = p if p.is_absolute() else home / rel
        p = Path(os.path.realpath(p))    # ~/.ssh -> ~/dotfiles/ssh: cover the real directory
        if not visible(p):
            continue
        if p.is_dir():
            a += ["--tmpfs", str(p), "--remount-ro", str(p)]
        else:
            a += ["--ro-bind", str(empty), str(p)]
    for p in list(env_files) + list(sockets):
        if visible(p) and not p.is_dir():
            a += ["--ro-bind", str(empty), str(p)]
    for p in allow_read:
        rp = Path(p).expanduser().resolve()
        if rp.exists():
            a += ["--ro-bind", str(rp), str(rp)]
    fwd = Path(__file__).with_name("_nsfwd.py")
    a += ["--chdir", str(cwd), "--", sys.executable, "-I", str(fwd), BRIDGE_IN,
          ",".join(str(p) for p in sorted(set(ports))), "--", *cmd]
    return a


_BWRAP_PROBE = ["bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--cap-drop", "ALL",
                "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true"]


def bwrap_problem() -> str | None:
    """None if bwrap can build the sandbox here, otherwise why not."""
    if not shutil.which("bwrap"):
        return "bwrap (bubblewrap) not found"
    try:
        r = subprocess.run(_BWRAP_PROBE, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        return f"bwrap failed to start: {e}"
    if r.returncode != 0:
        return ("bwrap cannot create namespaces here (" + (r.stderr.strip() or f"exit {r.returncode}") +
                "). On Ubuntu 24.04+ check kernel.apparmor_restrict_unprivileged_userns and the "
                "bwrap AppArmor profile")
    return None


def cwd_problem(cwd: Path, home: Path) -> str | None:
    cwd, home = Path(cwd).resolve(), Path(home).resolve()
    if _under(home, cwd):
        return (f"the current directory {cwd} contains your home directory, and it would be "
                "writable. Run from a project directory")
    return None


@contextmanager
def linux_sandbox(cmd: list[str], *, home: Path, gate_home: Path, ledger: Path, ports: list[int],
                  cwd: Path | None = None, allow_read: list[str] = (), allow_write: list[str] = ()):
    """Start the host side of the loopback bridge and yield the bwrap command line."""
    from ._nsfwd import serve_unix
    cwd = Path(cwd or Path.cwd()).resolve()
    home = Path(home)
    hooks = cwd / ".git" / "hooks"
    if hooks.parent.is_dir() and not hooks.exists():
        hooks.mkdir()       # a missing path can't be mounted over, and the project is writable
    sock_dir = Path(tempfile.mkdtemp(prefix="homestead-gate-bridge-"))
    servers = []
    try:
        (sock_dir / "empty").touch(mode=0o444)
        for p in sorted(set(ports)):
            servers.append(serve_unix(str(sock_dir / str(p)), p))
        env_files = _find_env_files([cwd]) + [p for p in home.glob(".env*")
                                              if p.name == ".env" or p.name.startswith(".env.")]
        yield bwrap_args(cmd, home=home, gate_home=gate_home, ledger=ledger, cwd=cwd,
                         sock_dir=sock_dir, ports=ports, tmpdir=os.environ.get("TMPDIR"),
                         allow_read=allow_read, allow_write=allow_write, env_files=env_files,
                         sockets=_live_unix_sockets())
    finally:
        for s in servers:
            s.close()
        shutil.rmtree(sock_dir, ignore_errors=True)


def _run_linux(cmd, *, allow_hosts, gate_port, model_port, gate_home, ledger, allow_read,
               allow_write, pass_env, on_deny) -> int:
    problem = bwrap_problem() or cwd_problem(Path.cwd(), Path.home())
    if problem:
        print(f"homestead-gate run: {problem}. Refusing to run the agent unconfined.", file=sys.stderr)
        return 2
    from .egress import make_proxy, serve_in_background

    proxy = make_proxy(allow_hosts, on_deny or (lambda h, why: None))
    serve_in_background(proxy)
    pport = proxy.server_address[1]
    env = _agent_env(pport, gate_port, pass_env)
    print(f"homestead-gate run: sandboxed (bubblewrap). internet only via "
          f"{', '.join(allow_hosts) or 'nothing'}; gate on :{gate_port}.", file=sys.stderr)
    try:
        with linux_sandbox(cmd, home=Path.home(), gate_home=gate_home, ledger=ledger,
                           ports=[gate_port, model_port, pport], allow_read=allow_read,
                           allow_write=allow_write) as argv:
            p = subprocess.Popen(argv, env=env)
            try:
                return p.wait()
            except KeyboardInterrupt:
                p.kill()          # --die-with-parent and the pid namespace take the rest down
                return p.wait()
    finally:
        proxy.shutdown()


def run(cmd: list[str], *, allow_hosts: list[str], gate_port: int, model_port: int,
        gate_home: Path, ledger: Path, allow_read: list[str] = (), pass_env: list[str] = (),
        allow_write: list[str] = (), on_deny=None) -> int:
    if sys.platform.startswith("linux"):
        return _run_linux(cmd, allow_hosts=allow_hosts, gate_port=gate_port, model_port=model_port,
                          gate_home=gate_home, ledger=ledger, allow_read=allow_read,
                          allow_write=allow_write, pass_env=pass_env, on_deny=on_deny)
    if sys.platform != "darwin":
        print(f"homestead-gate run: no sandbox for {sys.platform}. "
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
    env = _agent_env(pport, gate_port, pass_env)
    print(f"homestead-gate run: sandboxed. internet only via {', '.join(allow_hosts) or 'nothing'}; "
          f"gate on :{gate_port}.", file=sys.stderr)
    try:
        return subprocess.call(["sandbox-exec", "-f", f.name, *cmd], env=env)
    finally:
        proxy.shutdown()
        os.unlink(f.name)
