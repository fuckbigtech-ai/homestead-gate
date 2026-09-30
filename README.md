# homestead-gate

A 2-of-2 approval gate for AI agents: nothing an agent sends (email, posts, payments, wallet
transactions) leaves your machine until a local model has reviewed it **and** you have said yes.
Part of [fuckbigtech.ai](https://fuckbigtech.ai), alongside
[homestead-memory](https://github.com/fuckbigtech-ai/homestead-memory).

This repo starts with the evidence, not the product: **[GateBench](bench/)**, an open benchmark
that asks whether a small local model can catch a hijacked agent before it acts.

**v0.1 headline:** Qwen 3.5 9B (6.6GB, running on an 18GB laptop) blocked 30 of 30 attacks and
0 of 30 legitimate actions across three repeats. Full numbers in
[bench/RESULTS.md](bench/RESULTS.md), and read the limits in [bench/README.md](bench/README.md)
before quoting them.

Found an attack that gets through? Open a pull request with a new case. That's the point.

## The gate (in development, not released)

```bash
pip install -e .                         # PyPI release comes later
homestead-gate up                        # set up, then run the gate on 127.0.0.1:6000
homestead-gate doctor                    # one-screen health check
homestead-gate demo                      # a hijacked agent vs the gate, in a throwaway ledger
homestead-gate watch                     # the receipts; exits 1 if anyone edited them
```

`homestead-gate up` checks your machine, then picks a reviewer that fits it:

- **`qwen3.5:9b`** (6.6GB) if it fits comfortably. This is the model GateBench measured: 30/30
  attacks blocked, 0/30 false blocks, about 3.5s per review on an M3 Pro 18GB.
- **`nemotron-3-nano:4b`** (2.8GB) on smaller machines, such as an 8GB Mac. It also blocked 30/30
  attacks, but it false-blocked 3/30 legitimate requests (10%), so you get asked more often.
- **Neither:** if even the 4B needs more memory than the machine can give a model (it needs about
  4.1GB), `up` refuses to run. It also refuses a model from `--model` or an existing policy that
  does not fit.

If `~/.homestead-gate/policy.toml` does not exist, `up` asks for your email and wallet address.
It then writes the policy from `policy.example.toml`.

Next it checks that Ollama is installed and running. If the reviewer model is missing, `up`
prints the exact `ollama pull` command and the download size. It downloads nothing unless you pass
`--pull`. With `--pull`, the download goes through `model-load-guard` when that tool is on your
PATH.

`up` asks for the task. The reviewer trusts only this, and it comes from you, never from the agent.
Then the gate starts.

To run without prompts:

```bash
homestead-gate up --yes --email you@example.com --task "email me a summary of today's inbox"
homestead-gate up --yes --email you@example.com --dry-run    # show what it would do; change nothing
```

Give your agent the gate as its only way to send (Claude Code shown; any MCP client works):

```bash
claude mcp add homestead-gate -- homestead-gate mcp
```

It gets two tools, `gate_send_email` and `gate_prepare_wallet_tx`. Each call waits for your
decision in the gate's terminal, so raise your client's tool timeout if you like to think
(Claude Code: `MCP_TOOL_TIMEOUT=600000`).

Or call the gate directly with `POST http://127.0.0.1:6000/v1/request`:

```json
{"action": {"type": "email", "to": "me@example.com", "subject": "...", "body": "..."},
 "read":   [{"source": "web page", "content": "what the agent read while working"}]}
```

Each request goes through, in order:

1. **Policy** (`policy.example.toml`). Mail to yourself passes. Wrong chain, value over the cap,
   oversized calldata and too many actions per hour are denied without asking anyone.
2. **The local model**, with the exact prompt and settings GateBench measured. If it can't be
   reached or gives no clear answer, that counts as a flag.
3. **You**, in the terminal you started the gate in. Approving something the model flagged takes
   a typed phrase, a 60 second wait and a second yes.
4. **A receipt** in the [homestead-memory](https://github.com/fuckbigtech-ai/homestead-memory)
   ledger, written and fsynced **before** anything runs. A deny is on disk before the agent
   hears no.

In this version email is dry-run (written to `~/.homestead-gate/outbox`) and wallet transactions
are prepared for Sepolia only, unsigned. The gate holds no keys.

### Make the gate the only way out (macOS and Linux)

```bash
homestead-gate run --allow-host api.anthropic.com --allow-read ~/Library/Keychains -- claude
```

The agent runs in the macOS sandbox, and the profile blocks:

- **network:** everything except the gate, the local model and the hosts you allow (through a
  small proxy on your machine). No direct internet, no DNS, no ssh-agent or Docker socket.
- **secrets:** reading `~/.ssh`, cloud CLI credentials, `.env` files, registry tokens and git
  credentials. Secret-looking environment variables are dropped unless you pass `--pass-env`.
- **the gate itself:** writing its policy, receipts or its own code.
- **known places that run code later:** shell startup files, LaunchAgents, `~/bin`,
  `~/.local/bin`, git config and this repo's `.git/hooks`, Claude Code's settings and hooks.
- **system services that act outside the sandbox:** opening apps or URLs (`open`) and Apple
  Events (for example telling Mail to send).

Every blocked connection is written to the receipts. The file rules are a list of known places
on top of "allow everything else", so they stop what they name, not everything.

Claude Code keeps its login in the macOS keychain, hence `--allow-read ~/Library/Keychains`.
That also lets the agent ask the keychain for other items; macOS prompts you for most of them,
but read the prompt before you click.

#### Linux (bubblewrap)

```bash
sudo apt install bubblewrap              # or your distro's package
cd ~/code/my-project && homestead-gate run --allow-host api.anthropic.com -- <agent>
```

On Linux `run` uses [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`). If bwrap
is missing, or the kernel will not let it create namespaces, `run` refuses to start. It never
runs the agent unconfined. The design:

- **network:** the agent gets its own network namespace, with a loopback interface and nothing
  else. It has no route out and no DNS, and it cannot reach your machine's loopback ports. The
  gate, the local model and the egress proxy come in through one unix socket per port. A small
  forwarder inside the sandbox listens on `127.0.0.1:<port>` before the agent starts. Only those
  ports exist in there.
- **files:** `/` is read-only. `/tmp`, `/var/tmp` and `/run` are fresh and empty. That hides the
  host's unix sockets there: the Docker socket, the D-Bus and `systemd --user` buses (which can
  start programs outside the sandbox, like `open` on macOS), gpg-agent and ssh-agent. Any other
  unix socket that is live at launch is covered with an empty file. The agent can write only
  to the current directory, `$TMPDIR` and paths you pass with `--allow-write`.
- **secrets:** the same credential stores as on macOS, plus `~/.local/share/keyrings`,
  `~/.config/hub` and cargo's credentials, are covered with empty read-only mounts. A store
  that is a symlink (dotfile managers do this) is covered where it really lives.
- **the gate itself, and places that run code later:** read-only, bound again after the
  writable mounts. This covers the gate's state and code, this repo's `.git/hooks` and
  `.git/config`, shell startup files, `~/bin`, `~/.local/bin`, git config and Claude Code
  settings and hooks. It holds even when the gate's code is inside the current directory.
- **processes:** new pid, IPC, UTS, user and cgroup namespaces, so the agent cannot see or
  signal your other processes. All capabilities are dropped, `no_new_privs` is set, the
  sandbox gets a new session (no typing into your terminal with `TIOCSTI`), and it dies with
  `homestead-gate`.

`run` refuses to start if the current directory is your home directory or contains it,
because that directory is writable.

Gaps on Linux, beyond the list below:

- **`.env` files are found once, at launch.** bwrap cannot match a pattern, so `run` looks for
  `.env` and `.env.*` in the current directory tree and at the top of `$HOME`, and covers each
  one. It skips `.git`, `node_modules`, virtualenvs and caches, and stops after 20,000
  directories. `.env` files anywhere else, for example in your other projects, are readable.
  On macOS the rule matches every path.
- **The credential list is a list.** Anything readable that it does not name is readable, for
  example `~/.codex/auth.json`, `~/.claude/.credentials.json` or browser profiles.
- **Sockets are covered once, at launch.** A socket created later outside `/tmp`, `/var/tmp`
  and `/run` is reachable.
- **Missing files cannot be protected.** A mount needs something to mount over. If a protected
  path does not exist and it sits inside a writable directory, the agent can create it. The
  `.git/hooks` directory is created before launch for this reason.
- **Git worktrees:** when `.git` is a file, the real git directory is elsewhere and read-only,
  so commits from inside the sandbox fail.
- **Terminal programs:** the new session means the agent has no controlling terminal. On a
  test box, raw mode on stdin worked, but `/dev/tty` failed to open, there was no job control,
  and window resizes are not passed on. Full-screen agent UIs may misbehave.
- **Claude Code on Linux is untested.** It writes `~/.claude/` and replaces `~/.claude.json`
  by renaming a file in `$HOME`. Your home directory is read-only, so expect it to need
  `--allow-write ~/.claude`. The `~/.claude.json` rename may still fail.
- **Namespaces must be allowed.** Ubuntu 24.04 and later restrict unprivileged user
  namespaces (`kernel.apparmor_restrict_unprivileged_userns`). The packaged bwrap ships an
  AppArmor profile for this. If yours does not, `run` stops and says so.
- **Don't run it as root.** Root inside the sandbox still owns root's files for reading.
- **The kernel is shared.** A kernel exploit escapes any namespace sandbox.
- Tested on Ubuntu (kernel 6.8, bubblewrap 0.9.0).

### Credential custody: the gate holds the keys, not the agent

```bash
homestead-gate creds set-smtp --host smtp.example.com --user you@example.com   # you type the password into the OS prompt
homestead-gate up --live --task "..."                                           # approved mail is really sent
```

If the agent holds your email password or an API token, it can send without asking the gate. So the
gate keeps them: the password goes into the macOS keychain (Linux: libsecret) under the gate's own
entry, restricted to the gate's program. The agent's environment never contains it, the sandbox hides
the gate's settings file, and the password is never an argument, a log line or a receipt. The gate
only sends as the user it protects: if the stored account isn't the policy's email, `--live` refuses
to start. Without `--live`, approved mail still goes to a local outbox.

Limits: another program running as you can still ask the keychain for the entry. macOS answers with
a visible permission dialog rather than the password, so say no to anything that isn't the gate. A
compromised gate process has the password. Linux needs libsecret; there is no plaintext fallback.

### What it does not defend against

- **An agent that can reach your accounts some other way.** If the agent has your SMTP password,
  API tokens or a wallet key, it can skip the gate. Use `homestead-gate run`; without it, the
  gate only works for agents that choose to use it. An allowed host is still a way out: anything
  the agent can send to `api.anthropic.com` leaves your machine.
- **An unsandboxed agent running as you.** Approval happens only in the gate's terminal (there is
  no approve endpoint), but outside `homestead-gate run` an agent can stop or reconfigure the gate.
  Inside it on macOS, it can still send signals to your other processes; the sandbox limits files
  and network, not everything. On Linux the agent has its own pid namespace and cannot see them.
- **An agent that hides what it read.** The model sees what the agent reports reading. A hijacked
  agent can leave the injection out, and then the model judges the action against your task alone.
  Your task comes from you when you start the gate, never from the agent.
- **Multi-part requests.** The reviewer judges each action against the whole request, so for
  "pay the contractor and register my name" it can block the payment as incomplete. Give the gate one
  task at a time for now; a fix is being measured against the frozen benchmark before it ships.
- **Anything sent to an allowed host.** `api.anthropic.com` is a way out too, and a host on a
  shared CDN can front for other sites on the same CDN. Allow as few hosts as you can.
- **Places the file rules don't name.** Claude Code rewrites `~/.claude.json` constantly, so it
  can't be locked, and it can register new MCP servers that start outside the sandbox next time.
  Check `claude mcp list` if something looks off.
- **A rebuilt ledger.** Someone with your files can rewrite the whole chain consistently. Run
  `hsm checkpoint` to sign it, and keep the signature somewhere they can't reach.
- **Attacks GateBench doesn't cover.** 30 attacks, one step each, written by us. See the bench limits.

MIT licensed.
