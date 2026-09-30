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
ollama pull qwen3.5:9b                   # the reviewer GateBench measured (6.6GB)
homestead-gate demo                      # a hijacked agent vs the gate, in a throwaway ledger
homestead-gate up --task "email me a summary of today's inbox"   # gate on 127.0.0.1:6000
homestead-gate watch                     # the receipts; exits 1 if anyone edited them
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

### Make the gate the only way out (macOS)

```bash
homestead-gate run --allow-host api.anthropic.com --allow-read ~/Library/Keychains -- claude
```

The agent runs in the macOS sandbox. It can reach the gate, the local model and the hosts you
allow (through a small proxy on your machine), and nothing else: no direct internet, no ssh-agent,
no Docker socket. It can't read `~/.ssh`, cloud CLI credentials, `.env` files or registry tokens,
it can't write the gate's policy or receipts, and it can't edit your shell startup files or
LaunchAgents. Secret-looking environment variables are dropped unless you pass `--pass-env`.
Every blocked connection is written to the receipts.

Claude Code keeps its login in the macOS keychain, hence `--allow-read ~/Library/Keychains`.
That also lets the agent ask the keychain for other items; macOS prompts you for most of them,
but read the prompt before you click. Linux (bubblewrap) is next.

### What it does not defend against

- **An agent that can reach your accounts some other way.** If the agent has your SMTP password,
  API tokens or a wallet key, it can skip the gate. Use `homestead-gate run`; without it, the
  gate only works for agents that choose to use it. An allowed host is still a way out: anything
  the agent can send to `api.anthropic.com` leaves your machine.
- **An unsandboxed agent running as you.** Approval happens only in the gate's terminal (there is
  no approve endpoint), but outside `homestead-gate run` an agent can stop or reconfigure the gate.
  Inside it, it can still send signals to your other processes; the sandbox limits files and
  network, not everything.
- **An agent that hides what it read.** The model sees what the agent reports reading. A hijacked
  agent can leave the injection out, and then the model judges the action against your task alone.
  Your task comes from you when you start the gate, never from the agent.
- **A rebuilt ledger.** Someone with your files can rewrite the whole chain consistently. Run
  `hsm checkpoint` to sign it, and keep the signature somewhere they can't reach.
- **Attacks GateBench doesn't cover.** 30 attacks, one step each, written by us. See the bench limits.

MIT licensed.
