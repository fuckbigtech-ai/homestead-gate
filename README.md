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

### What it does not defend against

- **An agent that can reach your accounts some other way.** If the agent has your SMTP password,
  API tokens or a wallet key, it can skip the gate. The gate only works when it is the agent's
  only way out. Sandboxing the agent is the next milestone.
- **An agent that can type in your terminal or edit the gate's files.** Approval happens only in
  the gate's terminal (there is no approve endpoint), but an unsandboxed agent running as you can
  still stop or reconfigure the gate.
- **An agent that hides what it read.** The model sees what the agent reports reading. A hijacked
  agent can leave the injection out, and then the model judges the action against your task alone.
  Your task comes from you when you start the gate, never from the agent.
- **A rebuilt ledger.** Someone with your files can rewrite the whole chain consistently. Run
  `hsm checkpoint` to sign it, and keep the signature somewhere they can't reach.
- **Attacks GateBench doesn't cover.** 30 attacks, one step each, written by us. See the bench limits.

MIT licensed.
