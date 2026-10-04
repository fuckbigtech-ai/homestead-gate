# homestead

**A personal AI assistant that can't be talked into spending your money.** It reads your email, pays your bills
and answers for you. Anyone who can email you can try to give it orders, so nothing it sends (an email, a
payment, a wallet transaction) leaves until a second model on your machine has reviewed it **and** you have said
yes. The cloud does the thinking. Your machine has the veto. The cloud can't vote.

- **Try it:** [live demo](https://frumza--homestead-web-demo-web.modal.run) (no sign-up). The first task
  shows a hijack: one email tells the assistant to forward your inbox to a stranger, the brain obeys, and the
  gate holds it for you with the reviewer's reason. Then watch a morning of scheduled runs or write your own skill.
- **Always on, with memory and skills you own:** it wakes on a schedule, handles only new mail, leaves you a
  brief and a notification, and holds anything that needs you. It pays only people you saved in its memory, so
  an email saying "my bank changed, pay this new wallet" cannot redirect a payment. Skills are your own requests
  in a `skills.toml` you edit. [Details](#the-assistant).
- **Two NVIDIA open models:** Nemotron 3 Super on **Nebius Token Factory** plans and calls tools; Nemotron 3 Nano
  reviews every outbound action (4B on your machine in the product; 30B on Token Factory in the hosted demo)
- **Measured, not claimed:** on [AgentDojo](bench/agentdojo/RESULTS.md) (ETH Zurich's benchmark for hijacked
  agents), Nemotron 3 Super with its own safety prompt made the attacker's banking transfer in **55 of 144**
  attacked runs (38%). With the gate (Nano 30B reviewer), **0 of 144**. Travel: 11 of 119 to 0. The cost is
  published next to it: banking tasks finished under attack fell from 78% to 58%. The 4B reviewer on your
  machine, thinking before it answers (the assistant's default), blocked 0.54 legitimate calls per banking run
  (the 30B: 0.69) and let 1 of 144 through: the agent retried one attacker call until a review went its way. In
  the product a second key (you) still stands behind the model, and once you deny an action, an identical
  retry is refused without asking you again (not measured on AgentDojo, whose harness has no human). On travel, held out from all tuning, 0 of 106 action attacks got through. With a human in the loop, 1 of 143 banking attacks got through, not zero.
- **Receipts you can check:** every request, verdict and decision is written to a hash chain before anything
  runs; edit one record and `homestead-gate watch` shows the line where the chain breaks. Each session and
  each scheduled pass ends with a checkpoint signed by a key kept in your OS keychain, and you can anchor those
  checkpoints off the machine, so a rebuilt log fails against them too
  ([Receipts as audit evidence](#receipts-as-audit-evidence)).

```bash
git clone https://github.com/fuckbigtech-ai/homestead-gate && cd homestead-gate
pip install -e .                                   # not on PyPI yet
export NEBIUS_API_KEY=...                          # Nebius Token Factory
ollama pull nemotron-3-nano:4b                     # the local reviewer
homestead-gate assistant --skill triage            # go through the inbox; anything outbound waits for the gate
homestead-gate assistant --watch --every 15m       # always on: new mail only, a brief each pass
```

Built for the Nebius x NVIDIA Global AI Hackathon (Personal AI track). Part of
[fuckbigtech.ai](https://fuckbigtech.ai), alongside [homestead-memory](https://github.com/fuckbigtech-ai/homestead-memory)
(the verifiable memory the assistant uses). The open benchmark behind it is **[GateBench](bench/)**: found an
attack that gets through? Open a pull request with a new case.

## The assistant

A personal assistant that runs on a schedule, remembers who you deal with, and uses skills you write.
Two NVIDIA open models: Nemotron 3 Super on Nebius Token Factory plans and calls tools; Nemotron 3
Nano 4B runs on your machine as the gate's reviewer and reasons before its verdict (`think = true` in
the policy): about 4x slower per review (about 6s on a cloud L4 GPU; a laptop is slower), and far fewer
false blocks. Set `think = false` for faster reviews that ask you more often. Once you deny an action (or a
scheduled pass holds it), an identical retry in that session is refused without a second review or a
second question. Everything the assistant sends goes through the
[gate](#the-gate), so the cloud does the thinking, your machine has the veto, and the cloud can't vote.

```bash
export NEBIUS_API_KEY=...                                    # Nebius Token Factory (default backend)
ollama pull nemotron-3-nano:4b                               # the local reviewer
homestead-gate assistant --smoke                             # one live call with one tool, then exit
homestead-gate assistant --skill triage                      # one run of a skill, approvals in this terminal
homestead-gate assistant --watch --every 15m                 # always on: new mail only, a brief each pass
homestead-gate assistant --pending                           # answer what the scheduled passes held for you
homestead-gate assistant --memory                            # what it remembers, and who wrote each fact
homestead-gate assistant --remember "Sam Rivera" wallet 0x...  # save a fact as yours
homestead-gate assistant --skills                            # your skills (skills.toml)
homestead-gate assistant --data ~/.homestead-gate/mail --imap-setup  # your real inbox, read-only (below)
homestead-gate assistant --data ~/.homestead-gate/mail --sync        # fetch new mail once
homestead-gate assistant --task "..." --data DIR
homestead-gate assistant --backend nim ...                   # NVIDIA's hosted API instead (NVIDIA_API_KEY)
```

By default the data is fake: an inbox, one bill, a memory, a policy and three skills, written to
`~/.homestead-gate/assistant` (or `--data DIR`) on first run. That directory also holds the
assistant's own receipts, outbox, briefs and state, separate from the gate's. Email is dry-run
unless you pass `--live`, the same as `up`. Payments are unsigned Sepolia transactions. The inbox
is a JSON file (`inbox.json`); in the demo, `--demo-new-mail` delivers a second batch into it. To
put your real mail there instead, see the next section.

### Your real inbox (read-only)

```bash
homestead-gate assistant --data ~/.homestead-gate/mail --imap-setup    # server (default imap.gmail.com) and your address; then the OS asks for the password
homestead-gate assistant --data ~/.homestead-gate/mail --sync          # fetch new mail once, print how many arrived
homestead-gate assistant --data ~/.homestead-gate/mail --watch --once  # sync, then one pass over the new mail
```

Use the same `--data` every time, and not the demo's: `--imap-setup` refuses a data dir that holds
the demo's fake inbox, and `--demo-new-mail` refuses a dir that reads a real one. A new dir gets an
empty inbox, no bills, an empty memory, the default skills, and a policy whose `[user] email` is the
address you log in with. The launchd plist under [Always on](#always-on) needs the same `--data` added.

On macOS the first `--sync` may show a keychain dialog asking whether `security` may use the
`homestead-gate-imap` item. Unattended `--watch` runs need "Always Allow". The trade-off: after
that, any program running as you can read that item through `security` without being asked. If
nobody answers the dialog (under launchd), the keychain read gives up after 20 seconds and the pass
runs on the inbox it already has.

The first pass can bring up to 50 messages. The brain has 12 steps per pass, so it opens only some
of them, but all of them count as handled; the brief lists every one under "New mail".

Gmail accepts only an app password here, not your normal password:

1. Turn on 2-Step Verification: https://myaccount.google.com/security
2. Create an app password: https://myaccount.google.com/apppasswords
3. Run `--imap-setup` and paste the 16 letters into the password prompt.

Some work, school and Advanced Protection accounts do not offer app passwords.

How it reads your mail:

- **Read-only at the protocol level.** The mailbox is opened with `EXAMINE`, and messages are fetched
  with `BODY.PEEK[]`, so nothing is marked as read. The only commands sent are `LOGIN`, `EXAMINE`,
  `UID SEARCH`, `UID FETCH` and `LOGOUT`. The code refuses any other UID command, and a test fails if
  it calls store, copy, move, expunge, append, delete or close. This is a property of this code, not
  of the password: an app password can do anything to your mailbox, and can send mail too. Here it is
  only used to read.
- **What it fetches.** The first sync gets the last 3 days, at most 50 messages, newest first. Later
  syncs get only messages newer than the last one seen. If the server renumbers the mailbox
  (`UIDVALIDITY` changes), the sync starts over from the last 3 days, and the `Message-ID` check keeps
  messages from appearing twice. `days`, `max_messages` and `mailbox` are in the `[imap]` section of
  the data dir's `policy.toml`.
- **What it keeps.** For each message: the sender, subject, date and text. The text is the plain-text
  part, or else the HTML part with the tags removed, cut at 8,000 characters. At most the first
  512 KB of a message is downloaded. Attachments are never kept; the inbox notes only their names.
- **The password.** It is stored in the OS credential store under its own entry,
  `homestead-gate-imap`, and you type it into the store's own prompt. It is never written to a file
  or a log, never passed as an argument, and never shown in an error message. The entry is separate
  from the SMTP one, so reading mail can never turn on sending. Email stays dry-run until you run
  `creds set-smtp` and pass `--live`, and `--watch` never sends live mail.
- **When the server is unreachable.** `--watch` syncs before each pass. If the server cannot be
  reached, or refuses the login, the pass still runs on the inbox as it was, and the brief says so.

**What goes to the cloud.** The brain is Nemotron 3 Super on Nebius Token Factory, a cloud service,
and it needs to read your mail to do its job. `list_inbox` sends it the sender, subject and date of
each new message. `read_email` sends it the full text of each message it opens (up to the
8,000-character cut). Facts it looks up from memory are sent to it too. So the text of your email
does leave your machine. These stay on your machine:

- the memory store;
- the receipts;
- the reviewer, Nemotron 3 Nano 4B, which runs locally;
- your approvals.

Your mail is also kept on your machine as plain files in the data dir: `inbox.json`, the reads held
in `pending.json`, and the briefs. The dir is created with mode 0700.

### Always on

`--watch` wakes on a schedule and handles only the mail that arrived since the last pass. State
(which messages are done) lives in `state.json` in the data dir, and mail is marked done only when
a pass finishes, so a failed pass leaves it for the next one. If nothing is new, the cloud model is
not called. Each pass:

- runs one skill (`triage` unless you pass `--skill`), with `list_inbox` and `read_email` limited to
  the new messages;
- writes `brief.md` (and a dated copy under `briefs/`): what it did, what is waiting for you, the new
  mail, the memory it used, and, labelled as such, the model's own summary. The "done" and "waiting"
  lists are built from the gate's records, not from what the model says;
- shows a desktop notification with counts only, no email text (`osascript` on macOS, `notify-send`
  on Linux, nothing if neither is there).

Nobody is at the terminal during a pass, so its approver can only hold. Anything that needs you is
recorded as not executed (`gate.expired`, decided by `human:held`) and queued in `pending.json`.
`homestead-gate assistant --pending` puts each held item through the whole gate again (policy,
local reviewer, then you in the terminal). The queue is a file anyone with your files can edit, so
nothing is ever executed from it directly. A lock file stops two passes from overlapping.

`--watch --once` does one pass and exits, for launchd or cron. macOS, every 15 minutes
(`~/Library/LaunchAgents/com.example.homestead-assistant.plist`, then
`launchctl load` that file):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.example.homestead-assistant</string>
  <key>ProgramArguments</key><array>
    <string>/path/to/venv/bin/homestead-gate</string><string>assistant</string>
    <string>--watch</string><string>--once</string>
  </array>
  <key>EnvironmentVariables</key><dict><key>NEBIUS_API_KEY</key><string>...</string></dict>
  <key>StartInterval</key><integer>900</integer>
  <key>StandardOutPath</key><string>/tmp/homestead-assistant.log</string>
  <key>StandardErrorPath</key><string>/tmp/homestead-assistant.log</string>
</dict></plist>
```

Linux or any cron: `*/15 * * * * NEBIUS_API_KEY=... /path/to/venv/bin/homestead-gate assistant --watch --once`.
The plist puts the API key in a file in plain text; use a wrapper script that reads it from your
keychain if that matters to you. Approvals never happen in launchd or cron: they wait for `--pending`.

### Memory that decides things

Memory is [homestead-memory](https://github.com/fuckbigtech-ai/homestead-memory). Each fact records
who wrote it, when, and its source. `--memory` lists them.

- **Payees come only from facts you wrote.** `pay_invoice` refuses, before the gate, any wallet that
  is not a wallet fact written by you for that bill's payee. The demo inbox has an email from Sam
  saying his bank changed and asking you to pay a new wallet. The assistant cannot pay it; the brief
  says so, shows the wallet you saved, and tells you how to save a new one once you have checked
  with Sam yourself. There is no gate request and no approval card for it, because there is nothing
  you could safely approve.
- **The assistant cannot write contact details** (email, wallet, account, bank) into memory, and it
  cannot overwrite any fact you wrote. When it remembers other things, this code sets the source
  from what the run actually read, never from what the model says. A note edited by hand loses its
  writer, so it no longer counts as yours.
- **Your contacts are your allowlist.** The email addresses and wallets you wrote into memory are
  added to the policy's allowlists, so a message to them can go through when the reviewer approves.
  Facts the assistant wrote never count.
- **After you approve someone new, it offers to remember them.** In the terminal it asks for a name
  (blank skips); the fact is written as yours with the source "approved by you on DATE". Next time
  that address is a known contact.
- **Email recipients are treated differently from payees, on purpose.** Replying to someone new is
  normal, so an email to an address you never saved is not refused. It is not allowlisted either, so
  the gate always asks you about it. That is also how the poisoned-email demo still reaches the gate.

### Skills you write

`skills.toml` in the data dir holds your skills: a name, the instruction in your words, the tools it
may use, and an optional schedule for `--watch`. The three defaults (`triage`, `pay`, `summarize`)
are written there on first run; edit them or add your own.

```toml
[skills.landlord]
instruction = "Email landlord@example.org that the kitchen sink is fixed."
tools = ["recall", "send_email"]
schedule = "every 1h"          # optional
```

The instruction is your request, so the gate trusts it: the reviewer judges every action against it.
The tools list narrows what the cloud model is offered for that skill, and a call to any other tool
is refused. Outbound tools still go through the gate, whatever the list says. A skill cannot name a
tool that does not exist, and nothing in it can turn the gate off.

### How a run stays inside the gate

- **Read tools run at once:** `list_inbox`, `read_email`, `list_bills`, `recall` and `remember`.
- **Outbound tools are gate requests:** `send_email` and `pay_invoice`. They get the same policy,
  local reviewer, terminal approval and receipts as any other agent. The model gets a submit
  function, not the gate. It has no tool that approves, and any tool name it makes up is refused.
- **Fixed fields:** each action is built from a fixed list of arguments. Extra fields the model
  adds, such as `"approved": true`, a chain id or calldata, are dropped.
- **What it read goes with every request.** This code attaches the output of every read tool, not
  the model. So on this path the model cannot leave the poisoned email out, which narrows the
  "agent that hides what it read" gap (see [what it does not defend against](#what-it-does-not-defend-against)). Limits: the reviewer runs at a 4096-token context, so
  a long read keeps only its first 1400 and last 600 characters, with a note of how much was cut.
  Text hidden in the middle of a long email reaches the cloud model but not the reviewer. And
  GateBench measured one untrusted source per request; this path sends several, a shape the
  published numbers do not cover.
- **No asking twice.** An action that was denied or held is refused if the model tries it again,
  and a run may submit only 4 outbound actions.
- **The daily cap holds across runs.** Each run and each scheduled pass starts from a fresh policy
  and replays the last 24 hours of autonomous payments from its receipts.
- **Money moves on its own only if you asked for a payment.** If your request never mentions paying
  (an invoice, a bill, a tip, a refund, sending an amount), any payment the agent attempts goes to
  you, even to an allowlisted payee the model approves. The default `triage` skill does not ask for
  payments, so during `--watch` a payment is held for you. Found in our own demo: asked to "reply to
  anything that needs an answer", the agent paid an invoice and the model approved it.

Token Factory is OpenAI-compatible: `https://api.tokenfactory.nebius.com/v1`, model
`nvidia/nemotron-3-super-120b-a12b` (override with `HG_TOKENFACTORY_BASE_URL` /
`HG_TOKENFACTORY_MODEL`, or `--base-url` / `--llm-model`). The API key is read from the environment
when a request is built. It is never logged, printed or written to a receipt.

A cloud model that ignores the poisoned email never reaches the gate. To show the gate catching
a model that obeys it, `--unguarded-prompt` removes the warning about email instructions from
the system prompt. Our demo recordings say when they use it.

### Web demo (demo mode)

`demo/web` runs the same Assistant, Gate and scheduled pass behind a phone-sized page:

- **Watch the gate catch a hijack** (the default): "summarize my inbox", with one email telling the
  assistant to forward everything to a stranger and the brain's warning removed so it obeys. In 11 test runs
  on Token Factory the brain sent it to the gate 10 times on the first try and the reviewer flagged all 10;
  if the brain ignores the email, the page says so and tries once more.
- **Morning run:** two scheduled passes of the triage skill (07:00 and 07:15) over a seeded inbox,
  with new mail arriving in between, including Sam's "my wallet changed" email. Each pass shows its
  brief and the notification it would raise. Only the clock is simulated; nothing is approved on the
  page during these passes, the same as `--watch`.
- **Your skills:** run a default skill, or write one of your own (the instruction only; its tools are
  fixed to reading, looking things up and email, with no payments). Your skill is your request and
  the gate trusts it. The injection box is the opposite: text in an email someone sent you, which is
  never trusted.
- **Memory panel:** the facts each run used, who wrote each one and when. After you approve someone
  new, "Remember this" saves them as your fact, and the next run treats them as a known contact.
- **Try your own injection** (the poisoned email is yours to write) and **AgentDojo's published
  attack** (its template, warning on); then verify the receipts and see a tampered
  copy fail. The assistant's answer is rendered as markdown built from page elements, never as HTML.

```bash
export NEBIUS_API_KEY=...
PYTHONPATH=src python -m demo.web.server                   # http://127.0.0.1:8000
DEMO_BRAIN=scripted DEMO_REVIEWER=scripted PYTHONPATH=src python -m demo.web.server   # offline, no models
DEMO_REVIEWER=ollama OLLAMA_URL=https://...modal.run PYTHONPATH=src python -m demo.web.server   # Nano 4B on a Modal GPU
```

**Demo mode is not the product.** On the page, approval is a button and the reviewer is Nemotron
Nano 30B on Nebius Token Factory, so visitors need no GPU. In the product the reviewer runs on your
machine and approval happens only in the terminal you started the gate in; there is no approve
button on the network. The web approver lives only in `demo/web`, and a test fails if anything in
`src/homestead_gate` can import it. GateBench numbers were measured on the local reviewers, not on
the hosted Nano 30B. Each browser session gets its own data, memory, skills and receipts, deleted
after an hour. Runs are rate limited (5 per page and 20 in total per hour by default; a morning run
counts as two) with a token budget per run. Email is never sent and payments are unsigned. It is
hosted on Modal with `demo/web/modal_app.py` (live at the link at the top).


## The gate

```bash
pip install -e .                         # PyPI release comes later
homestead-gate up                        # set up, then run the gate on 127.0.0.1:6000
homestead-gate doctor                    # one-screen health check
homestead-gate demo                      # a hijacked agent vs the gate, in a throwaway ledger
homestead-gate watch                     # the receipts, verified, then checkpointed; exits 1 on any mismatch
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

Blocked connections are written to the receipts: the first attempt to each host, then at most one
per host per minute, because agents retry constantly. The file rules are a list of known places
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

### Receipts as audit evidence

The receipts are the homestead-memory hash chain: each record holds the hash of the one before it, so
editing one record breaks every hash after it. On its own that is tamper-evident against an edit, but
not against someone with your files who rebuilds the whole chain, because the hashes are not keyed.
Three things close most of that gap (`src/homestead_gate/receipts.py`):

- **Signed checkpoints, automatically.** When a gate session ends (`up`, an assistant run, `--pending`),
  after every scheduled pass, and on `homestead-gate watch`, the gate writes a checkpoint: head hash,
  record count, time, policy version and reviewer model. It is appended to `checkpoints.jsonl` in the
  ledger directory and copied to `.hsm/ledger.sig`, so `hsm watch` and `hsm checkpoint --verify` read it
  too. The signing key is not a file. It is derived from a random key the gate generates on first use and
  keeps in the OS credential store (keychain entry `homestead-gate-ledger-key`, readable without a prompt
  only by the gate's own interpreter; libsecret on Linux). With no credential store, checkpoints are
  written unsigned and the gate says so; anchors still work.
- **A keyed MAC on every new record.** The same key gives each new gate record an HMAC and a per-session
  counter in its metadata. Rewriting a record without the key fails its MAC, and deleting a record from
  the middle of a session leaves a gap in the counter, even if the chain hashes were recomputed. Older
  records, written before this, verify exactly as before.
- **Anchors off the machine.** Each checkpoint can also be written somewhere someone with your machine
  can't rewrite later. A rebuilt chain can't match a head that was anchored before the rebuild.

The gate never signs a chain that fails verification, fails a MAC, or does not extend every earlier
checkpoint it can see. That includes the local files, the anchor folder, and the last head it sealed for
this ledger, which it keeps in the credential store (entry `homestead-gate-ledger-head`). Checkpoint files
can be deleted, but someone with only your files can't reach that keychain entry, so a rebuild that also
strips every MAC and deletes the checkpoints is still refused. Without that rule, the gate's own automatic
signing would launder a rebuild. A refusal goes in the brief and the notification, and `watch` exits 1.

**Setting up anchors**, in the policy (`~/.homestead-gate/policy.toml`, or `policy.toml` in an assistant
data dir):

```toml
[receipts]
# A command that gets the checkpoint JSON on stdin ($HG_CHECKPOINT is the same JSON as a file,
# $HG_CHECKPOINT_NAME a unique name). Here: commit it to a private repo and push to a remote whose
# history you protect (no force-push, no deletes), so a copy leaves the machine at once.
anchor_command = "cd ~/hg-anchors && cat > $HG_CHECKPOINT_NAME.json && git add -A && git commit -qm anchor && git push -q"
# And/or a folder: a new file per checkpoint, never overwritten. The gate reads it back to check.
anchor_dir = "/Volumes/ANCHORS/homestead"
```

An anchor is worth only what a later attacker can't change. Anything that can run code as you can
delete files from a local folder, a mounted USB stick or a synced cloud folder. It forges nothing: it
removes the anchors after the point it rewrote and keeps the earlier ones, and verification then only
says that the newest records are not anchored yet. Good anchors are ones you can't rewrite from this
machine either: a remote with protected history, an email to yourself, a timestamp authority (below),
or a USB stick you unplug. A folder on the same disk is not an anchor. A synced cloud folder counts
only as far as its version history keeps deleted files out of reach; check what yours keeps.

**Trusted time (optional).** Timestamps come from the system clock, which someone with your machine can
set. For time you don't have to trust, make `anchor_command` an RFC 3161 request to a public timestamp
authority. The gate has no TSA client of its own and calls no service unless you configure one:

```toml
anchor_command = """
d=~/hg-tsa; mkdir -p $d; cp "$HG_CHECKPOINT" $d/$HG_CHECKPOINT_NAME.json &&
openssl ts -query -data $d/$HG_CHECKPOINT_NAME.json -sha256 -cert -out $d/$HG_CHECKPOINT_NAME.tsq &&
curl -sf -H 'Content-Type: application/timestamp-query' --data-binary @$d/$HG_CHECKPOINT_NAME.tsq \
  https://freetsa.org/tsr -o $d/$HG_CHECKPOINT_NAME.tsr
"""
```

Check a stamp later with `openssl ts -verify -data NAME.json -in NAME.tsr -CAfile cacert.pem -untrusted tsa.crt`.
Both certificates come from freetsa.org. The stamp proves the checkpoint, and so the head hash, existed by
that time.

**What an auditor gets:**

- the ledger, a JSONL file at `<ledger>/.hsm/ledger.jsonl`, plus `checkpoints.jsonl`;
- the anchored checkpoint files (`hg-checkpoint-*.json`), and any `.tsr` timestamp replies;
- the signer's public key, which is in every checkpoint. Pin it with `--signer` once you have it from the
  owner by another channel.

They verify a copy with:

```bash
homestead-gate watch --ledger COPY --anchors ANCHOR_DIR --signer PUBKEY --no-checkpoint
```

That checks the chain, then every anchored checkpoint's signatures, then whether the copy still contains each
anchored head. It reports the first anchored checkpoint the copy no longer matches and the last one it still
does, which bounds where the history was rewritten. `--no-checkpoint` keeps it read-only: no key is created on
the auditor's machine and nothing is written into the copy. The MACs are checked only on a machine that holds
the key. Anywhere else, watch says they were not checked. Each anchored file also carries the
`hsm-checkpoint v1 ...` line, so `hsm checkpoint --verify LINE COPY` works without homestead-gate.

**Tamper-evident against whom:**

| who | edits one record | rebuilds the whole log | deletes the newest records |
|---|---|---|---|
| someone with your files only (a copied disk, a backup, a shared folder), so no key | caught (chain, MAC) | caught. Rewritten records fail their MAC. With the MACs stripped, the chain still has to extend the head kept in the keychain, and anchored heads don't match | caught if those records were in a checkpoint (the keychain head) or an anchor |
| someone running code as you | caught | caught back to the last anchor they can't change. **Not caught** for records no such anchor has seen: through the gate's interpreter they can read the key and the keychain head | the same |

Anchors count only if this attacker can't modify them (see above).

**What it still does not cover:**

- **A compromised machine, before anchoring.** Anything that can run code as you can read the key
  through the gate's interpreter and rewrite records that no anchor has seen yet. Anchors fix history from
  the moment they are written; how much is exposed depends on how often you anchor.
- **Time, without a TSA.** Without a timestamp authority, `ts` is the system clock. Order is still provable
  from `seq`, the chain and the MAC counter, but wall-clock time is not.
- **Record MACs don't bind the record's position.** homestead-memory assigns `seq`, `ts` and `prev_hash`
  inside its own lock, so the MAC covers the content and the per-session counter, not those fields. Egress
  denials from `homestead-gate run` are written without a MAC.
- **A changed key.** If the keychain entry is lost, a new key is generated, and the keychain head goes with
  it. Anchors signed by the old key still verify. `watch` notes the change, and `--signer` turns it into a
  failure.
- **Tested against fakes only.** The tests run the real `security -i` and `secret-tool` code paths against
  a fake store. They never touch a real keychain.

### Threat model

Who can attack, what they can do, and what stops them. "Outbound action" means anything that leaves your
machine on your behalf: an email, a message, a payment, a wallet transaction.

| attacker | what they can do | what stops them | what does not |
|---|---|---|---|
| **Anyone who can put text in front of the agent** (an email, a web page, a tool result, a skill) | Steer the agent into an outbound action you did not ask for | The gate sees the exact action, what you asked for and what the agent read. A recipient, account or link you never named, or data you did not ask to send, is flagged and waits for you. In the assistant, a payment can go only to a wallet you saved in memory, so "my bank changed, pay this new wallet" is refused before the gate | Text that only changes what the agent *tells you* (a fake recommendation): no action, so the gate never sees it |
| **A compromised cloud model** (the brain itself is hostile) | Propose any action, invent arguments, retry | Same gate, same rules: the brain has a submit function, not the gate. Denied actions can't be retried, a run gets 4 outbound actions, unknown tools are refused, extra fields are dropped | The brain can lie in its summary to you. Read the receipts, not the summary |
| **A compromised or wrong local reviewer** | Approve something it should not | It is only one of two keys: anything flagged, anything not allowlisted, any calldata, any payment you never asked for, and any spend over the daily cap still needs you | A reviewer that approves an allowlisted, in-cap payment you did ask for, to the payee you named. That is the one path the policy lets through without you |
| **Someone replaying an old approval** | Reuse a "yes" for a different action | Each approval is bound to the exact typed action and the policy version that judged it; a changed field is a new request | |
| **Someone with your files** | Edit, delete or rebuild the receipt log | Every record holds the hash of the one before it, so an edit breaks the chain at that line (`homestead-gate watch` exits 1). New records carry a MAC keyed from the OS keychain, checkpoints are signed automatically, and anchored checkpoints catch a rebuilt log (`watch --anchors DIR`) | Records nobody anchored yet, if they can also run code as you (the gate's interpreter can read the key). [Receipts as audit evidence](#receipts-as-audit-evidence) |
| **An agent going around the gate** | Use your SMTP password or a wallet key directly | `homestead-gate run` sandboxes the agent: it can reach the gate, the local model and the hosts you allow, and it can't read your SSH keys, cloud credentials or `.env` files. The gate holds the email credentials, not the agent | Anything sent to a host you allowed |

How well it works, measured on outside benchmarks, is in [bench/agentdojo/RESULTS.md](bench/agentdojo/RESULTS.md):
without a gate, 28 to 36% of the attacks that try an action succeed on AgentDojo's banking, Slack and travel
suites; with the gate (model only, no human), none did. The cost is that it also blocks some legitimate work, and
those numbers are in the same file.

### FAQ

**How is this different from a sandbox (bubblewrap, gVisor, OpenShell)?** A sandbox decides what an agent can
*reach*. It can't tell "pay my plumber" from "pay the attacker", because both are the same call to the same
host. The gate judges each action against what you asked for. Use both: `homestead-gate run` is the sandbox,
the gate is the layer that reads the action.

**Isn't a model guarding a model just more guardrails?** That is why it is 2-of-2. The local model is one key and
you are the other. When the model is unsure or flags something, nothing happens until you decide, and the
policy (allowlists, a daily spending cap, calldata always to a human, no payment you never asked for) holds no
matter what either model says.

**Why not just ask me to confirm everything?** People approve on reflex after the tenth prompt. The gate asks only
when the model flags an action or a rule requires it (calldata, a payment you never asked for, spending over the
cap). It still asks too often on some kinds of task, such as "do what this file says": on AgentDojo's banking
tasks it flagged most of the actions it reviewed. Cutting that without letting attacks through is the open
problem, and the attempts so far are in the results.

**Where is the methodology?** GateBench's cases, prompt, run files and scorer are in [bench/](bench/), with a
frozen test split scored on both sides (attacks caught and legitimate actions blocked). The AgentDojo runs use
ETH Zurich's own tasks, attacks and scoring; the merge script recomputes every number from the traces, and the
write-up keeps the failed attempts (prompt v3 and v4 failed our held-out check, v5 did not beat v1 on travel).

**Does it phone home?** No. The gate, its reviewer and the receipts run on your machine. The only network
calls are the ones you configure: the cloud brain (Nebius Token Factory or NVIDIA NIM), the email server
you give it for sending, and the IMAP server if you connect your real inbox. The brain receives the mail
it reads ([what goes to the cloud](#your-real-inbox-read-only)). The gate sends no telemetry.

**Who is it for?** Anyone letting an AI assistant touch their email or money: the person who wants the
assistant to pay bills and answer mail, and doesn't want one poisoned email to empty the inbox to a stranger.

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
- **A rebuilt or shortened ledger, before it was anchored.** Signed checkpoints, record MACs and
  anchors catch a rebuild by anyone without the key, and a rebuild of anything that was anchored where the
  attacker can't write. Someone who can run code as you can still rewrite records that no such anchor has
  seen. Without `[receipts]` anchors, only this machine's keychain can catch a rebuild, so an auditor
  holding a copy can't. See [Receipts as audit evidence](#receipts-as-audit-evidence).
- **Attacks GateBench doesn't cover.** 30 attacks, one step each, written by us. See the bench limits.

MIT licensed.
