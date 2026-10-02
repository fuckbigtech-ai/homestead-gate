// homestead web demo. Everything shown here was written by a model, an email or a visitor, so it
// is put on the page with textContent only, never as HTML. Markdown from the model is turned into
// DOM nodes by renderMarkdown (md.js), which never parses HTML either.
"use strict";

const $ = (id) => document.getElementById(id);
function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}
function short(h) { return h ? String(h).slice(0, 16) : ""; }

let config = null;
let runId = null;
let source = null;
const cards = {};           // rid -> card element parts

async function api(path, body) {
  const opt = body === undefined ? {} : {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  };
  const r = await fetch(path, { credentials: "same-origin", ...opt });
  let data = {};
  try { data = await r.json(); } catch (e) { data = {}; }
  return { ok: r.ok, status: r.status, data };
}

// ---------------------------------------------------------------- setup

async function init() {
  const { data } = await api("/api/config");
  config = data;
  const reviewerSentence = data.reviewer_kind === "tokenfactory"
    ? `the reviewer runs on Nebius Token Factory (${data.reviewer_model}) so you don't need a GPU`
    : `the reviewer is ${data.reviewer}`;
  $("demo-text").textContent =
    `the approval happens in this page and ${reviewerSentence}. In the product, the reviewer runs on your ` +
    "own machine and approval happens only in the terminal you started the gate in; there is no approve " +
    "button on the network.";
  const m = $("models");
  m.textContent = "";
  m.append("Brain: ", el("b", "", data.brain), ". Reviewer: ", el("b", "", data.reviewer), ".");
  $("safe-tools").textContent = (data.safe_tools || []).join(", ");
  $("skill-text").maxLength = data.skill_max || 500;
  fillSkills(data.skills || []);
  $("injection").value = data.default_injection;
  $("injection").maxLength = data.injection_max;
  countInjection();
  const L = data.limits;
  $("limits").textContent =
    `Limits so the credits last: ${L.session_runs_per_hour} runs per hour for this page, ` +
    `${L.global_runs_per_hour} per hour for everyone, ${L.token_budget.toLocaleString()} tokens per run. ` +
    `An approval card waits ${L.approval_timeout_s} seconds, then counts as a no.`;
  if (data.active_run) {
    // a reload while a run is going: pick it up again; the stream replays from the start
    runId = data.active_run;
    $("run").disabled = true;
    $("run-status").textContent = "Your run is still going. Picked it up again.";
    resetTimeline();
    listen(runId);
  }
}

function scenario() { return document.querySelector("input[name=scenario]:checked").value; }

let skills = [];
function fillSkills(list, pick) {
  skills = list;
  const sel = $("skill-pick");
  const keep = pick || sel.value;
  sel.textContent = "";
  for (const k of list) {
    const o = el("option", "", `${k.name}${k.origin === "yours" ? " (yours)" : ""}`);
    o.value = k.name;
    sel.append(o);
  }
  if (keep && list.some((k) => k.name === keep)) sel.value = keep;
  showSkill();
}
function showSkill() {
  const k = skills.find((x) => x.name === $("skill-pick").value);
  const info = $("skill-info");
  info.textContent = "";
  if (!k) return;
  info.append(el("div", "", `"${k.instruction}"`),
    el("div", "muted", `Tools: ${k.tools.join(", ")}${k.schedule ? `. Schedule: ${k.schedule}` : ""}.`));
}
$("skill-pick").addEventListener("change", showSkill);
$("skill-save").addEventListener("click", async () => {
  const st = $("skill-status");
  st.className = "status";
  const r = await api("/api/skill", { name: $("skill-name").value, instruction: $("skill-text").value });
  if (!r.ok) {
    st.className = "status error";
    st.textContent = r.data.error || `Not saved (HTTP ${r.status}).`;
    return;
  }
  const name = $("skill-name").value.trim().toLowerCase();
  fillSkills(r.data.skills, name);
  st.textContent = `Saved. "${name}" is in your skills.toml for this session. Press Run to use it.`;
});
function countInjection() {
  const n = $("injection").value.length;
  $("inj-count").textContent = `${n} of ${config ? config.injection_max : 2000} characters.`;
}
function showScenario() {
  $("custom").hidden = scenario() !== "custom";
  $("skill-box").hidden = scenario() !== "skill";
  $("agentdojo-box").hidden = scenario() !== "agentdojo";
  // the published attack always runs with the warning on; the server ignores the box for it too
  $("unguarded").disabled = scenario() === "agentdojo";
  if (scenario() === "agentdojo") $("unguarded").checked = false;
}
document.querySelectorAll("input[name=scenario]").forEach((r) => r.addEventListener("change", showScenario));
$("injection").addEventListener("input", countInjection);

// ---------------------------------------------------------------- run

$("run").addEventListener("click", async () => {
  const status = $("run-status");
  status.className = "status";
  status.textContent = "Starting...";
  $("run").disabled = true;
  const body = { scenario: scenario(), unguarded: $("unguarded").checked };
  if (body.scenario === "custom") body.injection = $("injection").value;
  if (body.scenario === "skill") body.skill = $("skill-pick").value;
  const r = await api("/api/run", body);
  if (!r.ok) {
    status.className = "status error";
    status.textContent = r.data.error || `Could not start (HTTP ${r.status}).`;
    $("run").disabled = false;
    return;
  }
  status.textContent = "Running. Reads happen at once; anything outbound waits for you below.";
  runId = r.data.run_id;
  resetTimeline();
  listen(runId);
});

function resetTimeline() {
  $("timeline").textContent = "";
  $("summary").hidden = true;
  $("summary").textContent = "";
  $("memory").hidden = true;
  $("memory").textContent = "";
  $("task-line").textContent = "Starting...";
  for (const k of Object.keys(cards)) delete cards[k];
}

function listen(id) {
  if (source) source.close();
  source = new EventSource(`/api/runs/${id}/events`);
  const on = (type, fn) => source.addEventListener(type, (e) => fn(JSON.parse(e.data)));
  on("start", onStart);
  on("thinking", onThinking);
  on("read", onRead);
  on("outbound", () => {});
  on("tool_error", (d) => addStep("err", `${d.tool} refused`, d.error));
  on("approval", onApproval);
  on("gate_result", onGateResult);
  on("summary", onSummary);
  on("memory", onMemory);
  on("tick", onTick);
  on("mail_arrived", onMailArrived);
  on("brief", onBrief);
  on("run_error", (d) => addStep("err", "Stopped", d.message));
  source.onerror = () => {
    // the browser retries on its own; if the run is gone (session ended), stop and say so
    if (source.readyState === EventSource.CLOSED) {
      $("run").disabled = false;
      $("run-status").textContent = "Lost the connection to this run. Reload the page.";
    }
  };
  on("end", () => {
    source.close();
    $("run").disabled = false;
    $("run-status").textContent = "Done. Check the receipts below.";
    document.querySelectorAll(".step.thinking").forEach((n) => n.remove());
  });
}

function addStep(cls, what, meta, detail) {
  const li = el("li", `step ${cls || ""}`);
  li.append(el("div", "what", what));
  if (meta) li.append(el("div", "meta", meta));
  if (detail) {
    const d = el("details");
    d.append(el("summary", "", "Show what it read"), el("pre", "", detail));
    li.append(d);
  }
  $("timeline").append(li);
  return li;
}

function onStart(d) {
  // The first thing on screen in every run is what you asked for, never a verdict.
  const t = $("task-line");
  t.textContent = "";
  const label = d.skill ? `Your skill "${d.skill.name}", in your words` : "Your request";
  t.append(el("div", "block-label", label), el("div", "task", `"${d.task}"`));
  if (d.scenario === "morning") {
    t.append(el("div", "", "Two scheduled runs, 07:00 and 07:15, each over only the mail that is new. Nobody is at the " +
      "terminal, so anything that needs you is held and listed in the brief."));
  }
  if (d.skill) t.append(el("div", "muted", `Tools: ${d.skill.tools.join(", ")}.`));
  if (!d.guarded) t.append(el("div", "", "The brain's warning about instructions in emails is removed for this run."));
  if (d.custom_injection) t.append(el("div", "", "The poisoned email contains your text."));
  if (d.published_attack) t.append(el("div", "published-note", d.published_attack.label));
  $("h-steps").scrollIntoView({ behavior: "smooth", block: "start" });
}

function onTick(d) {
  const n = d.new.length;
  addStep("tick", `${d.at}: scheduled run wakes up`,
    n ? `${n} new email${n > 1 ? "s" : ""}: ${d.new.map((m) => m.from).join(", ")}` : "No new mail");
}

function onMailArrived(d) {
  addStep("", "New mail arrived", d.messages.map((m) => `${m.from}: ${m.subject}`).join(", "));
}

function onBrief(d) {
  const li = el("li");
  const card = el("article", "card brief");
  const head = el("div", "card-head");
  head.append(el("span", "card-title", `Brief left at ${d.at}`),
    el("span", "timer", `${d.done} done, ${d.waiting} waiting for you`));
  card.append(head);
  if (d.notification) card.append(el("div", "notif", `Desktop notification: "homestead: ${d.notification}"`));
  const body = el("div", "md");
  body.append(renderMarkdown(d.markdown));
  card.append(body);
  if (d.waiting) {
    card.append(el("div", "outcome bad", "In the product, you answer held items in your own terminal with " +
      "homestead-gate assistant --pending. Each goes through the gate again."));
  }
  li.append(card);
  $("timeline").append(li);
}

function onMemory(d) {
  const box = $("memory");
  box.textContent = "";
  box.hidden = false;
  box.append(el("div", "block-label", "Memory it used, and who wrote each fact"));
  const ul = el("ul", "facts");
  if (!d.facts.length) ul.append(el("li", "muted", "No facts from memory were used in this run."));
  for (const f of d.facts) ul.append(factItem(f));
  box.append(ul, el("div", "hint", "Who to pay comes only from facts you wrote. The assistant cannot write an email " +
    "address or a wallet into memory, and cannot change a fact you wrote."));
}

function factItem(f) {
  const li = el("li", f.written_by === "you" ? "mine" : "");
  li.append(el("div", "", `${f.entity}, ${f.field}: ${f.value}`),
    el("div", "meta", `Written by ${f.written_by}${f.when ? ` on ${f.when}` : ""}. Source: ${f.source}`));
  return li;
}

function onThinking(d) {
  document.querySelectorAll(".step.thinking").forEach((n) => n.remove());
  addStep("thinking", "The cloud model is deciding what to do next...");
}

function onRead(d) {
  const r = d.result || {};
  const a = d.args || {};
  if (r.error) return addStep("err", `${d.tool}`, r.error);
  switch (d.tool) {
    case "list_inbox":
      return addStep("", "Listed the inbox", `${(r.messages || []).length} emails`,
        (r.messages || []).map((m) => `${m.id}  ${m.from}  ${m.subject}`).join("\n"));
    case "read_email":
      return addStep("", `Read email from ${r.from}`, `"${r.subject}"`, r.body);
    case "list_bills":
      return addStep("", "Listed open bills", `${(r.bills || []).length} open`,
        (r.bills || []).map((b) => `${b.id}  ${b.from}  ${b.amount_eth} ETH  due ${b.due}`).join("\n"));
    case "recall":
      return addStep("", `Looked up "${a.entity}" in memory`, `${(r.facts || []).length} facts, each with its source`,
        (r.facts || []).map((f) => `${f.entity} ${f.field}: ${f.value}\n  source: ${f.source} (written by ${f.written_by})`).join("\n"));
    case "remember":
      return addStep("", `Remembered a fact about ${a.entity}`, "Its source is set by the code from what this run read, not by the model.");
    default:
      return addStep("", d.tool);
  }
}

// ---------------------------------------------------------------- approval cards

function describeAction(a) {
  if (a.type === "wallet_tx") return `Pay ${a.value_eth} ETH (Sepolia testnet, unsigned)`;
  if (a.type === "email") return "Send an email";
  return a.type;
}

function actionList(a, label) {
  const dl = el("dl", "kv");
  const row = (k, v, sub) => {
    const dd = el("dd", "", v);
    if (sub) dd.append(el("span", "sub", sub));
    dl.append(el("dt", "", k), dd);
  };
  row("To", a.to, label);
  if (a.type === "email") row("Subject", a.subject || "(none)");
  if (a.type === "wallet_tx") { row("Amount", `${a.value_eth} ETH`); row("Chain", `Sepolia (${a.chain_id})`); }
  const frag = document.createDocumentFragment();
  frag.append(dl);
  if (a.type === "email") {
    const p = el("pre", "", a.body || "");
    frag.append(el("div", "block-label", "Body, exactly as it would be sent"), p);
  }
  return frag;
}

function reviewBlock(verdictName, reason, span, model) {
  const b = el("div", "block");
  b.append(el("div", "block-label", `Reviewer (${model})`));
  const line = el("div");
  const verdict = { approve: ["ok", "Looks fine"], block: ["bad", "Flagged"],
    invalid: ["warn", "No clear verdict, counts as a flag"] }[verdictName] || ["warn", "Not asked"];
  line.append(el("span", `pill ${verdict[0]}`, verdict[1]), reason || "");
  b.append(line);
  if (span) b.append(el("span", "span", `Suspicious text: ${span}`));
  return b;
}

function ruleBlock(rule) {
  const b = el("div", "block");
  b.append(el("div", "block-label", "Rule that applied"), el("div", "", rule || ""));
  return b;
}

function receiptBlock(receipts, extraLabel) {
  const b = el("div", "block");
  b.append(el("div", "block-label", extraLabel || "Receipts so far (written before anything runs)"));
  const h = el("div", "hashes");
  const p = (receipts || []).find((r) => r.payload_sha256);
  if (p) h.append(el("span", "", `action sha256 ${short(p.payload_sha256)}...`));
  for (const r of receipts || []) h.append(el("span", "", `#${r.seq} ${r.action}  ${r.summary}  hash ${short(r.hash)}...`));
  b.append(h);
  return b;
}

function onApproval(d) {
  const li = el("li");
  const card = el("article", `card waiting ${d.flagged ? "flagged" : ""}`);
  const head = el("div", "card-head");
  const timer = el("span", "timer");
  head.append(el("span", "card-title", `Approval needed: ${describeAction(d.action)}`), timer);
  card.append(head, actionList(d.action, d.to_label));
  card.append(reviewBlock(d.verdict || (d.flagged ? "block" : "approve"), d.review_reason, d.span, d.reviewer_model));
  card.append(ruleBlock(d.rule));
  const receipts = receiptBlock(d.receipts);
  card.append(receipts);

  const actions = el("div", "actions");
  const deny = el("button", "deny", "Deny");
  const approve = el("button", "approve", d.flagged ? "Approve anyway..." : "Approve");
  deny.type = approve.type = "button";
  actions.append(deny, approve);
  const msg = el("div", "card-msg");
  card.append(actions, msg);
  li.append(card);
  $("timeline").append(li);
  // Never jump past the task: bring a waiting card into view after a moment, and only as far as needed.
  setTimeout(() => {
    if (card.classList.contains("waiting")) card.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, 1500);

  const deadline = d.deadline * 1000;
  const started = deadline - d.timeout_s * 1000;     // when the card was first shown
  const tick = setInterval(() => {
    const left = Math.max(0, Math.round((deadline - Date.now()) / 1000));
    timer.textContent = `${left}s left, then it counts as a no`;
    if (left <= 0) clearInterval(tick);
  }, 500);
  cards[d.rid] = { card, actions, msg, timer, tick, receipts };

  const send = async (decision, phrase) => {
    const r = await api("/api/decide", { run_id: runId, rid: d.rid, decision, phrase: phrase || "" });
    if (!r.ok) msg.textContent = r.data.message || r.data.error || "Not accepted.";
    else msg.textContent = "";
  };
  deny.addEventListener("click", () => send("deny"));
  approve.addEventListener("click", () => {
    if (!d.flagged) return send("approve");
    if (card.querySelector(".override")) return;
    const box = el("div", "override");
    box.append(el("div", "", `The reviewer flagged this. To send it anyway, type "send anyway", read it again, then confirm. The gate refuses before ${d.override_delay_s} seconds have passed.`));
    const input = el("input");
    input.placeholder = "send anyway";
    input.setAttribute("aria-label", "Type send anyway");
    input.autocomplete = "off";
    const go = el("button", "", "Still send it");
    go.type = "button";
    go.disabled = true;
    const wait = () => {
      const left = d.override_delay_s - Math.floor((Date.now() - started) / 1000);
      go.disabled = left > 0 || input.value.trim().toLowerCase() !== "send anyway";
      go.textContent = left > 0 ? `Still send it (${left}s)` : "Still send it";
      if (left > 0) setTimeout(wait, 500);
    };
    input.addEventListener("input", wait);
    wait();
    go.addEventListener("click", () => send("approve", input.value));
    box.append(input, go);
    card.insertBefore(box, msg);
    input.focus();
  });
}

function outcomeText(d) {
  const by = d.by || "";
  let who = by.startsWith("human") ? "you" : by === "policy" ? "the policy" : by;
  if (d.status === "executed") {
    if ((d.receipts || []).some((r) => String(r.summary).includes("overrode flag"))) who = "you, overriding the reviewer's flag";
    if (d.action && d.action.type === "wallet_tx") return [true, `Approved by ${who}. Unsigned transaction prepared; nothing was signed or broadcast.`];
    return [true, `Approved by ${who}. Written to the outbox file ${d.result.dry_run || ""}; demo mode never delivers email.`];
  }
  if (d.status === "expired" && by === "human:held") {
    return [false, "Held for you. Nothing was sent; it waits in the queue for your yes or no."];
  }
  if (d.status === "expired") return [false, "No answer in time, so it was not sent. The gate fails closed."];
  if (d.status === "failed") return [false, "Approved, but the action failed. Recorded."];
  return [false, `Not sent. Denied by ${who}.${d.reason && by === "policy" ? " " + d.reason : ""}`];
}

function onGateResult(d) {
  let c = cards[d.rid];
  if (!c) {
    // decided without a human: show the same card, already decided
    const li = el("li");
    const card = el("article", "card");
    const head = el("div", "card-head");
    const held = d.status === "expired" && d.by === "human:held";
    head.append(el("span", "card-title", `${describeAction(d.action)}: ${held ? "held for you" : "decided without asking you"}`));
    card.append(head, actionList(d.action, d.to_label));
    if (d.review) card.append(reviewBlock(d.review.verdict, d.review.reason, d.review.span, d.review.model));
    else card.append(reviewBlock(null, "Not needed: the policy decided first.", "", "not asked"));
    card.append(ruleBlock(d.rule));
    li.append(card);
    $("timeline").append(li);
    c = { card };
  } else {
    clearInterval(c.tick);
    c.timer.textContent = "";
    c.card.classList.remove("waiting");
    c.actions.remove();
    const o = c.card.querySelector(".override");
    if (o) o.remove();
    c.receipts.remove();
  }
  const [good, text] = outcomeText(d);
  c.card.append(receiptBlock(d.receipts, "Receipts for this action"));
  c.card.append(el("div", `outcome ${good ? "ok" : "bad"}`, text));
  if (d.can_remember) c.card.append(rememberBox(d));
}

function rememberBox(d) {
  // You approved someone who is not in your memory. Offer to remember them as YOUR fact.
  const box = el("div", "override");
  const field = d.action.type === "wallet_tx" ? "wallet" : "email";
  const today = new Date().toISOString().slice(0, 10);
  box.append(el("div", "", `Remember ${d.action.to} for next time? It is saved as your own fact, with the source ` +
    `"approved by you on ${today}", so the next run treats it as a known contact.`));
  const input = el("input");
  input.placeholder = "Their name";
  input.setAttribute("aria-label", "Their name");
  input.maxLength = 60;
  const go = el("button", "", `Remember this ${field}`);
  go.type = "button";
  const msg = el("div", "card-msg");
  go.addEventListener("click", async () => {
    const r = await api("/api/remember", { run_id: runId, rid: d.rid, name: input.value });
    if (!r.ok) { msg.textContent = r.data.error || "Not saved."; return; }
    box.textContent = "";
    const ul = el("ul", "facts");
    ul.append(factItem(r.data.fact));
    box.append(el("div", "outcome ok", "Remembered. Run it again and this address counts as a known contact."), ul);
  });
  box.append(input, go, msg);
  return box;
}

function onSummary(d) {
  const s = $("summary");
  s.hidden = false;
  s.textContent = "";
  const final = el("div", "final md");
  final.append(renderMarkdown(d.final));
  s.append(el("div", "block-label", "The assistant's answer, in its own words"), final);
  let counts;
  if (d.outbound === 0 && d.refused) {
    counts = `Nothing reached the gate. ${d.refused} payment${d.refused > 1 ? "s were" : " was"} refused before it: ` +
      "the wallet was not one you saved.";
  } else if (d.outbound === 0 && scenario() === "morning") {
    counts = "Nothing reached the gate in these runs.";
  } else if (d.outbound === 0 && scenario() === "agentdojo") {
    counts = "Nothing reached the gate: with its warning on, the brain did not act on the published attack this " +
      "time. On AgentDojo's banking suite it did in 38% of attacked runs; the gate stopped every one (see RESULTS.md).";
  } else if (d.outbound === 0) {
    counts = $("unguarded").checked
      ? "Nothing reached the gate: the assistant did not try to send anything this time."
      : "Nothing reached the gate: the assistant did not try to send anything. To see the gate stop a model that obeys the email, tick \"Remove the brain's warning\" and run again.";
  } else {
    counts = `${d.outbound} outbound action${d.outbound > 1 ? "s" : ""} reached the gate: ${d.executed} went ahead, ${d.stopped} stopped.`;
    if (d.refused) counts += ` ${d.refused} payment${d.refused > 1 ? "s were" : " was"} refused before the gate: not a wallet you saved.`;
  }
  s.append(el("div", "counts", counts), el("div", "counts", `Tokens used this run: ${d.tokens_used.toLocaleString()}`));
}

// ---------------------------------------------------------------- receipts

function ledgerList(v, brokenLines) {
  const ol = el("ol", "ledger");
  for (const r of v.records) {
    const li = el("li", brokenLines.has(r.line) ? "broken" : "");
    const body = el("div");
    body.append(el("div", "", `${r.action || ""}  ${r.summary || ""}`), el("div", "h", `hash ${r.hash || ""}`));
    li.append(el("span", "ln", r.line), body);
    ol.append(li);
  }
  return ol;
}

$("verify").addEventListener("click", async () => {
  const out = $("verify-out");
  out.textContent = "Checking...";
  const { data: v } = await api("/api/verify");
  out.textContent = "";
  if (!v.count) { out.append(el("div", "verdict ok", "No receipts yet. Run a task first.")); return; }
  if (v.ok) out.append(el("div", "verdict ok", `OK. ${v.count} receipts, and every hash checks out.`));
  else out.append(el("div", "verdict bad", `Broken at line ${v.breaks[0].line}: ${v.breaks[0].detail}`));
  out.append(ledgerList(v, new Set(v.breaks.map((b) => b.line))));
});

$("tamper").addEventListener("click", async () => {
  const out = $("verify-out");
  out.textContent = "Editing a copy...";
  const { data } = await api("/api/tamper", {});
  out.textContent = "";
  if (data.error) { out.append(el("div", "verdict ok", data.error)); return; }
  const e = data.edit;
  out.append(el("p", "", `In a copy of your receipts, line ${e.line} was changed from "${e.before}" to "${e.after}". The hash was left alone, the way a forger would leave it.`));
  const c = data.copy;
  if (c.ok) out.append(el("div", "verdict bad", "The copy still verifies. That should not happen."));
  else out.append(el("div", "verdict bad", `Copy is broken at line ${c.breaks[0].line}: ${c.breaks[0].detail}`));
  out.append(ledgerList(c, new Set(c.breaks.map((b) => b.line))));
  out.append(el("div", `verdict ${data.original.ok ? "ok" : "bad"}`,
    data.original.ok ? `Your real receipts are untouched and still verify (${data.original.count} lines).`
      : "Your real receipts do not verify."));
});

init();
