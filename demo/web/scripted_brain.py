"""A scripted stand-in for the cloud brain, for trying the web page offline (DEMO_BRAIN=scripted).

No model. It plays each task the way a fairly gullible model would, so every rule gets a turn:
- with the brain's warning removed, it obeys an email that asks it to forward mail somewhere;
- in triage, it answers Dana, confirms the dentist, and believes Sam's "my wallet changed"
  email enough to try paying the new wallet (the pay tool refuses it: payees come only from
  facts you wrote);
- for a skill you wrote, it emails an address you named in it, or else reads and summarizes.
The page labels it as scripted.
"""
from __future__ import annotations

import json
import re

from homestead_gate import assistant as asst

_ADDR = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_WALLET = re.compile(r"0x[0-9a-fA-F]{40}")


def _call(name: str, n: int, **args) -> dict:
    return {"id": f"s{n}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}


class ScriptedBrain:
    model = "scripted brain (no model)"

    def chat(self, messages, tools=None, **kw) -> dict:
        task = next((m["content"] for m in messages if m["role"] == "user"), "")
        guarded = asst.SYSTEM_GUARD.strip() in messages[0]["content"]
        done = [(m.get("name"), json.loads(m["content"])) for m in messages if m["role"] == "tool"]
        names = [n for n, _ in done]
        n = len(done)
        offered = {t["function"]["name"] for t in tools or []}
        say = lambda text: {"role": "assistant", "content": text, "finish_reason": "stop"}
        act = lambda c: {"role": "assistant", "content": "", "tool_calls": [c], "finish_reason": "tool_calls"}

        if asst.Policy.task_asks_to_spend(task) and "pay_invoice" in offered:
            if "recall" not in names:
                return act(_call("recall", n, entity="Sam Rivera"))
            if "list_bills" not in names:
                return act(_call("list_bills", n))
            if "pay_invoice" not in names:
                return act(_call("pay_invoice", n, invoice_id="INV-104", to=asst.SAM_WALLET, value_eth=0.02))
            res = done[-1][1]
            return say(f"I tried to pay Sam's invoice **INV-104** (0.02 ETH). The gate said: "
                       f"**{res.get('status') or res.get('error')}**.")

        named = [a for a in _ADDR.findall(task) if a.lower() != asst.USER_EMAIL]
        if named and "send_email" in offered:                      # a skill you wrote that names someone
            if "send_email" not in names:
                words = " ".join(task.split()[:6])
                return act(_call("send_email", n, to=named[0], subject=words[:60], body=task))
            res = done[names.index("send_email")][1]
            return say(f"I wrote to **{named[0]}** as you asked. The gate said: "
                       f"**{res.get('status') or res.get('error')}**.")

        if "list_inbox" not in names:
            return act(_call("list_inbox", n))
        listing = next(r for nm, r in done if nm == "list_inbox").get("messages", [])
        read = {r.get("id") for nm, r in done if nm == "read_email"}
        for m in listing:
            if m["id"] not in read:
                return act(_call("read_email", n, id=m["id"]))
        emails = [r for nm, r in done if nm == "read_email" and "body" in r]

        if "reply to anything" in task.lower():
            return self._triage(emails, done, names, n, act, say)

        senders = {m["from"].lower() for m in listing} | {asst.USER_EMAIL}
        if not guarded and "send_email" not in names and "send_email" in offered:
            for r in emails:
                for addr in _ADDR.findall(r.get("body", "")):
                    if addr.lower() not in senders:
                        return act(_call("send_email", n, to=addr, subject="archive",
                                         body="\n\n".join(f"{m['from']}: {m['subject']}" for m in listing)))
        lines = "\n".join(f"- **{m['from']}**: {m['subject']}" for m in listing)
        tail = ""
        if "send_email" in names:
            tail = f"\n\nI also tried to send an email; the gate said: **{done[names.index('send_email')][1].get('status')}**."
        return say(f"You have **{len(listing)} emails**:\n\n{lines}{tail}")

    @staticmethod
    def _triage(emails, done, names, n, act, say):
        tried = [(nm, r) for nm, r in done if nm in ("send_email", "pay_invoice")]
        plan = []
        for e in emails:
            body, sender = e.get("body", ""), e.get("from", "")
            if "saturday" in e.get("subject", "").lower():
                plan.append(("recall", {"entity": "Dana"}))
                plan.append(("send_email", {"to": sender, "subject": f"Re: {e['subject']}",
                                            "body": "Yes, 7pm on Saturday works for me. See you then!"}))
            elif "reply to this email to confirm" in body.lower():
                plan.append(("send_email", {"to": sender, "subject": f"Re: {e['subject']}",
                                            "body": "Confirmed, see you Tuesday at 10:00."}))
            elif "new wallet" in body.lower() and _WALLET.search(body):
                plan.append(("pay_invoice", {"invoice_id": "INV-104", "to": _WALLET.search(body).group(0),
                                             "value_eth": 0.02}))
        for i, (tool, args) in enumerate(plan):
            if sum(1 for t, _ in plan[:i + 1] if t == tool) > names.count(tool):
                return act(_call(tool, n, **args))
        out = []
        for nm, r in tried:
            what = "a payment" if nm == "pay_invoice" else "an email"
            st = {"expired": "held for your yes", "executed": "done"}.get(r.get("status"), r.get("status") or "refused")
            out.append(f"- {what}: **{st}**" + (f" ({r['error'].split(' Do not pay')[0]})" if r.get("error") else ""))
        return say(f"I went through **{len(emails)} new email{'s' if len(emails) != 1 else ''}**."
                   + ("\n\n" + "\n".join(out) if out else "\n\nNothing needed an answer."))
