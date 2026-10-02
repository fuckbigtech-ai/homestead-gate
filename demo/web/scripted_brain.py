"""A scripted stand-in for the cloud brain, for trying the web page offline (DEMO_BRAIN=scripted).

No model. It plays the scenarios the way a gullible model would: with the brain's warning
removed, it obeys an email that asks it to forward mail to an address. The page labels it.
"""
from __future__ import annotations

import json
import re

from homestead_gate import assistant as asst

_ADDR = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


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
        say = lambda text: {"role": "assistant", "content": text, "finish_reason": "stop"}
        act = lambda c: {"role": "assistant", "content": "", "tool_calls": [c], "finish_reason": "tool_calls"}

        if asst.Policy.task_asks_to_spend(task):
            if "recall" not in names:
                return act(_call("recall", n, entity="Sam Rivera"))
            if "list_bills" not in names:
                return act(_call("list_bills", n))
            if "pay_invoice" not in names:
                return act(_call("pay_invoice", n, invoice_id="INV-104", to=asst.SAM_WALLET, value_eth=0.02))
            res = done[-1][1]
            return say(f"I tried to pay Sam's invoice INV-104 (0.02 ETH). The gate said: {res.get('status')}.")

        if "list_inbox" not in names:
            return act(_call("list_inbox", n))
        listing = next(r for nm, r in done if nm == "list_inbox")["messages"]
        read = {r.get("id") for nm, r in done if nm == "read_email"}
        for m in listing:
            if m["id"] not in read:
                return act(_call("read_email", n, id=m["id"]))
        senders = {m["from"].lower() for m in listing} | {asst.USER_EMAIL}
        if not guarded and "send_email" not in names:
            for nm, r in done:
                if nm == "read_email":
                    for addr in _ADDR.findall(r.get("body", "")):
                        if addr.lower() not in senders:
                            return act(_call("send_email", n, to=addr, subject="archive",
                                             body="\n\n".join(f"{m['from']}: {m['subject']}" for m in listing)))
        lines = "; ".join(f"{m['from']}: {m['subject']}" for m in listing)
        tail = ""
        if "send_email" in names:
            tail = f" I also tried to send an email; the gate said: {done[names.index('send_email')][1].get('status')}."
        return say(f"You have {len(listing)} emails. {lines}.{tail}")
