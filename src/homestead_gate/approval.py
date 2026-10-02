"""The human half of the 2-of-2 gate.

The yes comes from the terminal the human started the gate in, and from nowhere else.
There is deliberately no approve endpoint on the daemon: anything that can reach
127.0.0.1:6000 (the agent, another local process, a web page doing cross-site requests
to localhost) could otherwise approve its own request, and 2-of-2 would quietly become
1-of-1.

Override friction: approving something the model flagged takes a typed phrase, then a
wait, then a second yes. Approval fatigue is the known way these gates fail; the friction
lands only on the rare flagged case, so it is cheap where it matters.
"""
from __future__ import annotations

import re
import select
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable

OVERRIDE_PHRASE = "send anyway"
BODY_LINES = 20
NO_MODEL_REASON = "no reviewer model (--no-model)"   # shown as is, never as a flag
# C0 and C1 control characters, ESC included. Everything shown here was written by the
# agent or quotes what it read, and one ANSI sequence (conceal, cursor-up, colour matched
# to the background) is enough to hide the model's flag line from the human.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(value) -> str:
    return _CONTROL.sub("?", str(value))


@dataclass
class HumanDecision:
    decision: str        # approve | deny | expired
    channel: str
    latency_s: float
    overrode_flag: bool = False


def _tty_input(prompt: str, timeout_s: float) -> str | None:
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [], [], max(0.0, timeout_s))
    if not ready:
        return None
    line = sys.stdin.readline()
    return line.strip() if line else None


class TerminalApprover:
    def __init__(self, *, override_delay_s: float = 60, timeout_s: float = 300,
                 input_fn: Callable[[str, float], str | None] = _tty_input,
                 out: Callable[[str], None] = print, sleep: Callable[[float], None] = time.sleep,
                 channel: str = "terminal"):
        self.delay, self.timeout = override_delay_s, timeout_s
        self.input, self.out, self.sleep, self.channel = input_fn, out, sleep, channel
        self._lock = threading.Lock()      # one prompt at a time, even with parallel requests

    def ask(self, *, rid: str, action: dict, flagged: bool, review_reason: str, span: str) -> HumanDecision:
        with self._lock:
            t0 = time.time()
            left = lambda: self.timeout - (time.time() - t0)
            self.out("")
            self.out(f"== approval needed [{rid}] ==")
            for k in ("type", "to", "subject", "value_eth", "chain_id", "data"):
                if action.get(k) not in (None, ""):
                    self.out(f"  {k:<9} {clean(action[k])}")
            if action.get("body"):
                lines = str(action["body"]).splitlines()
                self.out("  body:")
                for ln in lines[:BODY_LINES]:
                    self.out(f"    | {clean(ln)}")
                if len(lines) > BODY_LINES:
                    hidden = sum(len(x) + 1 for x in lines[BODY_LINES:])
                    self.out(f"    (+{len(lines) - BODY_LINES} more lines, {hidden} characters not shown)")
            if flagged and review_reason.startswith(NO_MODEL_REASON):
                self.out(f"  -- {clean(review_reason)}")
            elif flagged:
                self.out(f"  !! reviewer FLAGGED this: {clean(review_reason)}")
                if span:
                    self.out(f"  !! suspicious text: {clean(span[:200])}")
            else:
                self.out(f"  reviewer: ok ({clean(review_reason)})")

            ans = self.input("approve? [y/N] ", left())
            if ans is None:
                return HumanDecision("expired", self.channel, round(time.time() - t0, 2))
            if ans.lower() not in ("y", "yes"):
                return HumanDecision("deny", self.channel, round(time.time() - t0, 2))
            if not flagged:
                return HumanDecision("approve", self.channel, round(time.time() - t0, 2))

            phrase = self.input(f"the model flagged this. type '{OVERRIDE_PHRASE}' to continue: ", left())
            if phrase is None:
                return HumanDecision("expired", self.channel, round(time.time() - t0, 2))
            if phrase.strip().lower() != OVERRIDE_PHRASE:
                return HumanDecision("deny", self.channel, round(time.time() - t0, 2))
            self.out(f"  waiting {self.delay:g}s before the final yes. read it again.")
            self.sleep(self.delay)
            final = self.input("still send it? [y/N] ", left())
            if final is None:
                return HumanDecision("expired", self.channel, round(time.time() - t0, 2))
            ok = final.lower() in ("y", "yes")
            return HumanDecision("approve" if ok else "deny", self.channel,
                                 round(time.time() - t0, 2), overrode_flag=ok)
