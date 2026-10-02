"""Skills: named, reusable requests the user writes in a file they own.

A skill is the user's own instruction plus the tools it may use, kept in `skills.toml` in the
assistant's data dir:

  [skills.triage]
  instruction = "Go through my new mail and reply to anything that needs an answer from me."
  tools = ["list_inbox", "read_email", "recall", "send_email"]
  schedule = "every 15m"          # optional; used by `assistant --watch`

The instruction is the user's request, so the gate trusts it: it becomes the task the reviewer
judges every action against. The tools list narrows what the cloud model is offered for that
skill; outbound tools still go through the gate whatever the list says. A skill cannot add a
tool that does not exist, and it cannot turn the gate off.
"""
from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

SKILLS_FILE = "skills.toml"
NAME = re.compile(r"^[a-z][a-z0-9_-]{0,23}$")
INSTRUCTION_MAX = 500
ALL_TOOLS = ("list_inbox", "read_email", "list_bills", "recall", "remember", "send_email", "pay_invoice")
# What a skill written on a web page may use: read, look things up and write email (which still
# stops at the gate). No payments and no writing to memory.
SAFE_TOOLS = ("list_inbox", "read_email", "list_bills", "recall", "send_email")
_INTERVAL = re.compile(r"^(?:every\s+)?(\d+)\s*(s|sec|m|min|h|hr|hour|d|day)s?$", re.I)
_UNIT = {"s": 1, "sec": 1, "m": 60, "min": 60, "h": 3600, "hr": 3600, "hour": 3600, "d": 86400, "day": 86400}


@dataclass(frozen=True)
class Skill:
    name: str
    instruction: str
    tools: tuple[str, ...] = ALL_TOOLS
    schedule: str = ""
    origin: str = "default"          # default | yours

    def as_dict(self) -> dict:
        return {"name": self.name, "instruction": self.instruction, "tools": list(self.tools),
                "schedule": self.schedule, "origin": self.origin}


DEFAULT_SKILLS = (
    Skill("triage", "Go through my inbox and reply to anything that needs an answer from me. "
          "I'm free Saturday evening.",
          ("list_inbox", "read_email", "list_bills", "recall", "send_email", "pay_invoice"), "every 15m"),
    Skill("pay", "Pay Sam the plumber's invoice.", ("recall", "list_bills", "pay_invoice")),
    Skill("summarize", "Summarize my inbox for me.", ("list_inbox", "read_email", "recall", "send_email")),
)


class SkillError(ValueError):
    pass


def parse_interval(text: str) -> int:
    """'15m', 'every 15m', '1h', '90s' -> seconds."""
    m = _INTERVAL.match(str(text or "").strip())
    if not m:
        raise SkillError(f"cannot read the interval {text!r}; write it like 15m, 1h or 'every 30m'")
    secs = int(m.group(1)) * _UNIT[m.group(2).lower()]
    if secs <= 0:
        raise SkillError("the interval must be more than zero")
    return secs


def validate(name: str, instruction: str, tools, schedule: str = "", origin: str = "yours") -> Skill:
    name = str(name or "").strip().lower()
    if not NAME.match(name):
        raise SkillError("a skill name is 1 to 24 characters: lower-case letters, digits, - or _, "
                         "starting with a letter")
    instruction = " ".join(str(instruction or "").split())
    if not instruction:
        raise SkillError(f"skill {name!r} has no instruction")
    if len(instruction) > INSTRUCTION_MAX:
        raise SkillError(f"skill {name!r}: the instruction is limited to {INSTRUCTION_MAX} characters")
    tools = tuple(str(t) for t in (tools if tools is not None else ALL_TOOLS))
    bad = [t for t in tools if t not in ALL_TOOLS]
    if bad:
        raise SkillError(f"skill {name!r} names tools that do not exist: {', '.join(bad)} "
                         f"(choose from {', '.join(ALL_TOOLS)})")
    if not tools:
        raise SkillError(f"skill {name!r} has no tools")
    schedule = str(schedule or "").strip()
    if schedule:
        parse_interval(schedule)
    return Skill(name, instruction, tuple(dict.fromkeys(tools)), schedule, origin)


def _toml(skill: Skill) -> str:
    # json.dumps gives a valid TOML basic string (TOML accepts the same escapes, \uXXXX included).
    lines = [f"[skills.{skill.name}]", f"instruction = {json.dumps(skill.instruction)}",
             "tools = [" + ", ".join(json.dumps(t) for t in skill.tools) + "]"]
    if skill.schedule:
        lines.append(f"schedule = {json.dumps(skill.schedule)}")
    return "\n".join(lines) + "\n"


HEADER = """# Your skills. Each one is a request you make often, in your own words.
# The instruction is YOUR request: the gate judges every action against it.
# tools: what the assistant may use for this skill. Outbound tools (send_email, pay_invoice)
# still stop at the gate. schedule: how often `homestead-gate assistant --watch` runs it.
# Available tools: """ + ", ".join(ALL_TOOLS) + "\n\n"


def write_skills(path: Path, skills) -> None:
    Path(path).write_text(HEADER + "\n".join(_toml(s) for s in skills))


def ensure_skills_file(data_dir: Path) -> bool:
    """Write the default skills.toml if the data dir has none. Returns True when it wrote one."""
    p = Path(data_dir) / SKILLS_FILE
    if p.exists():
        return False
    p.parent.mkdir(parents=True, exist_ok=True)
    write_skills(p, DEFAULT_SKILLS)
    return True


def load_skills(data_dir: Path) -> dict[str, Skill]:
    """Read skills.toml. A default skill keeps origin 'default' while its text is unchanged."""
    p = Path(data_dir) / SKILLS_FILE
    try:
        raw = tomllib.loads(p.read_text())
    except FileNotFoundError:
        return {s.name: s for s in DEFAULT_SKILLS}
    except tomllib.TOMLDecodeError as e:
        raise SkillError(f"{p} is not valid TOML: {e}") from None
    defaults = {s.name: s for s in DEFAULT_SKILLS}
    out: dict[str, Skill] = {}
    for name, d in (raw.get("skills") or {}).items():
        if not isinstance(d, dict):
            raise SkillError(f"[skills.{name}] must be a table")
        s = validate(name, d.get("instruction", ""), d.get("tools"), d.get("schedule", ""))
        if defaults.get(s.name) == Skill(s.name, s.instruction, s.tools, s.schedule, "default"):
            s = defaults[s.name]
        out[s.name] = s
    return out


def save_skill(data_dir: Path, skill: Skill) -> None:
    """Add or replace one skill in skills.toml, keeping the others."""
    ensure_skills_file(data_dir)
    skills = load_skills(data_dir)
    skills[skill.name] = skill
    write_skills(Path(data_dir) / SKILLS_FILE, skills.values())
