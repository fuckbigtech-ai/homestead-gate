"""MCP server that gives an agent exactly two outbound tools, both routed through the gate.

    claude mcp add homestead-gate -- homestead-gate mcp

The agent gets gate_send_email and gate_prepare_wallet_tx. Each call becomes a POST to the
gate on 127.0.0.1:6000 and blocks until the human in the gate's terminal decides, so the
agent sees executed / denied / expired and nothing else. This server holds no credentials
and cannot approve anything; it is a thin, replaceable pipe.

This only helps if these are the agent's ONLY way out. An agent that also has a mail CLI,
an API token or a wallet key can simply not call them. That is what the sandbox milestone
is for, and the README says so.

Stdlib only. Same dual-era MCP subset as homestead-memory's server (initialize / ping /
tools/list / tools/call, plus server/discover for stateless 2026-07-28 clients).
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

from . import __version__

MODERN = "2026-07-28"
LEGACY = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
_META_VERSION = "io.modelcontextprotocol/protocolVersion"

_READ = {
    "type": "array",
    "description": ("Everything you read that led to this action: emails, web pages, tool output. "
                    "Include it verbatim. The reviewer treats it as untrusted data."),
    "items": {"type": "object", "properties": {"source": {"type": "string"}, "content": {"type": "string"}},
              "required": ["source", "content"]},
}
TOOLS = [
    {"name": "gate_send_email",
     "description": ("Send an email. The only way to send email. The user's policy decides first: mail to "
                     "the user's own address can pass automatically, and some sends are refused outright. "
                     "Everything else is reviewed by a local model and approved or denied by the user. "
                     "The call waits for that decision and returns it."),
     "inputSchema": {"type": "object", "additionalProperties": False, "required": ["to", "subject", "body"],
                     "properties": {"to": {"type": "string"}, "subject": {"type": "string"},
                                    "body": {"type": "string"}, "read": _READ}}},
    {"name": "gate_prepare_wallet_tx",
     "description": ("Prepare an Ethereum transaction on Sepolia testnet. Reviewed and approved like email. "
                     "Returns an UNSIGNED transaction; nothing is signed or broadcast."),
     "inputSchema": {"type": "object", "additionalProperties": False, "required": ["to", "value_eth"],
                     "properties": {"to": {"type": "string"}, "value_eth": {"type": "number", "minimum": 0},
                                    "data": {"type": "string"}, "read": _READ}}},
]


def to_request(name: str, args: dict) -> dict:
    read = [r for r in (args.get("read") or []) if isinstance(r, dict)]
    if name == "gate_send_email":
        action = {"type": "email", "to": args["to"], "subject": args["subject"], "body": args["body"]}
    else:
        action = {"type": "wallet_tx", "chain_id": 11155111, "to": args["to"],
                  "value_eth": args["value_eth"], **({"data": args["data"]} if args.get("data") else {})}
    return {"action": action, "read": read}


def forward(req: dict, url: str, timeout_s: float) -> dict:
    r = urllib.request.Request(f"{url}/v1/request", data=json.dumps(req).encode(),
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=timeout_s) as resp:
        return json.loads(resp.read())


def _text(obj: dict, error: bool) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(obj)}], "isError": error}


def call_tool(name: str, args: dict, url: str, timeout_s: float) -> dict:
    missing = [k for k in next(t for t in TOOLS if t["name"] == name)["inputSchema"]["required"] if k not in args]
    if missing:
        return _text({"error": f"missing {', '.join(missing)}"}, True)
    try:
        res = forward(to_request(name, args), url, timeout_s)
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        # No gate, no send. The agent is told plainly rather than left to find another route.
        return _text({"status": "not sent", "error": f"the gate is not running ({e}). "
                      "ask the user to start it with `homestead-gate up`."}, True)
    return _text(res, res.get("status") != "executed")


def handle(msg, state: dict, url: str, timeout_s: float):
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return None
    mid, method = msg.get("id"), msg.get("method")
    if "id" not in msg:
        if method == "notifications/initialized" and state.get("seen"):
            state["ready"] = True
        return None
    err = lambda code, m: {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": m}}
    params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
    modern = isinstance(params.get("_meta"), dict) and _META_VERSION in params["_meta"]
    # 2026-07-28 makes resultType REQUIRED on every result; clients reject tools/list without
    # it. Earlier revisions treat absence as "complete", so it is only added for modern calls.
    ok = lambda result: {"jsonrpc": "2.0", "id": mid,
                         "result": {**result, "resultType": "complete"} if modern or method == "server/discover" else result}
    info = {"name": "homestead-gate", "version": __version__}

    if method == "server/discover":
        return ok({"supportedVersions": [MODERN, *LEGACY], "capabilities": {"tools": {}},
                   "_meta": {"io.modelcontextprotocol/serverInfo": info}})
    if method == "initialize":
        state["seen"] = True
        asked = params.get("protocolVersion")
        return ok({"protocolVersion": asked if asked in LEGACY else LEGACY[0],
                   "capabilities": {"tools": {}}, "serverInfo": info})
    if method == "ping":
        return ok({})
    if not modern and not state.get("ready"):
        return err(-32002, "server not initialized")
    if method == "tools/list":
        # Modern clients also require a cache hint on list results. The tool set is fixed
        # per release; "private" because a local gate's tools are this user's alone.
        return ok({"tools": TOOLS, **({"ttlMs": 300_000, "cacheScope": "private"} if modern else {})})
    if method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name not in {t["name"] for t in TOOLS}:
            return err(-32602, f"unknown tool: {name}")
        if not isinstance(args, dict):
            return err(-32602, "arguments must be an object")
        return ok(call_tool(name, args, url, timeout_s))
    return err(-32601, f"method not found: {method}")


def serve(url: str = "http://127.0.0.1:6000", timeout_s: float = 600) -> int:
    state: dict = {}
    print(f"homestead-gate MCP on stdio, forwarding to {url}", file=sys.stderr)
    try:
        for line in sys.stdin:
            if not line.strip():
                continue
            try:
                out = handle(json.loads(line), state, url, timeout_s)
            except ValueError:
                out = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            if out is not None:
                sys.stdout.write(json.dumps(out) + "\n")
                sys.stdout.flush()
    except (BrokenPipeError, KeyboardInterrupt):
        pass
    return 0
