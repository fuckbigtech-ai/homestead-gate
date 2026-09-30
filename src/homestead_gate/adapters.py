"""What happens after both yeses. Deliberately boring and deliberately limited.

email      dry-run by default: the message is written to an outbox folder as .eml.
           SMTP delivery only when the policy names a server AND the gate was started
           with --live.
wallet_tx  prepare-only. Builds an UNSIGNED Sepolia transaction and hands it back.
           The gate holds no keys and never broadcasts; your own wallet signs.
"""
from __future__ import annotations

import smtplib
import time
from decimal import Decimal
from email.message import EmailMessage
from pathlib import Path

from .policy import SEPOLIA


def build_email(action: dict, sender: str) -> EmailMessage:
    m = EmailMessage()
    m["From"], m["To"] = sender, action["to"]
    m["Subject"] = action.get("subject", "")
    m.set_content(action.get("body", ""))
    return m


def send_email(action: dict, *, sender: str, outbox: Path, smtp: dict | None, live: bool) -> dict:
    msg = build_email(action, sender)
    if live and smtp:
        with smtplib.SMTP(smtp["host"], int(smtp.get("port", 587)), timeout=30) as s:
            if smtp.get("starttls", True):
                s.starttls()
            if smtp.get("user"):
                s.login(smtp["user"], smtp["password"])
            s.send_message(msg)
        return {"delivered": True, "via": f"smtp {smtp['host']}"}
    outbox.mkdir(parents=True, exist_ok=True)
    path = outbox / f"{int(time.time() * 1000)}.eml"
    path.write_bytes(bytes(msg))
    return {"delivered": False, "dry_run": str(path)}


def prepare_tx(action: dict) -> dict:
    chain = int(action.get("chain_id", SEPOLIA))
    if chain != SEPOLIA:
        raise ValueError(f"refusing chain {chain}: v1 prepares Sepolia transactions only")
    wei = int(Decimal(str(action.get("value_eth", 0) or 0)) * 10**18)
    return {"unsigned_tx": {"chainId": chain, "to": action["to"], "value": hex(wei),
                            "data": action.get("data") or "0x"},
            "signed": False, "note": "unsigned. sign it with your own wallet; the gate holds no keys."}
