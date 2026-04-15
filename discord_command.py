#!/usr/bin/env python3
"""Discord-friendly command wrapper for OSINT Helper.

Usage examples:
  !osint username snipercat1822
  !osint username snipercat1822 --probe
  !osint domain example.com
  !osint ip 8.8.8.8
  !osint email analyst@example.com
  !osint phone +15551234567
  !osint asn AS15169
  !osint ioc google.com 8.8.8.8 analyst@example.com https://example.com/login
"""

from __future__ import annotations

import os
import sys
import shlex
import argparse
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import osint_helper as core
import proxy_rotation

DISCORD_LIMIT = 1900


def parse_message(message: str) -> argparse.Namespace:
    message = message.strip()
    if message.startswith("!osint"):
        payload = message[len("!osint") :].strip()
    elif message.startswith("/osint"):
        payload = message[len("/osint") :].strip()
    else:
        raise ValueError("Message must start with !osint or /osint")

    parts = shlex.split(payload)
    if len(parts) < 2:
        raise ValueError(
            "Usage: !osint <username|domain|ip|email|phone|asn|ioc> <value...> [--probe] [--json]"
        )

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("mode", choices=["username", "domain", "ip", "email", "phone", "asn", "ioc"])
    parser.add_argument("values", nargs="+")
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--burner", action="store_true", help="Route requests through rotating proxies to hide your IP")
    args = parser.parse_args(parts)

    if args.mode != "username" and args.probe:
        raise ValueError("--probe is only supported with !osint username")
    if args.mode != "ioc" and len(args.values) != 1:
        raise ValueError("Non-IOC modes accept exactly one target value")

    return args


def shorten(text: str, max_len: int = DISCORD_LIMIT) -> str:
    if len(text) <= max_len:
        return text
    clipped = text[: max_len - 120].rstrip()
    return (
        clipped
        + "\n\n[truncated for Discord]\n"
        + "Tip: add --json for machine output or run the local CLI for full detail."
    )


def run_from_message(message: str) -> str:
    args = parse_message(message)
    value = args.values[0]

    # Activate burner mode if requested
    if args.burner:
        proxy_rotation.enable_burner()

    if args.mode == "username":
        report = core.build_username_report(value, probe=args.probe)
    elif args.mode == "domain":
        report = core.build_domain_report(value)
    elif args.mode == "ip":
        report = core.build_ip_report(value)
    elif args.mode == "phone":
        report = core.build_phone_report(value)
    elif args.mode == "asn":
        report = core.build_asn_report(value)
    elif args.mode == "ioc":
        report = core.build_ioc_report(args.values)
    else:
        report = core.build_email_report(value)

    proxy_rotation.disable_burner()

    out = json.dumps(report, indent=2, ensure_ascii=False) if args.json else core.render_text(report)
    return shorten(out)


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: discord_command.py '!osint domain example.com'")
        return 2

    raw = " ".join(sys.argv[1:])
    try:
        print(run_from_message(raw))
        return 0
    except Exception as e:
        print(f"OSINT command error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
