#!/usr/bin/env python3
"""Validate pentest scope entries.

Supported entries:
- Exact hostname/FQDN (e.g. app.example.com)
- IPv4 CIDR (e.g. 10.0.0.0/24)
- Wildcard hostname (e.g. *.example.com)

Exit codes:
- 0: all entries valid (and no strict-policy violations)
- 1: one or more entries are syntactically invalid
- 2: strict mode policy violation (wildcard entries present)
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from typing import Iterable, List, Tuple

HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)
WILDCARD_RE = re.compile(
    r"^\*\.(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def classify_entry(entry: str) -> str:
    if _is_cidr(entry):
        return "cidr"
    if WILDCARD_RE.match(entry):
        return "wildcard"
    if HOST_RE.match(entry):
        return "exact"
    return "invalid"


def validate_entries(entries: Iterable[str], strict: bool = False) -> Tuple[int, List[str], List[str]]:
    invalid: List[str] = []
    wildcards: List[str] = []

    for raw in entries:
        entry = raw.strip()
        if not entry:
            continue
        kind = classify_entry(entry)
        if kind == "invalid":
            invalid.append(entry)
        elif kind == "wildcard":
            wildcards.append(entry)

    if invalid:
        return 1, invalid, wildcards
    if strict and wildcards:
        return 2, invalid, wildcards
    return 0, invalid, wildcards


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate pentest scope entries")
    parser.add_argument(
        "entries",
        nargs="*",
        help="Scope entries to validate (exact host, CIDR, wildcard)",
    )
    parser.add_argument(
        "--file",
        dest="file_path",
        help="Optional file containing one scope entry per line",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat wildcard entries as policy violations (exit 2)",
    )
    return parser


def _read_file_entries(file_path: str) -> List[str]:
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    entries: List[str] = list(args.entries)
    if args.file_path:
        entries.extend(_read_file_entries(args.file_path))

    code, invalid, wildcards = validate_entries(entries, strict=args.strict)

    if code == 1:
        print("Invalid scope entries:", file=sys.stderr)
        for item in invalid:
            print(f"- {item}", file=sys.stderr)
    elif code == 2:
        print("Strict mode violation: wildcard scope entries are not allowed:", file=sys.stderr)
        for item in wildcards:
            print(f"- {item}", file=sys.stderr)
    else:
        print("Scope validation passed")

    return code


if __name__ == "__main__":
    raise SystemExit(main())
