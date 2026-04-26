#!/usr/bin/env python3
"""Check vulnerability SLA compliance from a findings JSON file.

Example:
  python scripts/check_sla.py --findings findings.json --updated-since 2026-01-01T00:00:00Z
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SLA_BY_SEVERITY = {
    "critical": 24 * 60 * 60,
    "high": 7 * 24 * 60 * 60,
    "medium": 30 * 24 * 60 * 60,
    "low": 90 * 24 * 60 * 60,
}


def _parse_iso8601(value: str, *, arg_name: str) -> datetime:
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid {arg_name} datetime: '{value}'. Expected ISO-8601 format, e.g. 2026-01-01T00:00:00Z"
        ) from exc

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _pick_updated_at(finding: dict[str, Any]) -> datetime | None:
    for key in ("updated_at", "updatedAt", "last_updated", "lastUpdated", "modified_at", "modifiedAt"):
        val = finding.get(key)
        if isinstance(val, str) and val.strip():
            try:
                return _parse_iso8601(val, arg_name=key)
            except argparse.ArgumentTypeError:
                return None
    return None


def _iter_findings(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return

    if isinstance(payload, dict):
        for key in ("findings", "items", "data"):
            val = payload.get(key)
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        yield item
                return


def _is_overdue(finding: dict[str, Any], now: datetime) -> bool:
    severity = str(finding.get("severity", "")).strip().lower()
    if severity not in SLA_BY_SEVERITY:
        return False

    opened = finding.get("created_at") or finding.get("createdAt") or finding.get("discovered_at") or finding.get("discoveredAt")
    if not isinstance(opened, str) or not opened.strip():
        return False

    try:
        opened_dt = _parse_iso8601(opened, arg_name="created_at")
    except argparse.ArgumentTypeError:
        return False

    age_seconds = (now - opened_dt).total_seconds()
    return age_seconds > SLA_BY_SEVERITY[severity]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check overdue vulnerability findings based on severity SLA windows.",
        epilog="Usage example: python scripts/check_sla.py --findings findings.json --updated-since 2026-01-01T00:00:00Z",
    )
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument(
        "--updated-since",
        type=lambda s: _parse_iso8601(s, arg_name="--updated-since"),
        default=None,
        help="Only evaluate findings updated on/after this ISO-8601 timestamp (e.g. 2026-01-01T00:00:00Z)",
    )
    args = parser.parse_args()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        print(f"ERROR: Findings file not found: {findings_path}", file=sys.stderr)
        return 2

    try:
        payload = json.loads(findings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"ERROR: Invalid JSON in findings file: {exc}", file=sys.stderr)
        return 2

    findings = list(_iter_findings(payload))

    if args.updated_since is not None:
        filtered: list[dict[str, Any]] = []
        for f in findings:
            updated_at = _pick_updated_at(f)
            if updated_at is not None and updated_at >= args.updated_since:
                filtered.append(f)
        findings = filtered

    now = datetime.now(timezone.utc)
    overdue = [f for f in findings if _is_overdue(f, now)]

    # Keep output format simple/unchanged: single summary line.
    print(f"overdue={len(overdue)} total={len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
