#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from vuln_management.models import Finding
from vuln_management.sla import is_overdue


def _parse_iso_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid value for --updated-after: '{value}'. Expected format YYYY-MM-DD."
        ) from exc


def _parse_datetime(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _load_findings(path: Path) -> list[Finding]:
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        items = data.get("findings", [])
    else:
        items = data
    return [Finding.model_validate(item) for item in items]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check remediation SLA status for findings")
    parser.add_argument("--findings", required=True, help="Path to findings JSON")
    parser.add_argument(
        "--severity",
        action="append",
        default=[],
        help="Filter by severity (repeatable)",
    )
    parser.add_argument(
        "--state",
        action="append",
        default=[],
        help="Filter by state (repeatable)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print aggregate summary only",
    )
    parser.add_argument(
        "--updated-after",
        type=_parse_iso_date,
        help="Include only findings updated on or after YYYY-MM-DD before SLA evaluation",
    )
    return parser


def _matches_filters(finding: Finding, severities: set[str], states: set[str], updated_after: date | None) -> bool:
    if severities and finding.severity.value not in severities:
        return False
    if states and finding.state.value not in states:
        return False
    if updated_after is not None:
        updated_at = _parse_datetime(finding.updated_at)
        if updated_at is None or updated_at.date() < updated_after:
            return False
    return True


def main() -> int:
    args = build_parser().parse_args()
    findings = _load_findings(Path(args.findings))

    severities = {s.lower() for s in args.severity}
    states = {s.lower() for s in args.state}

    filtered = [
        f
        for f in findings
        if _matches_filters(f, severities=severities, states=states, updated_after=args.updated_after)
    ]

    overdue = [f for f in filtered if is_overdue(f)]

    if not args.summary_only:
        for f in overdue:
            print(f"{f.id}\t{f.severity.value}\t{f.state.value}\toverdue")

    print(
        json.dumps(
            {
                "total": len(filtered),
                "overdue": len(overdue),
                "compliant": len(filtered) - len(overdue),
            }
        )
    )

    return 1 if overdue else 0


if __name__ == "__main__":
    raise SystemExit(main())
