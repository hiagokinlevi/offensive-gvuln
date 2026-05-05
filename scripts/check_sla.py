#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from vuln_management.models import Finding, Severity
from vuln_management.sla import get_overdue_findings


def _parse_iso_date(value: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            f"invalid --created-before date '{value}'; expected YYYY-MM-DD"
        ) from exc
    # Enforce strict YYYY-MM-DD (date.fromisoformat accepts this format; this guard ensures no surprises)
    if parsed.isoformat() != value:
        raise argparse.ArgumentTypeError(
            f"invalid --created-before date '{value}'; expected YYYY-MM-DD"
        )
    return parsed


def _load_findings(path: Path) -> list[Finding]:
    data: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Findings file must be a JSON array")
    return [Finding.model_validate(item) for item in data]


def _created_on_or_before(finding: Finding, cutoff: date) -> bool:
    created = finding.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    created_date = created.astimezone(timezone.utc).date()
    return created_date <= cutoff


def main() -> int:
    parser = argparse.ArgumentParser(description="Check overdue vulnerability findings by SLA")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument(
        "--severity",
        choices=[s.value for s in Severity],
        help="Only evaluate findings of this severity",
    )
    parser.add_argument("--tier", help="Only evaluate findings for this ownership tier")
    parser.add_argument(
        "--created-before",
        type=_parse_iso_date,
        help="Only include findings created on or before YYYY-MM-DD before SLA evaluation",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only output aggregate counts (suitable for cron/CI)",
    )

    args = parser.parse_args()

    findings = _load_findings(Path(args.findings))

    if args.created_before is not None:
        findings = [f for f in findings if _created_on_or_before(f, args.created_before)]

    if args.severity:
        findings = [f for f in findings if f.severity.value == args.severity]
    if args.tier:
        findings = [f for f in findings if f.owner_tier == args.tier]

    overdue = get_overdue_findings(findings)

    if not args.summary_only:
        for finding in overdue:
            print(
                f"{finding.id}\t{finding.severity.value}\t{finding.owner_tier}\t"
                f"created={finding.created_at.isoformat()}"
            )

    print(f"total_findings={len(findings)} overdue={len(overdue)}")
    return 1 if overdue else 0


if __name__ == "__main__":
    raise SystemExit(main())
