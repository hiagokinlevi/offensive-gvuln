#!/usr/bin/env python3
"""Check vulnerability findings for overdue SLA breaches."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

from vuln_management.sla import check_overdue_findings

_ALLOWED_SEVERITIES = {"Critical", "High", "Medium", "Low"}


def _parse_severity_filter(raw: str | None) -> list[str] | None:
    if raw is None:
        return None

    items = [part.strip() for part in raw.split(",") if part.strip()]
    if not items:
        raise ValueError("--severity must include at least one value")

    invalid = [s for s in items if s not in _ALLOWED_SEVERITIES]
    if invalid:
        raise ValueError(
            "Invalid severity value(s): "
            + ", ".join(invalid)
            + ". Allowed: Critical, High, Medium, Low"
        )

    # Preserve user order while deduplicating.
    deduped: list[str] = []
    for s in items:
        if s not in deduped:
            deduped.append(s)
    return deduped


def _filter_findings_by_severity(findings: Iterable[dict], severities: list[str] | None) -> list[dict]:
    if not severities:
        return list(findings)
    allowed = set(severities)
    return [f for f in findings if f.get("severity") in allowed]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check findings against SLA windows")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument(
        "--severity",
        help="Optional severity filter (single or comma-separated): Critical,High,Medium,Low",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        selected_severities = _parse_severity_filter(args.severity)
    except ValueError as exc:
        parser.error(str(exc))

    findings_path = Path(args.findings)
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    findings = data.get("findings", data)
    findings = _filter_findings_by_severity(findings, selected_severities)

    overdue = check_overdue_findings(findings)

    if not overdue:
        print("No overdue findings.")
        return 0

    print(json.dumps(overdue, indent=2))
    return 1


if __name__ == "__main__":
    sys.exit(main())
