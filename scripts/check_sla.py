#!/usr/bin/env python3
"""Check vulnerability findings against severity-based SLA deadlines."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vuln_management.models import Finding
from vuln_management.sla import is_overdue


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check findings for SLA breaches")
    parser.add_argument(
        "--findings",
        required=True,
        help="Path to findings JSON file",
    )
    parser.add_argument(
        "--output-json",
        required=False,
        help="Optional path to write machine-readable SLA summary JSON",
    )
    return parser.parse_args()


def _load_findings(path: str) -> list[Finding]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict) and "findings" in raw:
        raw = raw["findings"]
    if not isinstance(raw, list):
        raise ValueError("Findings input must be a list or an object containing a 'findings' list")
    return [Finding.model_validate(item) for item in raw]


def main() -> int:
    args = _parse_args()
    findings = _load_findings(args.findings)

    now = datetime.now(timezone.utc)
    overdue: list[dict[str, Any]] = []

    for finding in findings:
        if is_overdue(finding, now=now):
            due_date = finding.sla_due_at
            days_overdue = max(0, (now - due_date).days)
            overdue.append(
                {
                    "id": finding.id,
                    "severity": finding.severity,
                    "due_date": due_date.isoformat(),
                    "days_overdue": days_overdue,
                }
            )

    # Keep existing console output behavior
    print(f"Scanned findings: {len(findings)}")
    print(f"Overdue findings: {len(overdue)}")
    if overdue:
        for item in overdue:
            print(
                f"- {item['id']} ({item['severity']}): due {item['due_date']} "
                f"[{item['days_overdue']} day(s) overdue]"
            )

    if args.output_json:
        payload = {
            "total_findings_scanned": len(findings),
            "overdue_count": len(overdue),
            "overdue_findings": sorted(
                overdue,
                key=lambda x: (str(x["id"]), str(x["severity"]), str(x["due_date"])),
            ),
        }
        out_path = Path(args.output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    return 1 if overdue else 0


if __name__ == "__main__":
    raise SystemExit(main())
