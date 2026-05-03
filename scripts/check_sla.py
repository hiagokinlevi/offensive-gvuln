#!/usr/bin/env python3
"""Check vulnerability remediation SLA status.

Supports human-readable output (pretty) and machine-readable JSON output for CI/CD.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _parse_iso8601(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _load_findings(path: Path) -> List[Dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    else:
        findings = data
    if not isinstance(findings, list):
        raise ValueError("Findings payload must be a list or an object with a 'findings' list")
    return findings


def _build_overdue_rows(findings: List[Dict[str, Any]], now: datetime) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for finding in findings:
        status = str(finding.get("status", "open")).lower()
        if status in {"resolved", "closed", "accepted", "mitigated"}:
            continue

        due_raw = finding.get("sla_due_at") or finding.get("due_date")
        if not due_raw:
            continue

        try:
            due_at = _parse_iso8601(str(due_raw))
        except Exception:
            continue

        if due_at >= now:
            continue

        severity = str(finding.get("severity", "unknown")).lower()
        row = {
            "id": finding.get("id") or finding.get("finding_id"),
            "title": finding.get("title"),
            "severity": severity,
            "status": status,
            "sla_due_at": due_at.isoformat(),
            "days_overdue": max(0, int((now - due_at).total_seconds() // 86400)),
        }
        rows.append(row)

    return rows


def _render_pretty(total: int, overdue_rows: List[Dict[str, Any]], summary_only: bool) -> int:
    overdue_count = len(overdue_rows)
    by_severity = Counter(r.get("severity", "unknown") for r in overdue_rows)

    print(f"Total findings evaluated: {total}")
    print(f"Overdue findings: {overdue_count}")
    print("Overdue by severity:")
    for sev in SEVERITY_ORDER:
        print(f"  - {sev}: {by_severity.get(sev, 0)}")
    for sev, count in sorted(by_severity.items()):
        if sev not in SEVERITY_ORDER:
            print(f"  - {sev}: {count}")

    if not summary_only and overdue_rows:
        print("\nOverdue finding rows:")
        for r in overdue_rows:
            fid = r.get("id") or "<no-id>"
            title = r.get("title") or "<no-title>"
            sev = r.get("severity") or "unknown"
            days = r.get("days_overdue", 0)
            due = r.get("sla_due_at")
            print(f"- [{sev}] {fid}: {title} | due={due} | days_overdue={days}")

    return 1 if overdue_count > 0 else 0


def _render_json(total: int, overdue_rows: List[Dict[str, Any]], summary_only: bool) -> int:
    by_severity_counter = Counter(r.get("severity", "unknown") for r in overdue_rows)
    overdue_by_severity: Dict[str, int] = {sev: by_severity_counter.get(sev, 0) for sev in SEVERITY_ORDER}
    for sev, count in sorted(by_severity_counter.items()):
        if sev not in overdue_by_severity:
            overdue_by_severity[sev] = count

    payload: Dict[str, Any] = {
        "totals": {
            "findings_evaluated": total,
            "overdue": len(overdue_rows),
        },
        "overdue_by_severity": overdue_by_severity,
    }
    if not summary_only:
        payload["findings"] = overdue_rows

    print(json.dumps(payload, separators=(",", ":"), sort_keys=False))
    return 1 if overdue_rows else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Check overdue remediation SLA findings")
    parser.add_argument("--findings", required=True, help="Path to findings JSON")
    parser.add_argument("--summary-only", action="store_true", help="Only print aggregate summary")
    parser.add_argument(
        "--format",
        choices=["pretty", "json"],
        default="pretty",
        help="Output format (default: pretty)",
    )
    args = parser.parse_args()

    findings = _load_findings(Path(args.findings))
    now = datetime.now(timezone.utc)
    overdue_rows = _build_overdue_rows(findings, now)

    if args.format == "json":
        return _render_json(len(findings), overdue_rows, args.summary_only)
    return _render_pretty(len(findings), overdue_rows, args.summary_only)


if __name__ == "__main__":
    raise SystemExit(main())
