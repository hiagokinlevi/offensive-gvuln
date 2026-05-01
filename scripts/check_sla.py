#!/usr/bin/env python3
"""Check vulnerability remediation SLA compliance from findings JSON.

Default behavior prints per-finding overdue details and an aggregate summary.
Use --summary-only to suppress per-finding lines and emit concise aggregate
metrics suitable for cron/CI logs.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SLA_DAYS_BY_SEVERITY = {
    "critical": 1,
    "high": 7,
    "medium": 30,
    "low": 90,
}


def _parse_iso8601(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _load_findings(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"]
    raise ValueError("Unsupported findings format; expected list or {'findings': [...]}.")


def _get_scope_value(finding: dict[str, Any]) -> str | None:
    for key in ("scope", "asset", "target", "service", "host"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Check remediation SLA compliance.")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument("--scope", help="Optional scope substring filter")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Suppress per-finding output and print only aggregate SLA metrics",
    )
    args = parser.parse_args()

    findings_path = Path(args.findings)
    findings = _load_findings(findings_path)

    now = datetime.now(timezone.utc)
    overdue = []
    overdue_by_severity: Counter[str] = Counter()

    scanned = 0
    scanned_in_scope = 0
    overdue_in_scope = 0

    for f in findings:
        severity = str(f.get("severity", "")).lower().strip()
        if severity not in SLA_DAYS_BY_SEVERITY:
            continue

        created_raw = f.get("created_at") or f.get("discovered_at")
        if not isinstance(created_raw, str):
            continue

        scope_value = _get_scope_value(f)
        in_scope = True
        if args.scope:
            in_scope = bool(scope_value and args.scope.lower() in scope_value.lower())

        scanned += 1
        if in_scope:
            scanned_in_scope += 1

        created_at = _parse_iso8601(created_raw)
        age_days = (now - created_at).total_seconds() / 86400
        if age_days > SLA_DAYS_BY_SEVERITY[severity]:
            overdue.append(f)
            overdue_by_severity[severity] += 1
            if in_scope:
                overdue_in_scope += 1
            if not args.summary_only and in_scope:
                fid = f.get("id", "unknown")
                title = f.get("title", "")
                print(f"OVERDUE id={fid} severity={severity} age_days={age_days:.1f} title={title}")

    total_overdue = sum(overdue_by_severity.values())

    if args.summary_only:
        print(f"SLA_SUMMARY scanned={scanned} overdue={total_overdue}")
        sev_parts = [
            f"critical={overdue_by_severity.get('critical', 0)}",
            f"high={overdue_by_severity.get('high', 0)}",
            f"medium={overdue_by_severity.get('medium', 0)}",
            f"low={overdue_by_severity.get('low', 0)}",
        ]
        print("SLA_OVERDUE_BY_SEVERITY " + " ".join(sev_parts))
        if args.scope:
            print(
                f"SLA_SCOPE scope={args.scope} scanned={scanned_in_scope} overdue={overdue_in_scope}"
            )
    else:
        print(f"Scanned findings: {scanned}")
        if args.scope:
            print(f"Scanned in scope ('{args.scope}'): {scanned_in_scope}")
        print(f"Overdue findings: {total_overdue}")
        print("Overdue by severity:")
        for s in ("critical", "high", "medium", "low"):
            print(f"  - {s}: {overdue_by_severity.get(s, 0)}")

    return 1 if total_overdue > 0 else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(2)
