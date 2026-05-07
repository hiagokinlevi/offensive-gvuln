#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from typing import Any

SEVERITY_SLA = {
    "critical": timedelta(hours=24),
    "high": timedelta(days=7),
    "medium": timedelta(days=30),
    "low": timedelta(days=90),
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _due_at(finding: dict[str, Any]) -> datetime | None:
    sev = str(finding.get("severity", "")).lower()
    created = _parse_dt(finding.get("created_at"))
    if created is None or sev not in SEVERITY_SLA:
        return None
    return created + SEVERITY_SLA[sev]


def _sort_key(sort_by: str, finding: dict[str, Any]):
    fid = str(finding.get("id", ""))
    if sort_by == "severity":
        sev_rank = SEVERITY_ORDER.get(str(finding.get("severity", "")).lower(), 99)
        due = _due_at(finding) or datetime.max.replace(tzinfo=timezone.utc)
        created = _parse_dt(finding.get("created_at")) or datetime.max.replace(tzinfo=timezone.utc)
        return (sev_rank, due, created, fid)
    if sort_by == "created_at":
        created = _parse_dt(finding.get("created_at")) or datetime.max.replace(tzinfo=timezone.utc)
        due = _due_at(finding) or datetime.max.replace(tzinfo=timezone.utc)
        sev_rank = SEVERITY_ORDER.get(str(finding.get("severity", "")).lower(), 99)
        return (created, due, sev_rank, fid)
    # default due_at
    due = _due_at(finding) or datetime.max.replace(tzinfo=timezone.utc)
    sev_rank = SEVERITY_ORDER.get(str(finding.get("severity", "")).lower(), 99)
    created = _parse_dt(finding.get("created_at")) or datetime.max.replace(tzinfo=timezone.utc)
    return (due, sev_rank, created, fid)


def _load_findings(path: str) -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [x for x in data["findings"] if isinstance(x, dict)]
    return []


def main() -> int:
    parser = argparse.ArgumentParser(description="Check vulnerability remediation SLA status")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument("--summary-only", action="store_true", help="Only print summary counts")
    parser.add_argument(
        "--sort-by",
        choices=["due_at", "severity", "created_at"],
        default="due_at",
        help="Deterministic ordering for filtered findings output (default: due_at)",
    )
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    findings = _load_findings(args.findings)

    enriched: list[dict[str, Any]] = []
    for f in findings:
        status = str(f.get("status", "")).lower()
        if status in {"closed", "resolved", "accepted", "mitigated"}:
            continue
        due = _due_at(f)
        is_overdue = bool(due and due < now)
        row = dict(f)
        row["due_at"] = _iso(due)
        row["overdue"] = is_overdue
        enriched.append(row)

    summary = {
        "total_open": len(enriched),
        "overdue": sum(1 for x in enriched if x.get("overdue")),
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
    }
    for x in enriched:
        sev = str(x.get("severity", "")).lower()
        if sev in summary["by_severity"]:
            summary["by_severity"][sev] += 1

    ordered = sorted(enriched, key=lambda f: _sort_key(args.sort_by, f))

    if args.json:
        payload = {"summary": summary, "findings": ordered}
        print(json.dumps(payload, indent=2))
        return 0

    if not args.summary_only:
        for x in ordered:
            print(
                f"[{str(x.get('severity', 'unknown')).upper()}] "
                f"{x.get('id', '<no-id>')} "
                f"status={x.get('status', 'unknown')} "
                f"created_at={x.get('created_at')} due_at={x.get('due_at')} "
                f"overdue={x.get('overdue')}"
            )

    print("\nSummary:")
    print(f"  total_open: {summary['total_open']}")
    print(f"  overdue: {summary['overdue']}")
    print("  by_severity:")
    for sev in ("critical", "high", "medium", "low"):
        print(f"    {sev}: {summary['by_severity'][sev]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
