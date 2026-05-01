#!/usr/bin/env python3
import argparse
import csv
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


SEVERITY_SLA = {
    "critical": timedelta(hours=24),
    "high": timedelta(days=7),
    "medium": timedelta(days=30),
    "low": timedelta(days=90),
}

CSV_COLUMNS = [
    "finding_id",
    "severity",
    "state",
    "sla_due_at",
    "overdue_by",
    "status",
]


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _fmt_td(delta: timedelta) -> str:
    total = int(delta.total_seconds())
    sign = "-" if total < 0 else ""
    total = abs(total)
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    if days:
        return f"{sign}{days}d {hours:02}:{mins:02}:{secs:02}"
    return f"{sign}{hours:02}:{mins:02}:{secs:02}"


def _load_findings(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"]
    raise ValueError("Unsupported findings format; expected list or {\"findings\": [...]}.")


def evaluate_finding(f: dict[str, Any], now: datetime) -> dict[str, Any] | None:
    state = str(f.get("state", "")).lower()
    if state in {"resolved", "closed", "accepted", "risk_accepted", "false_positive"}:
        return None

    severity = str(f.get("severity", "")).lower()
    if severity not in SEVERITY_SLA:
        return None

    opened_at = _parse_dt(f.get("opened_at") or f.get("created_at") or f.get("discovered_at"))
    if not opened_at:
        return None

    due = opened_at + SEVERITY_SLA[severity]
    overdue = now - due
    status = "overdue" if overdue.total_seconds() > 0 else "within_sla"

    fid = f.get("finding_id") or f.get("id") or "unknown"

    return {
        "finding_id": str(fid),
        "severity": severity,
        "state": state or "unknown",
        "sla_due_at": due.isoformat().replace("+00:00", "Z"),
        "overdue_by": _fmt_td(overdue) if status == "overdue" else "00:00:00",
        "status": status,
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in CSV_COLUMNS})


def main() -> int:
    parser = argparse.ArgumentParser(description="Check vulnerability SLA status")
    parser.add_argument("--findings", required=True, help="Path to findings JSON")
    parser.add_argument("--summary-only", action="store_true", help="Show summary only")
    parser.add_argument("--csv", help="Write filtered SLA results to CSV path")
    args = parser.parse_args()

    findings = _load_findings(Path(args.findings))
    now = datetime.now(timezone.utc)

    rows: list[dict[str, Any]] = []
    for f in findings:
        row = evaluate_finding(f, now)
        if row is not None:
            rows.append(row)

    overdue = [r for r in rows if r["status"] == "overdue"]

    if not args.summary_only:
        for r in rows:
            print(
                f"{r['finding_id']} severity={r['severity']} state={r['state']} "
                f"due={r['sla_due_at']} status={r['status']} overdue_by={r['overdue_by']}"
            )

    print(f"total_open={len(rows)} overdue={len(overdue)} within_sla={len(rows) - len(overdue)}")

    if args.csv:
        write_csv(Path(args.csv), rows)

    return 1 if overdue else 0


if __name__ == "__main__":
    raise SystemExit(main())
