#!/usr/bin/env python3
"""Check vulnerability SLA status from findings JSON.

Supports pretty/json/csv output formats. By default results are written to stdout,
but may be redirected to a file via --output.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SLA_HOURS = {
    "critical": 24,
    "high": 24 * 7,
    "medium": 24 * 30,
    "low": 24 * 90,
}


def _parse_dt(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _is_open(state: str) -> bool:
    return state.lower() not in {"resolved", "closed", "accepted"}


def evaluate(findings: list[dict[str, Any]], now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    overdue = []
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings:
        sev = str(f.get("severity", "")).lower()
        if sev not in SLA_HOURS:
            continue
        if not _is_open(str(f.get("status", "open"))):
            continue

        created_raw = f.get("created_at") or f.get("discovered_at")
        if not created_raw:
            continue

        try:
            created = _parse_dt(str(created_raw))
        except Exception:
            continue

        age_hours = (now - created).total_seconds() / 3600.0
        sla_hours = SLA_HOURS[sev]
        if age_hours > sla_hours:
            by_sev[sev] += 1
            overdue.append(
                {
                    "id": f.get("id", ""),
                    "title": f.get("title", ""),
                    "severity": sev,
                    "status": f.get("status", "open"),
                    "age_hours": round(age_hours, 2),
                    "sla_hours": sla_hours,
                    "hours_overdue": round(age_hours - sla_hours, 2),
                }
            )

    return {
        "generated_at": now.isoformat(),
        "total_findings": len(findings),
        "overdue_total": len(overdue),
        "overdue_by_severity": by_sev,
        "overdue": overdue,
    }


def format_pretty(result: dict[str, Any], summary_only: bool = False) -> str:
    lines = []
    lines.append("SLA Check")
    lines.append(f"Generated: {result['generated_at']}")
    lines.append(f"Total findings: {result['total_findings']}")
    lines.append(f"Overdue total: {result['overdue_total']}")
    lines.append(
        "Overdue by severity: "
        f"critical={result['overdue_by_severity']['critical']}, "
        f"high={result['overdue_by_severity']['high']}, "
        f"medium={result['overdue_by_severity']['medium']}, "
        f"low={result['overdue_by_severity']['low']}"
    )

    if not summary_only and result["overdue"]:
        lines.append("")
        lines.append("Overdue findings:")
        for item in result["overdue"]:
            lines.append(
                f"- [{item['severity'].upper()}] {item['id']} {item['title']} "
                f"(age={item['age_hours']}h, overdue={item['hours_overdue']}h)"
            )

    return "\n".join(lines) + "\n"


def format_json(result: dict[str, Any], summary_only: bool = False) -> str:
    payload = dict(result)
    if summary_only:
        payload.pop("overdue", None)
    return json.dumps(payload, indent=2) + "\n"


def format_csv(result: dict[str, Any], summary_only: bool = False) -> str:
    from io import StringIO

    buf = StringIO()
    writer = csv.writer(buf)

    writer.writerow(["metric", "value"])
    writer.writerow(["generated_at", result["generated_at"]])
    writer.writerow(["total_findings", result["total_findings"]])
    writer.writerow(["overdue_total", result["overdue_total"]])
    for sev, count in result["overdue_by_severity"].items():
        writer.writerow([f"overdue_{sev}", count])

    if not summary_only:
        writer.writerow([])
        writer.writerow(
            [
                "id",
                "title",
                "severity",
                "status",
                "age_hours",
                "sla_hours",
                "hours_overdue",
            ]
        )
        for item in result["overdue"]:
            writer.writerow(
                [
                    item["id"],
                    item["title"],
                    item["severity"],
                    item["status"],
                    item["age_hours"],
                    item["sla_hours"],
                    item["hours_overdue"],
                ]
            )

    return buf.getvalue()


def render(result: dict[str, Any], fmt: str, summary_only: bool) -> str:
    if fmt == "json":
        return format_json(result, summary_only=summary_only)
    if fmt == "csv":
        return format_csv(result, summary_only=summary_only)
    return format_pretty(result, summary_only=summary_only)


def write_output(content: str, output_path: str | None) -> int:
    if not output_path:
        sys.stdout.write(content)
        return 0

    path = Path(output_path)
    try:
        if path.parent and not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return 0
    except Exception as exc:
        sys.stderr.write(f"Failed to write output file '{output_path}': {exc}\n")
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(description="Check overdue findings by SLA")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument(
        "--format",
        choices=["pretty", "json", "csv"],
        default="pretty",
        help="Output format (default: pretty)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Suppress per-finding details and print aggregate summary only",
    )
    parser.add_argument(
        "--output",
        help="Optional output file path. When omitted, writes to stdout.",
    )

    args = parser.parse_args()

    findings_path = Path(args.findings)
    if not findings_path.exists():
        sys.stderr.write(f"Findings file not found: {args.findings}\n")
        return 1

    try:
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
    except Exception as exc:
        sys.stderr.write(f"Failed to parse findings file: {exc}\n")
        return 1

    if not isinstance(findings, list):
        sys.stderr.write("Findings file must contain a JSON array\n")
        return 1

    result = evaluate(findings)
    content = render(result, args.format, args.summary_only)
    return write_output(content, args.output)


if __name__ == "__main__":
    raise SystemExit(main())
