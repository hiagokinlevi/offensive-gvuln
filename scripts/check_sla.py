#!/usr/bin/env python3
"""Check vulnerability findings for SLA overdue status.

Usage examples:
  python scripts/check_sla.py --findings findings.json
  python scripts/check_sla.py --findings findings.json --format json --summary-only
  python scripts/check_sla.py --findings findings.json --sla-tier high
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


SLA_HOURS = {
    "critical": 24,
    "high": 7 * 24,
    "medium": 30 * 24,
    "low": 90 * 24,
}


def _parse_dt(value: str) -> datetime:
    v = value.strip()
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    dt = datetime.fromisoformat(v)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _load_findings(path: Path) -> List[Dict[str, Any]]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
        return data["findings"]
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported findings JSON format; expected list or {'findings': [...]}.")


def _evaluate(findings: List[Dict[str, Any]], now: datetime) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    for f in findings:
        sev = str(f.get("severity", "")).strip().lower()
        if sev not in SLA_HOURS:
            continue
        created_raw = f.get("created_at") or f.get("created") or f.get("discovered_at")
        if not created_raw:
            continue
        try:
            created = _parse_dt(str(created_raw))
        except Exception:
            continue

        due = created.timestamp() + SLA_HOURS[sev] * 3600
        overdue = now.timestamp() > due

        results.append(
            {
                "id": f.get("id") or f.get("finding_id") or "",
                "title": f.get("title") or "",
                "severity": sev,
                "created_at": created.isoformat(),
                "due_at": datetime.fromtimestamp(due, tz=timezone.utc).isoformat(),
                "overdue": overdue,
            }
        )
    return results


def _print_table(rows: List[Dict[str, Any]]) -> None:
    if not rows:
        print("No findings matched.")
        return
    print("id\tseverity\toverdue\tdue_at\ttitle")
    for r in rows:
        print(f"{r['id']}\t{r['severity']}\t{str(r['overdue']).lower()}\t{r['due_at']}\t{r['title']}")


def _print_summary(rows: List[Dict[str, Any]]) -> None:
    total = len(rows)
    overdue = sum(1 for r in rows if r["overdue"])
    by_sev: Dict[str, int] = {k: 0 for k in SLA_HOURS}
    for r in rows:
        by_sev[r["severity"]] += 1
    print(f"total={total} overdue={overdue} critical={by_sev['critical']} high={by_sev['high']} medium={by_sev['medium']} low={by_sev['low']}")


def _emit_json(rows: List[Dict[str, Any]], summary_only: bool) -> None:
    if summary_only:
        out = {
            "total": len(rows),
            "overdue": sum(1 for r in rows if r["overdue"]),
            "by_severity": {
                "critical": sum(1 for r in rows if r["severity"] == "critical"),
                "high": sum(1 for r in rows if r["severity"] == "high"),
                "medium": sum(1 for r in rows if r["severity"] == "medium"),
                "low": sum(1 for r in rows if r["severity"] == "low"),
            },
        }
    else:
        out = rows
    print(json.dumps(out, indent=2))


def _emit_csv(rows: List[Dict[str, Any]]) -> None:
    w = csv.DictWriter(sys.stdout, fieldnames=["id", "title", "severity", "created_at", "due_at", "overdue"])
    w.writeheader()
    for r in rows:
        w.writerow(r)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check findings against severity SLA windows")
    parser.add_argument("--findings", required=True, help="Path to findings JSON")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table")
    parser.add_argument("--summary-only", action="store_true", help="Emit aggregate summary only")
    parser.add_argument(
        "--sla-tier",
        choices=["critical", "high", "medium", "low"],
        help="Restrict evaluation to a single SLA/severity tier",
    )
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    findings = _load_findings(Path(args.findings))
    if args.sla_tier:
        findings = [f for f in findings if str(f.get("severity", "")).strip().lower() == args.sla_tier]

    rows = _evaluate(findings, now=datetime.now(timezone.utc))

    if args.format == "json":
        _emit_json(rows, summary_only=args.summary_only)
        return 0

    if args.format == "csv":
        _emit_csv(rows)
        return 0

    if args.summary_only:
        _print_summary(rows)
    else:
        _print_table(rows)
        _print_summary(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
