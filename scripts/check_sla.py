#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vuln_management.sla import evaluate_sla


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check vulnerability SLA status")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument(
        "--state",
        action="append",
        dest="states",
        default=None,
        help="Lifecycle state to include (repeatable, e.g. --state open --state in_progress)",
    )
    parser.add_argument(
        "--now",
        default=None,
        help="Override current time (ISO-8601, e.g. 2025-01-01T00:00:00+00:00)",
    )
    return parser.parse_args()


def _load_findings(path: str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    else:
        findings = data
    if not isinstance(findings, list):
        raise ValueError("Findings payload must be a list or an object containing a 'findings' list")
    return findings


def _parse_now(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def main() -> int:
    args = _parse_args()
    now = _parse_now(args.now)
    findings = _load_findings(args.findings)

    if args.states:
        selected = {s.strip().lower() for s in args.states if s and s.strip()}
        findings = [f for f in findings if str(f.get("state", "")).strip().lower() in selected]

    results = evaluate_sla(findings, now=now)

    output = {
        "now": now.isoformat(),
        "total": len(results),
        "overdue": sum(1 for r in results if r.get("overdue")),
        "breached": sum(1 for r in results if r.get("breached")),
        "results": results,
    }
    print(json.dumps(output, indent=2))
    return 1 if output["overdue"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
