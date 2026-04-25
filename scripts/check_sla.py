from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check overdue findings against SLA deadlines")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument(
        "--fail-on-overdue",
        action="store_true",
        help="Exit with code 2 when one or more overdue findings are detected",
    )
    return parser.parse_args()


def _load_findings(path: str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    else:
        findings = data
    if not isinstance(findings, list):
        raise ValueError("Findings payload must be a list or an object with a 'findings' list")
    return findings


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _is_overdue(finding: dict[str, Any], now: datetime) -> bool:
    status = str(finding.get("status", "")).lower()
    if status in {"closed", "resolved", "accepted", "false_positive"}:
        return False

    due = _parse_dt(finding.get("sla_due_at") or finding.get("due_at") or finding.get("sla_due"))
    if due is None:
        return False
    return due < now


def main() -> int:
    args = _parse_args()
    findings = _load_findings(args.findings)

    now = datetime.now(timezone.utc)
    overdue = [f for f in findings if _is_overdue(f, now)]

    # Preserve existing human-readable behavior style: print overdue findings summary.
    print(f"Total findings: {len(findings)}")
    print(f"Overdue findings: {len(overdue)}")
    for f in overdue:
        fid = f.get("id", "<unknown>")
        title = f.get("title", "")
        due = f.get("sla_due_at") or f.get("due_at") or f.get("sla_due") or "<no-due>"
        print(f"- {fid} | due={due} | {title}")

    if args.fail_on_overdue and overdue:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
