#!/usr/bin/env python3
"""Check vulnerability findings against severity-based SLA windows.

By default the checker is tolerant: malformed finding records are skipped.
Use --strict to fail fast (non-zero exit) when any record is malformed.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SLA_WINDOWS = {
    "critical": timedelta(hours=24),
    "high": timedelta(days=7),
    "medium": timedelta(days=30),
    "low": timedelta(days=90),
}

OPEN_STATES = {"open", "in_progress", "reopened"}
VALID_SEVERITIES = set(SLA_WINDOWS.keys())


@dataclass
class ParseResult:
    finding_id: str
    severity: str
    state: str
    discovered_at: datetime
    raw: dict[str, Any]


def _parse_datetime(value: Any) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("discovered_at must be a non-empty ISO-8601 string")

    normalized = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid discovered_at: {value!r}") from exc

    if dt.tzinfo is None:
        # Treat naive timestamps as UTC for stable behavior.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _parse_finding(record: Any, index: int) -> ParseResult:
    if not isinstance(record, dict):
        raise ValueError(f"record at index {index} must be an object")

    missing = [k for k in ("id", "severity", "state", "discovered_at") if k not in record]
    if missing:
        raise ValueError(f"record at index {index} missing required fields: {', '.join(missing)}")

    finding_id = str(record["id"]).strip()
    if not finding_id:
        raise ValueError(f"record at index {index} has empty id")

    severity = str(record["severity"]).strip().lower()
    if severity not in VALID_SEVERITIES:
        raise ValueError(
            f"record {finding_id!r} has invalid severity {record['severity']!r}; "
            f"expected one of {sorted(VALID_SEVERITIES)}"
        )

    state = str(record["state"]).strip().lower()
    # "bad severity/state/date" requirement: validate state against known open/closed states.
    valid_states = OPEN_STATES | {"resolved", "closed", "accepted_risk", "false_positive"}
    if state not in valid_states:
        raise ValueError(f"record {finding_id!r} has invalid state {record['state']!r}")

    discovered_at = _parse_datetime(record["discovered_at"])

    return ParseResult(
        finding_id=finding_id,
        severity=severity,
        state=state,
        discovered_at=discovered_at,
        raw=record,
    )


def _load_findings(path: Path) -> list[Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"]
    raise ValueError("input must be a JSON array or object with a 'findings' array")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check finding SLA compliance")
    parser.add_argument("--findings", required=True, help="Path to findings JSON")
    parser.add_argument("--summary-only", action="store_true", help="Print only summary output")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail (non-zero) if any finding record is malformed",
    )
    args = parser.parse_args()

    now = datetime.now(timezone.utc)

    try:
        records = _load_findings(Path(args.findings))
    except Exception as exc:
        print(f"ERROR: failed to read findings: {exc}", file=sys.stderr)
        return 2

    overdue = 0
    evaluated = 0
    skipped_invalid = 0

    for idx, record in enumerate(records):
        try:
            finding = _parse_finding(record, idx)
        except Exception as exc:
            skipped_invalid += 1
            print(f"WARN: skipped invalid finding at index {idx}: {exc}", file=sys.stderr)
            continue

        if finding.state not in OPEN_STATES:
            continue

        evaluated += 1
        deadline = finding.discovered_at + SLA_WINDOWS[finding.severity]
        is_overdue = now > deadline
        if is_overdue:
            overdue += 1

        if not args.summary_only:
            status = "OVERDUE" if is_overdue else "OK"
            print(
                f"{status}\t{finding.finding_id}\tseverity={finding.severity}\t"
                f"state={finding.state}\tdeadline={deadline.isoformat()}"
            )

    print(
        f"summary: total={len(records)} evaluated_open={evaluated} overdue={overdue} skipped_invalid={skipped_invalid}"
    )

    if args.strict and skipped_invalid > 0:
        print(
            f"ERROR: strict mode enabled and {skipped_invalid} malformed finding record(s) were encountered",
            file=sys.stderr,
        )
        return 3

    return 1 if overdue > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
