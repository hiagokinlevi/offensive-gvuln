#!/usr/bin/env python3
"""Check vulnerability SLA status and print overdue findings."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SLA_DAYS = {
    "critical": 1,
    "high": 7,
    "medium": 30,
    "low": 90,
}


@dataclass
class Finding:
    finding_id: str
    title: str
    severity: str
    discovered_at: datetime
    state: str


def _parse_dt(value: str) -> datetime:
    # Supports both Z and explicit offsets
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def _load_findings(path: Path) -> list[Finding]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    findings = raw.get("findings", raw if isinstance(raw, list) else [])
    out: list[Finding] = []
    for item in findings:
        out.append(
            Finding(
                finding_id=item.get("id", item.get("finding_id", "unknown")),
                title=item.get("title", ""),
                severity=str(item.get("severity", "")).lower(),
                discovered_at=_parse_dt(item["discovered_at"]),
                state=str(item.get("state", "open")).lower(),
            )
        )
    return out


def _iter_overdue(findings: Iterable[Finding], now: datetime) -> Iterable[tuple[Finding, int]]:
    for f in findings:
        if f.state in {"resolved", "closed", "accepted_risk", "risk_accepted", "false_positive"}:
            continue
        if f.severity not in SLA_DAYS:
            continue
        age_days = (now - f.discovered_at).total_seconds() / 86400
        overdue_days = int(age_days - SLA_DAYS[f.severity])
        if overdue_days >= 0:
            yield f, overdue_days


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check findings against SLA deadlines")
    parser.add_argument("--findings", required=True, help="Path to findings JSON")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only print aggregate overdue count",
    )
    parser.add_argument(
        "--fail-on-overdue",
        type=int,
        default=1,
        help=(
            "Exit non-zero when overdue findings count is greater than or equal to this threshold "
            "(default: 1). Use 0 to always fail, or a higher value for tolerance windows."
        ),
    )
    args = parser.parse_args(argv)

    findings = _load_findings(Path(args.findings))
    now = datetime.now(timezone.utc)
    overdue = list(_iter_overdue(findings, now))

    if not args.summary_only:
        for f, days in overdue:
            print(f"[OVERDUE] {f.finding_id} ({f.severity}) - {f.title} :: overdue_by_days={days}")

    print(f"overdue_count={len(overdue)}")

    return 1 if len(overdue) >= args.fail_on_overdue else 0


if __name__ == "__main__":
    raise SystemExit(main())
