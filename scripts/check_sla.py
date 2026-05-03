#!/usr/bin/env python3
"""Check vulnerability findings against severity-based SLA windows."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

SLA_HOURS = {
    "Critical": 24,
    "High": 24 * 7,
    "Medium": 24 * 30,
    "Low": 24 * 90,
}
VALID_SEVERITIES = tuple(SLA_HOURS.keys())


def _parse_datetime(value: str) -> datetime:
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _normalize_severities(raw_values: list[str] | None) -> set[str] | None:
    if not raw_values:
        return None

    tokens: list[str] = []
    for entry in raw_values:
        tokens.extend(part.strip() for part in entry.split(","))

    selected: set[str] = set()
    invalid: list[str] = []

    canonical = {s.lower(): s for s in VALID_SEVERITIES}
    for token in tokens:
        if not token:
            continue
        mapped = canonical.get(token.lower())
        if mapped is None:
            invalid.append(token)
        else:
            selected.add(mapped)

    if invalid:
        allowed = ", ".join(VALID_SEVERITIES)
        raise ValueError(
            f"Invalid severity value(s): {', '.join(invalid)}. Allowed values: {allowed}."
        )

    return selected if selected else None


def _iter_open_findings(findings: Iterable[dict]) -> Iterable[dict]:
    for finding in findings:
        status = str(finding.get("status", "")).lower()
        if status in {"closed", "resolved", "remediated", "accepted"}:
            continue
        yield finding


def _load_findings(path: Path) -> list[dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        data = data["findings"]
    if not isinstance(data, list):
        raise ValueError("Findings input must be a JSON array or an object with a 'findings' array.")
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate finding SLA breaches by severity.")
    parser.add_argument("--findings", required=True, help="Path to findings JSON")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Print only aggregate breach counts",
    )
    parser.add_argument(
        "--severity",
        action="append",
        help="Limit evaluation to severities (repeatable or comma-separated): Critical,High,Medium,Low",
    )
    args = parser.parse_args()

    try:
        findings = _load_findings(Path(args.findings))
        selected_severities = _normalize_severities(args.severity)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    now = datetime.now(timezone.utc)

    open_findings = list(_iter_open_findings(findings))
    if selected_severities is not None:
        open_findings = [
            f for f in open_findings if str(f.get("severity", "")).strip() in selected_severities
        ]

    overdue: list[tuple[dict, float]] = []
    counts = Counter()

    for finding in open_findings:
        severity = str(finding.get("severity", "")).strip()
        sla_hours = SLA_HOURS.get(severity)
        if sla_hours is None:
            continue

        discovered_at = finding.get("discovered_at") or finding.get("created_at")
        if not discovered_at:
            continue

        try:
            discovered_dt = _parse_datetime(str(discovered_at))
        except Exception:
            continue

        age_hours = (now - discovered_dt).total_seconds() / 3600
        if age_hours > sla_hours:
            overdue.append((finding, age_hours - sla_hours))
            counts[severity] += 1

    if not args.summary_only:
        for finding, overdue_hours in overdue:
            fid = finding.get("id", "<no-id>")
            severity = finding.get("severity", "Unknown")
            title = finding.get("title", "")
            print(f"{fid} | {severity} | overdue {overdue_hours:.1f}h | {title}")

    total_overdue = sum(counts.values())
    print("SLA Summary")
    for sev in VALID_SEVERITIES:
        print(f"- {sev}: {counts.get(sev, 0)} overdue")
    print(f"- Total: {total_overdue} overdue")

    return 1 if total_overdue > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
