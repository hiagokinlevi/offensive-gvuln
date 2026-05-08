#!/usr/bin/env python3
"""Check vulnerability findings for SLA overdue status."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vuln_management.sla import is_overdue


def parse_as_of(value: str) -> datetime:
    """Parse an ISO8601 UTC timestamp for deterministic SLA evaluation.

    Accepts values like:
      - 2026-01-02T03:04:05Z
      - 2026-01-02T03:04:05+00:00
    """

    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "--as-of must be a valid ISO8601 UTC timestamp (e.g. 2026-01-02T03:04:05Z)"
        ) from exc

    if dt.tzinfo is None:
        raise argparse.ArgumentTypeError(
            "--as-of must include timezone and be UTC (e.g. trailing 'Z')"
        )

    if dt.utcoffset() != timezone.utc.utcoffset(dt):
        raise argparse.ArgumentTypeError("--as-of must be in UTC")

    return dt.astimezone(timezone.utc)


def _load_findings(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        return payload["findings"]
    raise ValueError("Expected JSON array or object with 'findings' array")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check findings for SLA overdue status")
    parser.add_argument("--findings", required=True, help="Path to findings JSON")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Only print aggregate overdue summary",
    )
    parser.add_argument(
        "--as-of",
        type=parse_as_of,
        help="Evaluate SLA status as of this UTC ISO8601 timestamp (e.g. 2026-01-02T03:04:05Z)",
    )

    args = parser.parse_args()
    as_of = args.as_of

    findings = _load_findings(Path(args.findings))

    overdue_count = 0
    for finding in findings:
        overdue = is_overdue(finding, as_of=as_of) if as_of else is_overdue(finding)
        if overdue:
            overdue_count += 1
            if not args.summary_only:
                fid = finding.get("id", "<unknown>")
                sev = finding.get("severity", "<unknown>")
                print(f"OVERDUE\t{fid}\t{sev}")

    total = len(findings)
    print(f"summary: overdue={overdue_count} total={total}")
    return 1 if overdue_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
