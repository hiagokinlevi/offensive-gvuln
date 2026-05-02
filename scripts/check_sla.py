#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check vulnerability remediation SLA status")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Show only aggregate counts, suppress per-finding lines",
    )
    parser.add_argument(
        "--fail-on-overdue",
        action="store_true",
        help="Exit non-zero when overdue findings are present",
    )
    parser.add_argument(
        "--exit-code-only",
        action="store_true",
        help=(
            "Suppress normal output and rely on exit code only: "
            "0=no overdue findings, 2=overdue findings, 1=runtime/validation error"
        ),
    )
    return parser.parse_args()


def _parse_dt(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def main() -> int:
    args = _parse_args()

    try:
        data = json.loads(Path(args.findings).read_text(encoding="utf-8"))
        findings = data if isinstance(data, list) else data.get("findings", [])
        now = datetime.now(timezone.utc)

        overdue = []
        for f in findings:
            status = str(f.get("status", "")).lower()
            if status in {"closed", "resolved", "accepted", "mitigated"}:
                continue
            due_raw = f.get("sla_due_at") or f.get("due_date")
            if not due_raw:
                continue
            due = _parse_dt(str(due_raw))
            if due < now:
                overdue.append(f)

        if not args.exit_code_only:
            if not args.summary_only:
                for f in overdue:
                    fid = f.get("id", "<unknown>")
                    sev = f.get("severity", "unknown")
                    due = f.get("sla_due_at") or f.get("due_date") or "n/a"
                    print(f"OVERDUE: id={fid} severity={sev} due={due}")
            print(f"overdue={len(overdue)} total={len(findings)}")

        if overdue:
            return 2 if (args.fail_on_overdue or args.exit_code_only) else 0
        return 0
    except Exception as exc:
        if not args.exit_code_only:
            print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
