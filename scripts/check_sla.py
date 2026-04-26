#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _sla_due_date(finding: dict[str, Any]) -> datetime | None:
    # Prefer explicit due_date if present; fallback to known SLA fields if available.
    for key in ("due_date", "sla_due_date", "sla_due_at"):
        dt = _parse_dt(finding.get(key))
        if dt is not None:
            return dt
    return None


def _updated_at(finding: dict[str, Any]) -> datetime | None:
    for key in ("updated_at", "last_updated", "modified_at"):
        dt = _parse_dt(finding.get(key))
        if dt is not None:
            return dt
    return None


def _sort_key(sort_by: str):
    if sort_by == "severity":
        return lambda f: (SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0), str(f.get("id", "")))
    if sort_by == "due_date":
        return lambda f: ((_sla_due_date(f) or datetime.max.replace(tzinfo=timezone.utc)), str(f.get("id", "")))
    if sort_by == "updated_at":
        return lambda f: ((_updated_at(f) or datetime.min.replace(tzinfo=timezone.utc)), str(f.get("id", "")))
    # id
    return lambda f: str(f.get("id", ""))


def _render_stdout(findings: list[dict[str, Any]]) -> None:
    if not findings:
        print("No overdue findings.")
        return

    print("Overdue findings:")
    for f in findings:
        fid = f.get("id", "<unknown>")
        sev = f.get("severity", "unknown")
        due = f.get("due_date") or f.get("sla_due_date") or f.get("sla_due_at") or "n/a"
        updated = f.get("updated_at") or f.get("last_updated") or f.get("modified_at") or "n/a"
        print(f"- {fid} | severity={sev} | due_date={due} | updated_at={updated}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Check vulnerability SLA status")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument("--json", action="store_true", help="Emit JSON output")
    parser.add_argument(
        "--sort-by",
        choices=["severity", "due_date", "updated_at", "id"],
        default="id",
        help="Sort output deterministically by selected field",
    )
    parser.add_argument(
        "--descending",
        action="store_true",
        help="Sort in descending order",
    )
    args = parser.parse_args()

    findings_path = Path(args.findings)
    data = json.loads(findings_path.read_text(encoding="utf-8"))

    if isinstance(data, dict) and "findings" in data:
        findings = data.get("findings", [])
    elif isinstance(data, list):
        findings = data
    else:
        raise SystemExit("Unsupported findings JSON structure")

    overdue = [f for f in findings if bool(f.get("is_overdue", False))]
    overdue = sorted(overdue, key=_sort_key(args.sort_by), reverse=args.descending)

    if args.json:
        print(json.dumps({"overdue": overdue}, indent=2))
    else:
        _render_stdout(overdue)

    return 1 if overdue else 0


if __name__ == "__main__":
    raise SystemExit(main())
