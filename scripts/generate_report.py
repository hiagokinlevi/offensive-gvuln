#!/usr/bin/env python3
"""Generate vulnerability reports from findings JSON.

Supports JSON, CSV, Markdown, and NDJSON output formats.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterable, Sequence

from vuln_management.models import FindingSeverity


_ALLOWED_SEVERITIES = {s.value.casefold(): s.value for s in FindingSeverity}


def _parse_severity_filter(raw: str | None) -> set[str] | None:
    """Parse and validate a comma-separated severity filter list.

    Returns a normalized set of canonical severity values (e.g. {"Critical", "High"})
    or None when no filter is supplied.
    """
    if raw is None:
        return None

    values = [v.strip() for v in raw.split(",") if v.strip()]
    if not values:
        raise ValueError("--severity requires at least one severity value")

    normalized: set[str] = set()
    invalid: list[str] = []
    for value in values:
        canonical = _ALLOWED_SEVERITIES.get(value.casefold())
        if canonical is None:
            invalid.append(value)
        else:
            normalized.add(canonical)

    if invalid:
        allowed = ", ".join(sorted(_ALLOWED_SEVERITIES.values()))
        bad = ", ".join(invalid)
        raise ValueError(f"Invalid severity value(s): {bad}. Allowed: {allowed}")

    return normalized


def load_findings(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("Findings input must be a JSON array")
    return data


def _filter_findings_by_severity(findings: Sequence[dict], severities: set[str] | None) -> list[dict]:
    if severities is None:
        return list(findings)
    return [f for f in findings if str(f.get("severity", "")).strip() in severities]


def render_json(findings: Sequence[dict]) -> str:
    return json.dumps(list(findings), indent=2)


def render_ndjson(findings: Sequence[dict]) -> str:
    return "\n".join(json.dumps(f) for f in findings)


def render_csv(findings: Sequence[dict]) -> str:
    rows = list(findings)
    fieldnames: list[str] = []
    for row in rows:
        for key in row.keys():
            if key not in fieldnames:
                fieldnames.append(key)

    from io import StringIO

    out = StringIO()
    writer = csv.DictWriter(out, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue().rstrip("\n")


def render_markdown(findings: Sequence[dict]) -> str:
    rows = list(findings)
    headers = ["id", "title", "severity", "state", "owner", "sla_due_at"]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(["---"] * len(headers)) + " |",
    ]
    for finding in rows:
        values = [str(finding.get(h, "")) for h in headers]
        lines.append("| " + " | ".join(values) + " |")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate vulnerability findings report")
    parser.add_argument("--findings", required=True, help="Path to findings JSON array")
    parser.add_argument(
        "--format",
        required=True,
        choices=["json", "csv", "markdown", "ndjson"],
        help="Output format",
    )
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument(
        "--severity",
        help="Comma-separated severities to include (case-insensitive), e.g. Critical,High",
    )
    return parser


def generate_report(findings: Sequence[dict], output_format: str) -> str:
    if output_format == "json":
        return render_json(findings)
    if output_format == "csv":
        return render_csv(findings)
    if output_format == "markdown":
        return render_markdown(findings)
    if output_format == "ndjson":
        return render_ndjson(findings)
    raise ValueError(f"Unsupported format: {output_format}")


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        severity_filter = _parse_severity_filter(args.severity)
    except ValueError as exc:
        parser.error(str(exc))

    findings = load_findings(Path(args.findings))
    filtered_findings = _filter_findings_by_severity(findings, severity_filter)

    report = generate_report(filtered_findings, args.format)
    Path(args.output).write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
