#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

from vuln_management.models import Finding
from vuln_management.sla import is_finding_overdue


def _load_findings(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Findings input must be a JSON array")
    return [Finding.model_validate(item) for item in data]


def _to_json(findings: list[Finding]) -> str:
    return json.dumps([f.model_dump(mode="json") for f in findings], indent=2)


def _to_jsonl(findings: list[Finding]) -> str:
    return "\n".join(json.dumps(f.model_dump(mode="json")) for f in findings)


def _to_csv(findings: list[Finding]) -> str:
    if not findings:
        return ""

    rows = [f.model_dump(mode="json") for f in findings]
    headers = sorted({k for r in rows for k in r.keys()})

    from io import StringIO

    out = StringIO()
    writer = csv.DictWriter(out, fieldnames=headers)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return out.getvalue()


def _to_markdown(findings: list[Finding]) -> str:
    lines = ["# Vulnerability Findings", ""]
    if not findings:
        lines.append("_No findings to report._")
        return "\n".join(lines)

    for f in findings:
        lines.extend(
            [
                f"## {f.id}: {f.title}",
                f"- Severity: {f.severity}",
                f"- Status: {f.status}",
                f"- Owner: {f.owner or 'unassigned'}",
                "",
            ]
        )
    return "\n".join(lines)


def _render(findings: list[Finding], output_format: str) -> str:
    if output_format == "json":
        return _to_json(findings)
    if output_format == "jsonl":
        return _to_jsonl(findings)
    if output_format == "csv":
        return _to_csv(findings)
    if output_format == "markdown":
        return _to_markdown(findings)
    raise ValueError(f"Unsupported format: {output_format}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate vulnerability report output")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument(
        "--format",
        default="json",
        choices=["json", "csv", "markdown", "jsonl"],
        help="Output format",
    )
    parser.add_argument("--output", help="Optional output file path")
    parser.add_argument(
        "--overdue-only",
        action="store_true",
        help="Only include findings currently past SLA due date",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    findings = _load_findings(Path(args.findings))

    if args.overdue_only:
        findings = [f for f in findings if is_finding_overdue(f)]

    rendered = _render(findings, args.format)

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
