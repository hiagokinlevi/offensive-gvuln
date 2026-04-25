#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterable

from pydantic import ValidationError

from vuln_management.models import Finding, Severity


def load_findings(path: Path) -> list[Finding]:
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)

    if not isinstance(raw, list):
        raise ValueError("Findings file must contain a JSON array of findings")

    findings: list[Finding] = []
    for item in raw:
        findings.append(Finding.model_validate(item))
    return findings


def parse_severities(severity_arg: str | None) -> set[Severity] | None:
    if not severity_arg:
        return None

    parsed: set[Severity] = set()
    invalid: list[str] = []

    for token in (s.strip() for s in severity_arg.split(",")):
        if not token:
            continue
        try:
            parsed.add(Severity(token.lower()))
        except ValueError:
            invalid.append(token)

    if invalid:
        valid_values = ", ".join(s.value for s in Severity)
        raise ValueError(
            f"Invalid --severity value(s): {', '.join(invalid)}. "
            f"Valid values: {valid_values}"
        )

    if not parsed:
        raise ValueError("--severity was provided but no valid severity values were found")

    return parsed


def filter_findings_by_severity(
    findings: Iterable[Finding],
    severities: set[Severity] | None,
) -> list[Finding]:
    if not severities:
        return list(findings)
    return [f for f in findings if f.severity in severities]


def render_json(findings: list[Finding]) -> str:
    return json.dumps([f.model_dump(mode="json") for f in findings], indent=2)


def render_csv(findings: list[Finding]) -> str:
    if not findings:
        return ""

    fields = list(findings[0].model_dump(mode="json").keys())
    output_lines: list[str] = []

    from io import StringIO

    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=fields)
    writer.writeheader()
    for finding in findings:
        writer.writerow(finding.model_dump(mode="json"))

    return buf.getvalue()


def render_markdown(findings: list[Finding]) -> str:
    lines = ["# Vulnerability Report", "", f"Total Findings: **{len(findings)}**", ""]

    if not findings:
        lines.append("No findings to report.")
        return "\n".join(lines)

    lines.extend(
        [
            "| ID | Title | Severity | State |",
            "|---|---|---|---|",
        ]
    )
    for f in findings:
        lines.append(f"| {f.id} | {f.title} | {f.severity.value} | {f.state.value} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate vulnerability findings reports in JSON, CSV, or Markdown format. "
            "Example severity filtering: --severity critical,high"
        )
    )
    parser.add_argument("--findings", required=True, type=Path, help="Path to findings JSON file")
    parser.add_argument(
        "--format",
        required=True,
        choices=["json", "csv", "markdown"],
        help="Output format",
    )
    parser.add_argument("--output", required=True, type=Path, help="Output file path")
    parser.add_argument(
        "--severity",
        help="Comma-separated severity filter (e.g., critical,high)",
    )

    args = parser.parse_args()

    try:
        findings = load_findings(args.findings)
        severities = parse_severities(args.severity)
        findings = filter_findings_by_severity(findings, severities)
    except (ValueError, ValidationError) as exc:
        parser.error(str(exc))

    if args.format == "json":
        rendered = render_json(findings)
    elif args.format == "csv":
        rendered = render_csv(findings)
    else:
        rendered = render_markdown(findings)

    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
