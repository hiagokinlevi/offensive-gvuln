#!/usr/bin/env python3
"""Generate vulnerability reports in JSON, CSV, Markdown, or NDJSON format."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Iterable

from vuln_management.models import Finding, FindingState


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate vulnerability report outputs")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument(
        "--format",
        required=True,
        choices=["json", "csv", "markdown", "md", "ndjson", "jsonl"],
        help="Output format",
    )
    parser.add_argument("--output", required=True, help="Output report path")
    parser.add_argument(
        "--state",
        action="append",
        choices=[state.value for state in FindingState],
        help="Filter by finding state (repeatable), e.g. --state open --state remediated",
    )
    return parser.parse_args()


def load_findings(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Findings file must contain a JSON array")
    return [Finding.model_validate(item) for item in data]


def filter_findings_by_state(findings: Iterable[Finding], states: list[str] | None) -> list[Finding]:
    if not states:
        return list(findings)
    allowed_states = {FindingState(state) for state in states}
    return [f for f in findings if f.state in allowed_states]


def write_json(findings: list[Finding], output: Path) -> None:
    payload = [f.model_dump(mode="json") for f in findings]
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def write_ndjson(findings: list[Finding], output: Path) -> None:
    lines = [json.dumps(f.model_dump(mode="json")) for f in findings]
    output.write_text(("\n".join(lines) + ("\n" if lines else "")), encoding="utf-8")


def write_csv(findings: list[Finding], output: Path) -> None:
    fieldnames = [
        "id",
        "title",
        "severity",
        "state",
        "asset",
        "owner",
        "discovered_at",
        "sla_due_at",
        "remediated_at",
    ]
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            row = finding.model_dump(mode="json")
            writer.writerow({k: row.get(k) for k in fieldnames})


def write_markdown(findings: list[Finding], output: Path) -> None:
    lines = [
        "# Vulnerability Report",
        "",
        "| ID | Title | Severity | State | Asset | Owner | SLA Due |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        lines.append(
            f"| {f.id} | {f.title} | {f.severity.value} | {f.state.value} | {f.asset} | {f.owner} | {f.sla_due_at.isoformat()} |"
        )
    lines.append("")
    output.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    args = parse_args()
    findings = load_findings(Path(args.findings))
    findings = filter_findings_by_state(findings, args.state)

    output = Path(args.output)
    fmt = args.format.lower()

    if fmt == "json":
        write_json(findings, output)
    elif fmt == "csv":
        write_csv(findings, output)
    elif fmt in {"markdown", "md"}:
        write_markdown(findings, output)
    elif fmt in {"ndjson", "jsonl"}:
        write_ndjson(findings, output)
    else:
        raise ValueError(f"Unsupported format: {args.format}")


if __name__ == "__main__":
    main()
