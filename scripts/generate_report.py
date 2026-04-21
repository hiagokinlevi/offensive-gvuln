#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path

from vuln_management.models import Finding


def load_findings(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Findings file must contain a JSON array of findings")
    return [Finding.model_validate(item) for item in data]


def to_json(findings: list[Finding]) -> str:
    return json.dumps([f.model_dump(mode="json") for f in findings], indent=2)


def to_jsonl(findings: list[Finding]) -> str:
    # Newline-delimited JSON (NDJSON): one normalized finding per line
    return "\n".join(json.dumps(f.model_dump(mode="json")) for f in findings)


def to_csv(findings: list[Finding]) -> str:
    if not findings:
        return ""

    rows = [f.model_dump(mode="json") for f in findings]
    fieldnames = sorted({k for row in rows for k in row.keys()})

    from io import StringIO

    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def to_markdown(findings: list[Finding]) -> str:
    lines = ["# Vulnerability Report", "", f"Total Findings: **{len(findings)}**", ""]
    for f in findings:
        item = f.model_dump(mode="json")
        lines.extend(
            [
                f"## {item.get('id', 'unknown')} — {item.get('title', 'Untitled')}",
                f"- Severity: **{item.get('severity', 'unknown')}**",
                f"- Status: `{item.get('status', 'unknown')}`",
                f"- Asset: `{item.get('asset', 'unknown')}`",
                f"- Owner: `{item.get('owner', 'unknown')}`",
                f"- SLA Due: `{item.get('sla_due', 'n/a')}`",
                "",
                "### Description",
                item.get("description", ""),
                "",
                "### Remediation",
                item.get("remediation", ""),
                "",
            ]
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate vulnerability reports")
    parser.add_argument("--findings", required=True, help="Path to findings JSON")
    parser.add_argument(
        "--format",
        required=True,
        choices=["json", "jsonl", "csv", "markdown"],
        help="Output format",
    )
    parser.add_argument("--output", required=True, help="Output file path")
    args = parser.parse_args()

    findings = load_findings(Path(args.findings))

    if args.format == "json":
        rendered = to_json(findings)
    elif args.format == "jsonl":
        rendered = to_jsonl(findings)
    elif args.format == "csv":
        rendered = to_csv(findings)
    else:
        rendered = to_markdown(findings)

    Path(args.output).write_text(rendered, encoding="utf-8")
    print(f"Wrote {args.format} report: {args.output}")


if __name__ == "__main__":
    main()
