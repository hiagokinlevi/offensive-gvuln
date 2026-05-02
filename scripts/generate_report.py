#!/usr/bin/env python3
"""Generate vulnerability reports from findings JSON.

Supports JSON, CSV, Markdown, and JSONL output with optional filtering.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate vulnerability report")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument("--output", required=True, help="Path to output report file")
    parser.add_argument(
        "--format",
        required=True,
        choices=["json", "csv", "md", "jsonl"],
        help="Output format",
    )
    parser.add_argument("--severity", help="Optional severity filter")
    parser.add_argument("--state", help="Optional state filter")
    parser.add_argument(
        "--max-findings",
        type=int,
        default=None,
        help="Maximum number of findings to include after filters are applied",
    )
    return parser.parse_args()


def _load_findings(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "findings" in data and isinstance(data["findings"], list):
        return data["findings"]
    if isinstance(data, list):
        return data
    raise ValueError("Unsupported findings JSON structure")


def _apply_filters(
    findings: list[dict[str, Any]],
    severity: str | None,
    state: str | None,
) -> list[dict[str, Any]]:
    filtered = findings
    if severity:
        filtered = [f for f in filtered if str(f.get("severity", "")).lower() == severity.lower()]
    if state:
        filtered = [f for f in filtered if str(f.get("state", "")).lower() == state.lower()]
    return filtered


def _write_json(path: Path, findings: list[dict[str, Any]], metadata: dict[str, Any]) -> None:
    payload = {"metadata": metadata, "findings": findings}
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def _write_jsonl(path: Path, findings: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding) + "\n")


def _write_csv(path: Path, findings: list[dict[str, Any]]) -> None:
    headers = ["id", "title", "severity", "state", "owner", "asset", "created_at", "due_at"]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for finding in findings:
            writer.writerow({h: finding.get(h, "") for h in headers})


def _write_md(path: Path, findings: list[dict[str, Any]], metadata: dict[str, Any]) -> None:
    lines = ["# Vulnerability Report", "", "## Metadata", ""]
    for k, v in metadata.items():
        lines.append(f"- **{k}**: {v}")
    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No findings.")
    else:
        for f in findings:
            lines.append(f"### {f.get('id', 'N/A')} - {f.get('title', 'Untitled')}")
            lines.append(f"- Severity: {f.get('severity', 'N/A')}")
            lines.append(f"- State: {f.get('state', 'N/A')}")
            if f.get("description"):
                lines.append(f"- Description: {f.get('description')}")
            lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    args = parse_args()

    if args.max_findings is not None and args.max_findings <= 0:
        print("Error: --max-findings must be greater than 0", file=sys.stderr)
        return 1

    findings_path = Path(args.findings)
    output_path = Path(args.output)

    findings = _load_findings(findings_path)
    filtered = _apply_filters(findings, args.severity, args.state)

    truncation_note = None
    original_filtered_count = len(filtered)
    if args.max_findings is not None and original_filtered_count > args.max_findings:
        filtered = filtered[: args.max_findings]
        truncation_note = (
            f"Truncated findings to {args.max_findings} from {original_filtered_count} "
            "after applying filters"
        )
        print(f"[generate_report] {truncation_note}")

    metadata: dict[str, Any] = {
        "total_input_findings": len(findings),
        "total_filtered_findings": original_filtered_count,
        "total_reported_findings": len(filtered),
        "severity_filter": args.severity,
        "state_filter": args.state,
        "max_findings": args.max_findings,
    }
    if truncation_note:
        metadata["truncation_note"] = truncation_note

    fmt = args.format
    if fmt == "json":
        _write_json(output_path, filtered, metadata)
    elif fmt == "jsonl":
        _write_jsonl(output_path, filtered)
    elif fmt == "csv":
        _write_csv(output_path, filtered)
    elif fmt == "md":
        _write_md(output_path, filtered, metadata)
    else:
        print(f"Unsupported format: {fmt}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
