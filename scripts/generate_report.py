#!/usr/bin/env python3
"""Generate vulnerability reports in JSON, CSV, Markdown, or NDJSON formats."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA_PATH = REPO_ROOT / "vuln_management" / "schemas" / "findings.schema.json"


def _load_findings(findings_path: Path) -> list[dict[str, Any]]:
    data = json.loads(findings_path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        findings = data["findings"]
    else:
        findings = data
    if not isinstance(findings, list):
        raise ValueError("Findings payload must be a list or an object containing a 'findings' list")
    for idx, item in enumerate(findings):
        if not isinstance(item, dict):
            raise ValueError(f"Finding at index {idx} must be an object")
    return findings


def _validate_schema(findings: list[dict[str, Any]], schema_path: Path) -> None:
    try:
        import jsonschema
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("Schema validation requested but 'jsonschema' is not installed") from exc

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)

    errors: list[str] = []
    for idx, finding in enumerate(findings):
        for err in validator.iter_errors(finding):
            loc = ".".join(str(p) for p in err.path) or "<root>"
            errors.append(f"record[{idx}] {loc}: {err.message}")

    if errors:
        preview = "\n".join(errors[:10])
        if len(errors) > 10:
            preview += f"\n... and {len(errors) - 10} more"
        raise ValueError(f"Schema validation failed:\n{preview}")


def _render_json(findings: list[dict[str, Any]]) -> str:
    return json.dumps(findings, indent=2)


def _render_ndjson(findings: list[dict[str, Any]]) -> str:
    return "\n".join(json.dumps(item, separators=(",", ":")) for item in findings) + ("\n" if findings else "")


def _render_csv(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return ""
    headers: list[str] = sorted({k for row in findings for k in row.keys()})
    from io import StringIO

    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=headers)
    writer.writeheader()
    writer.writerows(findings)
    return buf.getvalue()


def _render_markdown(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "# Vulnerability Report\n\nNo findings.\n"
    headers: list[str] = sorted({k for row in findings for k in row.keys()})
    lines = ["# Vulnerability Report", "", "| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in findings:
        lines.append("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate vulnerability reports")
    parser.add_argument("--findings", required=True, help="Path to findings JSON file")
    parser.add_argument("--format", choices=["json", "csv", "markdown", "ndjson", "jsonl"], default="markdown")
    parser.add_argument("--output", required=True, help="Output file path")
    parser.add_argument("--validate-schema", action="store_true", help="Validate findings against repository JSON schema before rendering")
    parser.add_argument("--schema", default=str(DEFAULT_SCHEMA_PATH), help="Optional path to findings JSON schema")
    args = parser.parse_args()

    try:
        findings = _load_findings(Path(args.findings))
        if args.validate_schema:
            _validate_schema(findings, Path(args.schema))

        fmt = "ndjson" if args.format == "jsonl" else args.format
        if fmt == "json":
            rendered = _render_json(findings)
        elif fmt == "csv":
            rendered = _render_csv(findings)
        elif fmt == "ndjson":
            rendered = _render_ndjson(findings)
        else:
            rendered = _render_markdown(findings)

        Path(args.output).write_text(rendered, encoding="utf-8")
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
