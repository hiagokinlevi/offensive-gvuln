from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_generate_report_validate_schema_valid_and_invalid(tmp_path: Path) -> None:
    script = Path("scripts/generate_report.py")

    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "required": ["id", "title", "severity"],
        "properties": {
            "id": {"type": "string"},
            "title": {"type": "string"},
            "severity": {"type": "string"},
        },
        "additionalProperties": True,
    }
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(schema), encoding="utf-8")

    valid_findings = [{"id": "F-1", "title": "SQL Injection", "severity": "high"}]
    invalid_findings = [{"id": "F-2", "title": "Missing Severity"}]

    valid_path = tmp_path / "valid.json"
    invalid_path = tmp_path / "invalid.json"
    out_path = tmp_path / "report.md"

    valid_path.write_text(json.dumps(valid_findings), encoding="utf-8")
    invalid_path.write_text(json.dumps(invalid_findings), encoding="utf-8")

    ok = subprocess.run(
        [
            sys.executable,
            str(script),
            "--findings",
            str(valid_path),
            "--format",
            "markdown",
            "--output",
            str(out_path),
            "--validate-schema",
            "--schema",
            str(schema_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stderr
    assert out_path.exists()

    bad = subprocess.run(
        [
            sys.executable,
            str(script),
            "--findings",
            str(invalid_path),
            "--format",
            "markdown",
            "--output",
            str(out_path),
            "--validate-schema",
            "--schema",
            str(schema_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode != 0
    assert "Schema validation failed" in bad.stderr
