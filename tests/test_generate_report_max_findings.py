from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path("scripts/generate_report.py")


def _write_findings(path: Path) -> None:
    data = [
        {"id": "F-001", "title": "one", "severity": "high", "state": "open"},
        {"id": "F-002", "title": "two", "severity": "high", "state": "open"},
        {"id": "F-003", "title": "three", "severity": "high", "state": "open"},
    ]
    path.write_text(json.dumps(data), encoding="utf-8")


def test_max_findings_invalid_value_returns_nonzero(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    out = tmp_path / "report.json"
    _write_findings(findings)

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--findings",
            str(findings),
            "--output",
            str(out),
            "--format",
            "json",
            "--max-findings",
            "0",
        ],
        capture_output=True,
        text=True,
    )

    assert proc.returncode != 0
    assert "--max-findings must be greater than 0" in proc.stderr


def test_max_findings_truncates_after_filters_and_reports_note(tmp_path: Path) -> None:
    findings = tmp_path / "findings.json"
    out = tmp_path / "report.json"
    _write_findings(findings)

    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--findings",
            str(findings),
            "--output",
            str(out),
            "--format",
            "json",
            "--severity",
            "high",
            "--max-findings",
            "2",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 0
    assert "Truncated findings to 2 from 3 after applying filters" in proc.stdout

    payload = json.loads(out.read_text(encoding="utf-8"))
    assert [f["id"] for f in payload["findings"]] == ["F-001", "F-002"]
    assert payload["metadata"]["total_filtered_findings"] == 3
    assert payload["metadata"]["total_reported_findings"] == 2
    assert "truncation_note" in payload["metadata"]
