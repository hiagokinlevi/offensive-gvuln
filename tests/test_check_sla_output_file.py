from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_check_sla_writes_to_output_file_with_parent_creation(tmp_path: Path) -> None:
    findings = [
        {
            "id": "F-1",
            "title": "Old critical",
            "severity": "critical",
            "status": "open",
            "created_at": "2020-01-01T00:00:00Z",
        }
    ]
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(findings), encoding="utf-8")

    output_path = tmp_path / "nested" / "sla" / "report.json"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/check_sla.py",
            "--findings",
            str(findings_path),
            "--format",
            "json",
            "--summary-only",
            "--output",
            str(output_path),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout == ""
    assert output_path.exists()

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["overdue_total"] >= 1
