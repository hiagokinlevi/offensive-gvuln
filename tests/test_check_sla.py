from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_check_sla_severity_filter_changes_overdue_results(tmp_path: Path) -> None:
    findings = [
        {
            "id": "F-CRIT-1",
            "title": "Critical overdue",
            "severity": "Critical",
            "status": "open",
            "created_at": "2020-01-01T00:00:00Z",
        },
        {
            "id": "F-HIGH-1",
            "title": "High overdue",
            "severity": "High",
            "status": "open",
            "created_at": "2020-01-01T00:00:00Z",
        },
    ]

    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(findings), encoding="utf-8")

    unfiltered = subprocess.run(
        [sys.executable, "scripts/check_sla.py", "--findings", str(findings_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert unfiltered.returncode == 1
    unfiltered_ids = {item["id"] for item in json.loads(unfiltered.stdout)}
    assert unfiltered_ids == {"F-CRIT-1", "F-HIGH-1"}

    filtered = subprocess.run(
        [
            sys.executable,
            "scripts/check_sla.py",
            "--findings",
            str(findings_file),
            "--severity",
            "Critical",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert filtered.returncode == 1
    filtered_ids = {item["id"] for item in json.loads(filtered.stdout)}
    assert filtered_ids == {"F-CRIT-1"}
