from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run(tmp_path: Path, findings: list[dict], sort_by: str) -> list[str]:
    fpath = tmp_path / "findings.json"
    fpath.write_text(json.dumps(findings), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/check_sla.py",
            "--findings",
            str(fpath),
            "--json",
            "--sort-by",
            sort_by,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(proc.stdout)
    return [f["id"] for f in payload["findings"]]


def test_sort_by_due_at_severity_created_at(tmp_path: Path):
    findings = [
        {"id": "F-1", "severity": "Low", "status": "open", "created_at": "2026-01-01T00:00:00Z"},
        {"id": "F-2", "severity": "Critical", "status": "open", "created_at": "2026-01-03T00:00:00Z"},
        {"id": "F-3", "severity": "High", "status": "open", "created_at": "2026-01-02T00:00:00Z"},
        {"id": "F-4", "severity": "Medium", "status": "open", "created_at": "2026-01-01T12:00:00Z"},
    ]

    # due_at asc: F-2 (1d), F-3 (7d), F-4 (30d), F-1 (90d)
    assert _run(tmp_path, findings, "due_at") == ["F-2", "F-3", "F-4", "F-1"]

    # severity rank: Critical -> High -> Medium -> Low
    assert _run(tmp_path, findings, "severity") == ["F-2", "F-3", "F-4", "F-1"]

    # created_at asc
    assert _run(tmp_path, findings, "created_at") == ["F-1", "F-4", "F-3", "F-2"]
