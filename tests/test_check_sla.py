from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run_check_sla(tmp_path: Path, findings_payload: list[dict], *args: str) -> subprocess.CompletedProcess[str]:
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(findings_payload), encoding="utf-8")
    return subprocess.run(
        [sys.executable, "scripts/check_sla.py", "--findings", str(findings_file), *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _finding(fid: str, updated_at: str) -> dict:
    return {
        "id": fid,
        "title": f"Finding {fid}",
        "description": "desc",
        "severity": "high",
        "state": "open",
        "asset": "asset-1",
        "owner": "team-a",
        "created_at": "2024-01-01T00:00:00Z",
        "updated_at": updated_at,
    }


def test_updated_after_filters_findings_before_sla_eval(tmp_path: Path) -> None:
    payload = [
        _finding("F-1", "2024-01-10T00:00:00Z"),
        _finding("F-2", "2024-03-15T00:00:00Z"),
    ]

    result = _run_check_sla(tmp_path, payload, "--updated-after", "2024-03-01", "--summary-only")

    assert result.returncode in (0, 1)
    summary = json.loads(result.stdout.strip().splitlines()[-1])
    assert summary["total"] == 1


def test_updated_after_can_yield_empty_result(tmp_path: Path) -> None:
    payload = [_finding("F-1", "2024-01-10T00:00:00Z")]

    result = _run_check_sla(tmp_path, payload, "--updated-after", "2024-12-01", "--summary-only")

    assert result.returncode == 0
    summary = json.loads(result.stdout.strip().splitlines()[-1])
    assert summary == {"total": 0, "overdue": 0, "compliant": 0}


def test_updated_after_invalid_date_input(tmp_path: Path) -> None:
    payload = [_finding("F-1", "2024-01-10T00:00:00Z")]

    result = _run_check_sla(tmp_path, payload, "--updated-after", "2024-13-40")

    assert result.returncode != 0
    assert "Invalid value for --updated-after" in result.stderr
