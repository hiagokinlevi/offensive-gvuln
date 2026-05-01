from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _sample_findings() -> list[dict]:
    return [
        {
            "id": "F-001",
            "title": "SQLi in login",
            "severity": "high",
            "state": "open",
            "asset": "app01",
            "owner": "team-a",
            "description": "Unsanitized query",
            "discovered_at": "2026-01-10T10:00:00Z",
            "sla_due_at": "2026-01-17T10:00:00Z",
            "tags": ["web"],
        },
        {
            "id": "F-002",
            "title": "Outdated package",
            "severity": "medium",
            "state": "remediated",
            "asset": "api01",
            "owner": "team-b",
            "description": "Patch available",
            "discovered_at": "2026-01-01T10:00:00Z",
            "sla_due_at": "2026-01-31T10:00:00Z",
            "remediated_at": "2026-01-05T10:00:00Z",
            "tags": ["deps"],
        },
    ]


def _run_generate_report(tmp_path: Path, extra_args: list[str]) -> subprocess.CompletedProcess[str]:
    findings_path = tmp_path / "findings.json"
    output_path = tmp_path / "report.json"
    findings_path.write_text(json.dumps(_sample_findings()), encoding="utf-8")

    cmd = [
        sys.executable,
        "scripts/generate_report.py",
        "--findings",
        str(findings_path),
        "--format",
        "json",
        "--output",
        str(output_path),
        *extra_args,
    ]
    return subprocess.run(cmd, capture_output=True, text=True)


def test_generate_report_filters_single_state(tmp_path: Path) -> None:
    result = _run_generate_report(tmp_path, ["--state", "open"])
    assert result.returncode == 0, result.stderr

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert len(report) == 1
    assert report[0]["id"] == "F-001"
    assert report[0]["state"] == "open"


def test_generate_report_filters_multiple_states(tmp_path: Path) -> None:
    result = _run_generate_report(tmp_path, ["--state", "open", "--state", "remediated"])
    assert result.returncode == 0, result.stderr

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert len(report) == 2
    assert {item["state"] for item in report} == {"open", "remediated"}


def test_generate_report_rejects_invalid_state(tmp_path: Path) -> None:
    result = _run_generate_report(tmp_path, ["--state", "not-a-real-state"])
    assert result.returncode != 0
    assert "invalid choice" in result.stderr.lower()
