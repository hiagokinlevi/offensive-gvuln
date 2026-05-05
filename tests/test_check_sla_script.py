from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _write_findings(path: Path) -> None:
    now = datetime.now(timezone.utc)
    findings = [
        {
            "id": "old-critical",
            "title": "Old critical",
            "description": "desc",
            "severity": "Critical",
            "status": "Open",
            "owner": "sec",
            "owner_tier": "app",
            "created_at": (now - timedelta(days=10)).isoformat(),
            "updated_at": (now - timedelta(days=10)).isoformat(),
        },
        {
            "id": "new-critical",
            "title": "New critical",
            "description": "desc",
            "severity": "Critical",
            "status": "Open",
            "owner": "sec",
            "owner_tier": "app",
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
        },
    ]
    path.write_text(json.dumps(findings), encoding="utf-8")


def test_created_before_filters_before_sla_eval(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    _write_findings(findings_path)

    cutoff = (datetime.now(timezone.utc) - timedelta(days=5)).date().isoformat()
    result = subprocess.run(
        [
            sys.executable,
            "scripts/check_sla.py",
            "--findings",
            str(findings_path),
            "--created-before",
            cutoff,
            "--summary-only",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "total_findings=1 overdue=1" in result.stdout


def test_created_before_invalid_date_returns_nonzero(tmp_path: Path) -> None:
    findings_path = tmp_path / "findings.json"
    _write_findings(findings_path)

    result = subprocess.run(
        [
            sys.executable,
            "scripts/check_sla.py",
            "--findings",
            str(findings_path),
            "--created-before",
            "2026-13-40",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "invalid --created-before date" in result.stderr
