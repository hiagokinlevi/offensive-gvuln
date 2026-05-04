from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/check_sla.py", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def test_fail_on_overdue_threshold_exit_codes(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)

    findings = [
        {
            "id": "F-1",
            "title": "Old high vuln",
            "severity": "high",
            "state": "open",
            "discovered_at": (now - timedelta(days=10)).isoformat(),
        },
        {
            "id": "F-2",
            "title": "Fresh medium vuln",
            "severity": "medium",
            "state": "open",
            "discovered_at": (now - timedelta(days=2)).isoformat(),
        },
    ]

    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(findings), encoding="utf-8")

    # One overdue finding; threshold above count => success
    below_threshold = _run(["--findings", str(findings_file), "--summary-only", "--fail-on-overdue", "2"])
    assert below_threshold.returncode == 0
    assert "overdue_count=1" in below_threshold.stdout

    # One overdue finding; threshold at count => failure
    at_threshold = _run(["--findings", str(findings_file), "--summary-only", "--fail-on-overdue", "1"])
    assert at_threshold.returncode == 1
    assert "overdue_count=1" in at_threshold.stdout
