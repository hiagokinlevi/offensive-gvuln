from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _run_check(tmp_path: Path, findings: list[dict], fail_on_overdue: bool) -> subprocess.CompletedProcess[str]:
    findings_file = tmp_path / "findings.json"
    findings_file.write_text(json.dumps(findings), encoding="utf-8")

    cmd = [sys.executable, "scripts/check_sla.py", "--findings", str(findings_file)]
    if fail_on_overdue:
        cmd.append("--fail-on-overdue")

    return subprocess.run(cmd, text=True, capture_output=True)


def test_fail_on_overdue_exit_codes(tmp_path: Path) -> None:
    now = datetime.now(timezone.utc)

    not_overdue = [
        {
            "id": "F-1",
            "title": "Future due finding",
            "status": "open",
            "sla_due_at": (now + timedelta(days=3)).isoformat(),
        }
    ]
    overdue = [
        {
            "id": "F-2",
            "title": "Past due finding",
            "status": "open",
            "sla_due_at": (now - timedelta(days=3)).isoformat(),
        }
    ]

    ok_proc = _run_check(tmp_path, not_overdue, fail_on_overdue=True)
    assert ok_proc.returncode == 0, ok_proc.stderr

    bad_proc = _run_check(tmp_path, overdue, fail_on_overdue=True)
    assert bad_proc.returncode == 2, bad_proc.stderr
