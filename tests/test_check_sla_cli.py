from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path("scripts/check_sla.py")


def test_exit_code_only_quiet_mode_and_exit_mapping(tmp_path: Path) -> None:
    overdue_payload = {
        "findings": [
            {
                "id": "F-1",
                "severity": "High",
                "status": "open",
                "sla_due_at": "2000-01-01T00:00:00Z",
            }
        ]
    }
    ok_payload = {
        "findings": [
            {
                "id": "F-2",
                "severity": "Low",
                "status": "open",
                "sla_due_at": "2999-01-01T00:00:00Z",
            }
        ]
    }

    overdue_file = tmp_path / "overdue.json"
    ok_file = tmp_path / "ok.json"
    overdue_file.write_text(json.dumps(overdue_payload), encoding="utf-8")
    ok_file.write_text(json.dumps(ok_payload), encoding="utf-8")

    p_overdue = subprocess.run(
        [sys.executable, str(SCRIPT), "--findings", str(overdue_file), "--exit-code-only"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p_overdue.returncode == 2
    assert p_overdue.stdout == ""

    p_ok = subprocess.run(
        [sys.executable, str(SCRIPT), "--findings", str(ok_file), "--exit-code-only"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p_ok.returncode == 0
    assert p_ok.stdout == ""

    p_err = subprocess.run(
        [sys.executable, str(SCRIPT), "--findings", str(tmp_path / "missing.json"), "--exit-code-only"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert p_err.returncode == 1
    assert p_err.stdout == ""
