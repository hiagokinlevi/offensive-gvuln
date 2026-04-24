import json
import subprocess
import sys
from pathlib import Path


def test_check_sla_filters_by_state(tmp_path: Path) -> None:
    findings = [
        {
            "id": "F-OPEN",
            "title": "Open critical",
            "severity": "critical",
            "state": "open",
            "discovered_at": "2024-01-01T00:00:00+00:00",
        },
        {
            "id": "F-INPROG",
            "title": "In progress high",
            "severity": "high",
            "state": "in_progress",
            "discovered_at": "2024-01-01T00:00:00+00:00",
        },
        {
            "id": "F-CLOSED",
            "title": "Closed critical",
            "severity": "critical",
            "state": "closed",
            "discovered_at": "2024-01-01T00:00:00+00:00",
        },
    ]

    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(findings), encoding="utf-8")

    proc = subprocess.run(
        [
            sys.executable,
            "scripts/check_sla.py",
            "--findings",
            str(findings_path),
            "--state",
            "open",
            "--state",
            "in_progress",
            "--now",
            "2024-02-15T00:00:00+00:00",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    payload = json.loads(proc.stdout)

    assert payload["total"] == 2
    ids = {item["id"] for item in payload["results"]}
    assert ids == {"F-OPEN", "F-INPROG"}
    assert "F-CLOSED" not in ids
