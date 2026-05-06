import json
import subprocess
import sys
from pathlib import Path


def _run(args):
    return subprocess.run(
        [sys.executable, "scripts/generate_report.py", *args],
        capture_output=True,
        text=True,
    )


def test_severity_filter_accepts_multi_value_case_insensitive(tmp_path: Path):
    findings = [
        {"id": "F-1", "title": "A", "severity": "Critical", "state": "open"},
        {"id": "F-2", "title": "B", "severity": "High", "state": "open"},
        {"id": "F-3", "title": "C", "severity": "Low", "state": "open"},
    ]
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(findings), encoding="utf-8")

    out_path = tmp_path / "report.json"
    proc = _run(
        [
            "--findings",
            str(findings_path),
            "--format",
            "json",
            "--output",
            str(out_path),
            "--severity",
            "critical,HIGH",
        ]
    )

    assert proc.returncode == 0, proc.stderr
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert [f["id"] for f in data] == ["F-1", "F-2"]


def test_severity_filter_rejects_invalid_value(tmp_path: Path):
    findings_path = tmp_path / "findings.json"
    findings_path.write_text("[]", encoding="utf-8")
    out_path = tmp_path / "report.json"

    proc = _run(
        [
            "--findings",
            str(findings_path),
            "--format",
            "json",
            "--output",
            str(out_path),
            "--severity",
            "critical,urgent",
        ]
    )

    assert proc.returncode != 0
    assert "Invalid severity value" in proc.stderr
