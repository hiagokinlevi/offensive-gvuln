from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import check_sla


def _write_findings(tmp_path: Path) -> Path:
    p = tmp_path / "findings.json"
    p.write_text(
        json.dumps(
            [
                {"id": "F-1", "title": "crit", "severity": "critical", "created_at": "2024-01-01T00:00:00Z"},
                {"id": "F-2", "title": "high", "severity": "high", "created_at": "2024-01-01T00:00:00Z"},
                {"id": "F-3", "title": "med", "severity": "medium", "created_at": "2024-01-01T00:00:00Z"},
            ]
        ),
        encoding="utf-8",
    )
    return p


def test_sla_tier_filters_to_single_severity(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    findings = _write_findings(tmp_path)

    rc = check_sla.main(["--findings", str(findings), "--sla-tier", "high", "--format", "json"])
    assert rc == 0

    out = json.loads(capsys.readouterr().out)
    assert len(out) == 1
    assert out[0]["id"] == "F-2"
    assert out[0]["severity"] == "high"


def test_sla_tier_invalid_value_rejected() -> None:
    parser = check_sla.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["--findings", "x.json", "--sla-tier", "urgent"])


def test_no_regression_when_sla_tier_omitted(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    findings = _write_findings(tmp_path)

    rc = check_sla.main(["--findings", str(findings), "--format", "json"])
    assert rc == 0

    out = json.loads(capsys.readouterr().out)
    ids = {row["id"] for row in out}
    assert ids == {"F-1", "F-2", "F-3"}
