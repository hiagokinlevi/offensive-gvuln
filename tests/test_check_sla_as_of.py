from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from scripts.check_sla import main, parse_as_of


def test_parse_as_of_valid_z() -> None:
    dt = parse_as_of("2026-01-02T03:04:05Z")
    assert dt == datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def test_parse_as_of_invalid() -> None:
    with pytest.raises(Exception):
        parse_as_of("not-a-timestamp")


def test_as_of_stabilizes_overdue_result(tmp_path, monkeypatch, capsys) -> None:
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(
        json.dumps(
            [
                {
                    "id": "F-1",
                    "severity": "critical",
                    "state": "open",
                    "created_at": "2026-01-01T00:00:00Z",
                }
            ]
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "check_sla.py",
            "--findings",
            str(findings_path),
            "--as-of",
            "2026-01-01T12:00:00Z",
            "--summary-only",
        ],
    )
    rc_before = main()
    out_before = capsys.readouterr().out

    monkeypatch.setattr(
        "sys.argv",
        [
            "check_sla.py",
            "--findings",
            str(findings_path),
            "--as-of",
            "2026-01-03T00:00:01Z",
            "--summary-only",
        ],
    )
    rc_after = main()
    out_after = capsys.readouterr().out

    assert rc_before == 0
    assert "overdue=0" in out_before
    assert rc_after == 1
    assert "overdue=1" in out_after
