import json
from datetime import datetime, timedelta, timezone

from scripts.generate_report import main


def _finding(fid: str, severity: str, discovered_at: datetime) -> dict:
    return {
        "id": fid,
        "title": f"Finding {fid}",
        "description": "desc",
        "severity": severity,
        "status": "open",
        "owner": "team-security",
        "asset": "api01",
        "discovered_at": discovered_at.isoformat(),
    }


def test_generate_report_overdue_only_filters_mixed_findings(tmp_path, capsys):
    now = datetime.now(timezone.utc)

    findings = [
        _finding("F-OLD-CRIT", "critical", now - timedelta(days=3)),  # overdue (24h SLA)
        _finding("F-NEW-HIGH", "high", now - timedelta(days=1)),      # not overdue (7d SLA)
    ]

    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps(findings), encoding="utf-8")

    rc = main([
        "--findings",
        str(findings_path),
        "--format",
        "json",
        "--overdue-only",
    ])

    assert rc == 0
    out = capsys.readouterr().out
    payload = json.loads(out)

    assert [item["id"] for item in payload] == ["F-OLD-CRIT"]
