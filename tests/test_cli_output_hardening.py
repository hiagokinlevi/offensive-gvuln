"""Regression tests for CLI commands that write exported artifacts to disk."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from click.testing import CliRunner

from vuln_management.models import Finding, FindingStatus, Severity


def _finding(*, status: FindingStatus = FindingStatus.OPEN, finding_id: str = "finding-001") -> Finding:
    return Finding(
        id=finding_id,
        title="SQL Injection in login flow",
        severity=Severity.HIGH,
        status=status,
        description="Unsanitized input reaches the database query builder.",
        affected_asset="app.example.com/login",
        cvss_score=8.8,
        cve_id="CVE-2026-1234",
        discovered_at=datetime(2026, 4, 1, tzinfo=timezone.utc),
    )


def _write_findings(path: Path, findings: list[Finding]) -> None:
    path.write_text(
        json.dumps([finding.model_dump(mode="json") for finding in findings], indent=2),
        encoding="utf-8",
    )


def test_generate_cli_rejects_symlinked_output_file() -> None:
    from cli.main import cli as main_cli

    runner = CliRunner()
    with runner.isolated_filesystem():
        findings_file = Path("findings.json")
        _write_findings(findings_file, [_finding()])
        real_output = Path("real-report.md")
        real_output.write_text("placeholder", encoding="utf-8")
        linked_output = Path("report.md")
        linked_output.symlink_to(real_output)

        result = runner.invoke(
            main_cli,
            ["generate", str(findings_file), "--output", str(linked_output)],
        )

        assert result.exit_code != 0
        assert "must not be a symlink" in result.output
        assert real_output.read_text(encoding="utf-8") == "placeholder"


def test_notify_sla_cli_rejects_symlinked_output_directory() -> None:
    from cli.main import cli as main_cli

    runner = CliRunner()
    with runner.isolated_filesystem():
        findings_file = Path("findings.json")
        _write_findings(findings_file, [_finding(finding_id="crit-1", status=FindingStatus.OPEN)])
        real_dir = Path("real-exports")
        real_dir.mkdir()
        linked_dir = Path("exports-link")
        linked_dir.symlink_to(real_dir, target_is_directory=True)

        result = runner.invoke(
            main_cli,
            [
                "notify-sla",
                str(findings_file),
                "--channel",
                "slack",
                "--minimum-tier",
                "breached",
                "--dry-run",
                "--output",
                str(linked_dir / "payload.json"),
            ],
        )

        assert result.exit_code != 0
        assert "symlinked directories" in result.output
        assert not (real_dir / "payload.json").exists()


def test_retest_diff_cli_rejects_symlinked_output_file() -> None:
    from cli.main import cli as main_cli

    runner = CliRunner()
    with runner.isolated_filesystem():
        baseline_file = Path("baseline.json")
        candidate_file = Path("candidate.json")
        _write_findings(baseline_file, [_finding(status=FindingStatus.OPEN, finding_id="fixed-1")])
        _write_findings(candidate_file, [_finding(status=FindingStatus.CLOSED, finding_id="fixed-1")])
        real_output = Path("real-diff.md")
        real_output.write_text("placeholder", encoding="utf-8")
        linked_output = Path("diff.md")
        linked_output.symlink_to(real_output)

        result = runner.invoke(
            main_cli,
            [
                "retest",
                "diff",
                str(baseline_file),
                str(candidate_file),
                "--output",
                str(linked_output),
            ],
        )

        assert result.exit_code != 0
        assert "must not be a symlink" in result.output
        assert real_output.read_text(encoding="utf-8") == "placeholder"


def test_risk_acceptance_create_rejects_symlinked_output_directory() -> None:
    from cli.main import cli as main_cli

    runner = CliRunner()
    with runner.isolated_filesystem():
        real_dir = Path("real-records")
        real_dir.mkdir()
        linked_dir = Path("records-link")
        linked_dir.symlink_to(real_dir, target_is_directory=True)

        result = runner.invoke(
            main_cli,
            [
                "risk-acceptance",
                "create",
                "--finding-id",
                _finding().id,
                "--requested-by",
                "analyst@example.com",
                "--approved-by",
                "manager@example.com",
                "--reason",
                "Approved by governance committee.",
                "--expires-at",
                "2026-12-31T23:59:59Z",
                "--output",
                str(linked_dir / "risk-record.json"),
            ],
            env={"GVULN_APPROVER_SIGNING_KEY": "team-key"},
        )

        assert result.exit_code != 0
        assert "symlinked directories" in result.output
        assert not (real_dir / "risk-record.json").exists()
