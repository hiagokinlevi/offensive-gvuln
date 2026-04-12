"""Tests for structured retest planning and diff reporting."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from click.testing import CliRunner

from vuln_management.models import Finding, FindingStatus, Severity
from vuln_management.retest import generate_retest_diff_report, schedule_retest


def _finding(*, status: FindingStatus, title: str = "SQL Injection", finding_id: str | None = None) -> Finding:
    return Finding(
        id=finding_id or "finding-001",
        title=title,
        severity=Severity.HIGH,
        status=status,
        description="Test finding.",
        affected_asset="app.example.com",
        discovered_at=datetime(2026, 4, 1, tzinfo=timezone.utc),
    )


class TestScheduleRetest:
    def test_schedule_retest_sets_plan_and_status(self) -> None:
        finding = _finding(status=FindingStatus.REMEDIATED)
        transition_name = schedule_retest(
            finding,
            due_at=datetime.now(timezone.utc) + timedelta(days=2),
            actor="qa@example.com",
            environment="staging",
            scope_summary="Verify the login flow and SQLi payload regression checks.",
        )

        assert transition_name == "schedule_retest"
        assert finding.status == FindingStatus.RETEST_SCHEDULED
        assert finding.retest_plan is not None
        assert finding.retest_plan.environment == "staging"
        assert finding.retest_plan.requested_by == "qa@example.com"

    def test_schedule_retest_rejects_past_deadline(self) -> None:
        finding = _finding(status=FindingStatus.REMEDIATED)
        try:
            schedule_retest(
                finding,
                due_at=datetime.now(timezone.utc) - timedelta(minutes=1),
                actor="qa@example.com",
                environment="prod",
                scope_summary="Re-run exploit reproduction steps safely.",
            )
        except ValueError as exc:
            assert "future" in str(exc)
        else:
            raise AssertionError("Expected ValueError for past retest due date")


class TestRetestDiffReport:
    def test_classifies_fixed_regressed_and_new_findings(self) -> None:
        baseline = [
            _finding(status=FindingStatus.OPEN, finding_id="fixed-1", title="Fixed"),
            _finding(status=FindingStatus.CLOSED, finding_id="regressed-1", title="Regressed"),
            _finding(status=FindingStatus.OPEN, finding_id="unchanged-1", title="Still open"),
        ]
        candidate = [
            _finding(status=FindingStatus.CLOSED, finding_id="fixed-1", title="Fixed"),
            _finding(status=FindingStatus.TRIAGED, finding_id="regressed-1", title="Regressed"),
            _finding(status=FindingStatus.IN_REMEDIATION, finding_id="unchanged-1", title="Still open"),
            _finding(status=FindingStatus.OPEN, finding_id="new-1", title="New"),
        ]

        report = generate_retest_diff_report(baseline, candidate)

        assert [finding.id for finding in report.fixed_findings] == ["fixed-1"]
        assert [finding.id for finding in report.regressed_findings] == ["regressed-1"]
        assert [finding.id for finding in report.unchanged_open_findings] == ["unchanged-1"]
        assert [finding.id for finding in report.newly_open_findings] == ["new-1"]
        assert report.total_changes == 3


class TestRetestCli:
    def test_schedule_command_persists_retest_plan(self) -> None:
        from cli.main import cli as main_cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            finding = _finding(status=FindingStatus.REMEDIATED, finding_id="abc12345")
            findings_file = Path("findings.json")
            findings_file.write_text(
                json.dumps([finding.model_dump(mode="json")], indent=2),
                encoding="utf-8",
            )

            result = runner.invoke(
                main_cli,
                [
                    "retest",
                    "schedule",
                    str(findings_file),
                    "--id",
                    "abc123",
                    "--due-at",
                    "2026-12-31T23:59:59Z",
                    "--actor",
                    "qa@example.com",
                    "--environment",
                    "staging",
                    "--scope",
                    "Verify the login workflow, exports, and API payload handling.",
                    "--save",
                ],
            )

            assert result.exit_code == 0, result.output
            saved = json.loads(findings_file.read_text(encoding="utf-8"))
            assert saved[0]["status"] == "retest_scheduled"
            assert saved[0]["retest_plan"]["environment"] == "staging"

    def test_schedule_command_rejects_symlinked_findings_file_when_saving(self) -> None:
        from cli.main import cli as main_cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            finding = _finding(status=FindingStatus.REMEDIATED, finding_id="abc12345")
            real_file = Path("findings.json")
            real_file.write_text(
                json.dumps([finding.model_dump(mode="json")], indent=2),
                encoding="utf-8",
            )
            linked_file = Path("findings-link.json")
            linked_file.symlink_to(real_file)

            result = runner.invoke(
                main_cli,
                [
                    "retest",
                    "schedule",
                    str(linked_file),
                    "--id",
                    "abc123",
                    "--due-at",
                    "2026-12-31T23:59:59Z",
                    "--actor",
                    "qa@example.com",
                    "--environment",
                    "staging",
                    "--scope",
                    "Verify the login workflow, exports, and API payload handling.",
                    "--save",
                ],
            )

            assert result.exit_code != 0
            assert "must not be a symlink" in result.output
            saved = json.loads(real_file.read_text(encoding="utf-8"))
            assert saved[0]["status"] == "remediated"

    def test_diff_command_outputs_markdown_summary(self) -> None:
        from cli.main import cli as main_cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            baseline_file = Path("baseline.json")
            candidate_file = Path("candidate.json")
            baseline_file.write_text(
                json.dumps([_finding(status=FindingStatus.OPEN, finding_id="fixed-1").model_dump(mode="json")], indent=2),
                encoding="utf-8",
            )
            candidate_file.write_text(
                json.dumps([_finding(status=FindingStatus.CLOSED, finding_id="fixed-1").model_dump(mode="json")], indent=2),
                encoding="utf-8",
            )

            result = runner.invoke(main_cli, ["retest", "diff", str(baseline_file), str(candidate_file)])

            assert result.exit_code == 0, result.output
            assert "Retest Diff Report" in result.output
            assert "Fixed findings" in result.output
