"""Tests for SLA notification payload generation and CLI dry-run flow."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from click.testing import CliRunner

from vuln_management.models import Finding, FindingStatus, Severity
from vuln_management.sla_notifications import build_notification_payload
from vuln_management.sla_report import build_sla_report


_NOW = datetime(2026, 4, 9, 12, 0, tzinfo=timezone.utc)


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: Severity,
    hours_ago: float,
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    return Finding(
        id=finding_id,
        title=title,
        severity=severity,
        status=status,
        description="Test finding.",
        affected_asset="app.example.com",
        discovered_at=_NOW - timedelta(hours=hours_ago),
    )


class TestBuildNotificationPayload:
    def test_builds_slack_payload_with_top_findings(self) -> None:
        report = build_sla_report(
            [
                _finding(
                    finding_id="crit-1",
                    title="Critical overdue issue",
                    severity=Severity.CRITICAL,
                    hours_ago=60,
                ),
                _finding(
                    finding_id="high-1",
                    title="High overdue issue",
                    severity=Severity.HIGH,
                    hours_ago=200,
                ),
            ],
            now=_NOW,
        )

        payload = build_notification_payload(
            report,
            channel="slack",
            repository_label="k1n-offensive-gvuln",
            minimum_tier="breached",
            max_findings=1,
        )

        assert payload.channel == "slack"
        assert "SLA alert" in payload.summary
        assert payload.body["blocks"][0]["text"]["text"] == "k1n-offensive-gvuln SLA alert"
        assert "crit-1" in payload.body["blocks"][3]["text"]["text"]
        assert "high-1" not in payload.body["blocks"][3]["text"]["text"]

    def test_builds_teams_payload_including_warning_threshold(self) -> None:
        report = build_sla_report(
            [
                _finding(
                    finding_id="warn-1",
                    title="Near breach",
                    severity=Severity.HIGH,
                    hours_ago=100,
                ),
            ],
            now=_NOW,
        )

        payload = build_notification_payload(
            report,
            channel="teams",
            minimum_tier="warning",
        )

        assert payload.channel == "teams"
        assert payload.body["@type"] == "MessageCard"
        assert payload.body["sections"][0]["facts"][-1]["value"] == "warning"
        assert "warn-1" in payload.body["sections"][0]["text"]


class TestNotifySlaCli:
    def test_dry_run_writes_slack_payload_to_file(self) -> None:
        from cli.main import cli as main_cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            findings_file = Path("findings.json")
            findings_file.write_text(
                json.dumps(
                    [
                        _finding(
                            finding_id="crit-1",
                            title="Critical overdue issue",
                            severity=Severity.CRITICAL,
                            hours_ago=60,
                        ).model_dump(mode="json")
                    ],
                    indent=2,
                ),
                encoding="utf-8",
            )

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
                    "payload.json",
                ],
            )

            assert result.exit_code == 0, result.output
            payload = json.loads(Path("payload.json").read_text(encoding="utf-8"))
            assert payload["blocks"][0]["text"]["text"] == "offensive-gvuln SLA alert"
            assert "crit-1" in payload["blocks"][3]["text"]["text"]

    def test_live_send_requires_webhook_url(self) -> None:
        from cli.main import cli as main_cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            findings_file = Path("findings.json")
            findings_file.write_text(
                json.dumps(
                    [
                        _finding(
                            finding_id="warn-1",
                            title="Near breach",
                            severity=Severity.HIGH,
                            hours_ago=100,
                        ).model_dump(mode="json")
                    ],
                    indent=2,
                ),
                encoding="utf-8",
            )

            result = runner.invoke(
                main_cli,
                [
                    "notify-sla",
                    str(findings_file),
                    "--channel",
                    "teams",
                ],
            )

            assert result.exit_code == 1
            assert "--webhook-url is required" in result.output
