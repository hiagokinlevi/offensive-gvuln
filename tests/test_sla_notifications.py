"""Tests for SLA notification payload generation and CLI dry-run flow."""
from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from vuln_management.models import Finding, FindingStatus, Severity
from vuln_management.sla_notifications import build_notification_payload, send_webhook_notification
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


class TestSendWebhookNotification:
    def test_accepts_public_https_webhook(self, monkeypatch: pytest.MonkeyPatch) -> None:
        report = build_sla_report(
            [
                _finding(
                    finding_id="crit-1",
                    title="Critical overdue issue",
                    severity=Severity.CRITICAL,
                    hours_ago=60,
                ),
            ],
            now=_NOW,
        )
        payload = build_notification_payload(report, channel="slack")

        class _Response:
            status = 202

            def __enter__(self) -> "_Response":
                return self

            def __exit__(self, exc_type, exc, tb) -> None:
                return None

            def getcode(self) -> int:
                return self.status

        captured: dict[str, object] = {}

        def _fake_urlopen(req, timeout: int):
            captured["url"] = req.full_url
            captured["timeout"] = timeout
            return _Response()

        def _fake_getaddrinfo(host: str, port: int, *, type: int, proto: int):
            assert host == "hooks.slack.com"
            assert port == 443
            assert type == socket.SOCK_STREAM
            assert proto == socket.IPPROTO_TCP
            return [
                (socket.AF_INET, type, proto, "", ("54.192.55.10", port)),
                (socket.AF_INET6, type, proto, "", ("2600:9000:2047:3800::1", port, 0, 0)),
            ]

        monkeypatch.setattr("vuln_management.sla_notifications.socket.getaddrinfo", _fake_getaddrinfo)
        monkeypatch.setattr("vuln_management.sla_notifications.request.urlopen", _fake_urlopen)

        status = send_webhook_notification(
            "https://hooks.slack.com/services/T000/B000/example",
            payload,
            timeout=3,
        )

        assert status == 202
        assert captured == {
            "url": "https://hooks.slack.com/services/T000/B000/example",
            "timeout": 3,
        }

    @pytest.mark.parametrize(
        ("webhook_url", "error_fragment"),
        [
            ("", "must not be empty"),
            ("http://hooks.slack.com/services/T000/B000/example", "must use https"),
            ("file:///tmp/webhook.json", "must use https"),
            ("https://user:pass@hooks.slack.com/services/T000/B000/example", "embedded credentials"),
            ("https://localhost/webhook", "localhost"),
            ("https://alerts.localhost/webhook", "localhost"),
            ("https://127.0.0.1/webhook", "non-public IP"),
            ("https://[::1]/webhook", "non-public IP"),
            ("https://10.0.0.15/webhook", "non-public IP"),
        ],
    )
    def test_rejects_unsafe_webhook_urls(
        self,
        webhook_url: str,
        error_fragment: str,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
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
        payload = build_notification_payload(report, channel="teams")

        def _unexpected_urlopen(*args, **kwargs):
            raise AssertionError("urlopen should not be reached for rejected webhook URLs")

        monkeypatch.setattr("vuln_management.sla_notifications.request.urlopen", _unexpected_urlopen)

        with pytest.raises(ValueError, match=error_fragment):
            send_webhook_notification(webhook_url, payload)

    def test_rejects_webhook_hostnames_that_resolve_to_non_public_ips(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
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
        payload = build_notification_payload(report, channel="teams")

        def _fake_getaddrinfo(host: str, port: int, *, type: int, proto: int):
            assert host == "alerts.example.test"
            return [
                (socket.AF_INET, type, proto, "", ("127.0.0.1", port)),
                (socket.AF_INET, type, proto, "", ("10.0.0.25", port)),
            ]

        def _unexpected_urlopen(*args, **kwargs):
            raise AssertionError("urlopen should not be reached for rejected webhook URLs")

        monkeypatch.setattr("vuln_management.sla_notifications.socket.getaddrinfo", _fake_getaddrinfo)
        monkeypatch.setattr("vuln_management.sla_notifications.request.urlopen", _unexpected_urlopen)

        with pytest.raises(ValueError, match="must not resolve to loopback or non-public IP addresses"):
            send_webhook_notification("https://alerts.example.test/webhook", payload)


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
