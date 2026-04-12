"""Tests for GitHub and JIRA issue sync adapters."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from click.testing import CliRunner

from vuln_management.issue_sync import (
    build_github_issue_payload,
    build_jira_issue_payload,
    export_issue_sync_payloads,
    redact_sensitive_text,
)
from vuln_management.models import Finding, FindingStatus, Severity


def _finding(
    *,
    finding_id: str = "finding-001",
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.OPEN,
    description: str = "Unsanitized input reaches the database query builder.",
    affected_asset: str = "app.example.com/login",
    discovered_at: datetime = datetime(2026, 4, 1, tzinfo=timezone.utc),
) -> Finding:
    return Finding(
        id=finding_id,
        title="SQL Injection in login flow",
        severity=severity,
        status=status,
        description=description,
        affected_asset=affected_asset,
        cvss_score=8.8,
        cve_id="CVE-2026-1234",
        discovered_at=discovered_at,
    )


def test_build_github_issue_payload_adds_security_metadata() -> None:
    payload = build_github_issue_payload(
        _finding(severity=Severity.CRITICAL),
        assignees=("alice", "bob"),
        milestone=7,
    ).to_dict()

    assert payload["title"].startswith("[CRITICAL]")
    assert "severity:critical" in payload["labels"]
    assert "workflow:gvuln" in payload["labels"]
    assert payload["assignees"] == ["alice", "bob"]
    assert payload["milestone"] == 7
    assert "Finding Summary" in payload["body"]


def test_build_github_issue_payload_redacts_sensitive_description_values() -> None:
    payload = build_github_issue_payload(
        _finding(
            affected_asset="https://api.example.test/login?access_token=secret-token-value",
            description=(
                "Repro used password=hunter2 and Authorization: Bearer "
                "eyJhbGciOiJIUzI1NiJ9.testtoken"
            ),
        )
    ).to_dict()

    assert "hunter2" not in payload["body"]
    assert "secret-token-value" not in payload["body"]
    assert "eyJhbGciOiJIUzI1NiJ9.testtoken" not in payload["body"]
    assert "password=[REDACTED]" in payload["body"]
    assert "access_token=[REDACTED]" in payload["body"]
    assert "Bearer [REDACTED]" in payload["body"]


def test_build_jira_issue_payload_redacts_private_key_blocks() -> None:
    payload = build_jira_issue_payload(
        _finding(
            description=(
                "Temporary debug output:\n"
                "-----BEGIN PRIVATE KEY-----\n"
                "abc123\n"
                "-----END PRIVATE KEY-----"
            )
        )
    ).to_dict(project_key="SEC")

    description = payload["fields"]["description"]
    assert "abc123" not in description
    assert "[PRIVATE_KEY_REDACTED]" in description


def test_build_github_issue_payload_redacts_url_credentials_and_signed_query_values() -> None:
    payload = build_github_issue_payload(
        _finding(
            affected_asset="https://scanner:ultra-secret@example.test/export?sig=azure-secret&view=summary",
            description=(
                "Artifact download used "
                "https://analyst:topsecret@example.test/report?"
                "X-Amz-Signature=aws-secret&keep=1"
            ),
        )
    ).to_dict()

    assert "ultra-secret" not in payload["body"]
    assert "topsecret" not in payload["body"]
    assert "azure-secret" not in payload["body"]
    assert "aws-secret" not in payload["body"]
    assert "scanner:[REDACTED]@example.test" in payload["body"]
    assert "analyst:[REDACTED]@example.test" in payload["body"]
    assert "?sig=[REDACTED]&view=summary" in payload["body"]
    assert "?X-Amz-Signature=[REDACTED]&keep=1" in payload["body"]


def test_redact_sensitive_text_redacts_aws_access_keys() -> None:
    redacted = redact_sensitive_text("Leaked key AKIAIOSFODNN7EXAMPLE in request log")

    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "[AWS_ACCESS_KEY_REDACTED]" in redacted


def test_redact_sensitive_text_redacts_prefixed_secret_field_names() -> None:
    redacted = redact_sensitive_text(
        "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY "
        "aws_session_token=token-12345 "
        "slack_webhook_url=https://hooks.slack.com/services/T000/B000/SECRET"
    )

    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in redacted
    assert "token-12345" not in redacted
    assert "https://hooks.slack.com/services/T000/B000/SECRET" not in redacted
    assert "aws_secret_access_key=[REDACTED]" in redacted
    assert "aws_session_token=[REDACTED]" in redacted
    assert "slack_webhook_url=[REDACTED]" in redacted


def test_redact_sensitive_text_redacts_json_style_secret_values() -> None:
    redacted = redact_sensitive_text(
        '{"api_key": "abc-123-SECRET", "client_secret": "super-secret-value"}'
    )

    assert "abc-123-SECRET" not in redacted
    assert "super-secret-value" not in redacted
    assert '"api_key": "[REDACTED]"' in redacted
    assert '"client_secret": "[REDACTED]"' in redacted


def test_redact_sensitive_text_redacts_token_auth_and_cookie_values() -> None:
    redacted = redact_sensitive_text(
        "Authorization: Token sk_live_secretvalue123456 "
        "Cookie: sessionid=abc123.supersecret.token; csrftoken=csrf-secret"
    )

    assert "sk_live_secretvalue123456" not in redacted
    assert "abc123.supersecret.token" not in redacted
    assert "csrf-secret" not in redacted
    assert "Token [REDACTED]" in redacted
    assert "sessionid=[REDACTED]" in redacted
    assert "csrftoken=[REDACTED]" in redacted


def test_build_github_issue_payload_redacts_bare_github_tokens() -> None:
    classic_pat = "ghp_abcdefghijklmnopqrstuvwxyz0123456789ABCD"
    fine_grained_pat = (
        "github_pat_11ABCDEFGHijklmnop_qrstuvwxyz0123456789ABCDEFGHIJKLMN"
    )
    payload = build_github_issue_payload(
        _finding(
            affected_asset=f"https://api.example.test/tokens/{classic_pat}",
            description=(
                f"Temporary triage note captured {classic_pat} and "
                f"{fine_grained_pat} in debug output."
            ),
        )
    ).to_dict()

    assert classic_pat not in payload["body"]
    assert fine_grained_pat not in payload["body"]
    assert payload["body"].count("[GITHUB_TOKEN_REDACTED]") == 3


def test_build_jira_issue_payload_maps_priority_and_due_date() -> None:
    payload = build_jira_issue_payload(
        _finding(severity=Severity.MEDIUM),
        issue_type="Bug",
        components=("payments",),
    ).to_dict(project_key="SEC")

    fields = payload["fields"]
    assert fields["project"]["key"] == "SEC"
    assert fields["issuetype"]["name"] == "Bug"
    assert fields["priority"]["name"] == "Medium"
    assert fields["components"] == [{"name": "payments"}]
    assert fields["duedate"] == "2026-05-01"


def test_export_issue_sync_payloads_sorts_by_severity_and_filters_closed() -> None:
    findings = [
        _finding(finding_id="low", severity=Severity.LOW, discovered_at=datetime(2026, 4, 3, tzinfo=timezone.utc)),
        _finding(finding_id="closed", severity=Severity.CRITICAL, status=FindingStatus.CLOSED),
        _finding(finding_id="critical", severity=Severity.CRITICAL, discovered_at=datetime(2026, 4, 2, tzinfo=timezone.utc)),
    ]

    payload = export_issue_sync_payloads(findings, target="github", repo="org/repo")

    assert payload["generated_items"] == 2
    assert [item["finding_id"] for item in payload["items"]] == ["critical", "low"]


def test_export_issue_sync_payloads_requires_target_specific_context() -> None:
    try:
        export_issue_sync_payloads([_finding()], target="jira")
    except ValueError as exc:
        assert "project_key" in str(exc)
    else:
        raise AssertionError("Expected project_key validation error")


def test_issue_sync_cli_exports_github_payloads() -> None:
    from cli.main import cli as main_cli

    runner = CliRunner()
    with runner.isolated_filesystem():
        findings_file = Path("findings.json")
        findings_file.write_text(
            json.dumps([
                _finding(finding_id="abc123").model_dump(mode="json"),
                _finding(finding_id="closed456", status=FindingStatus.CLOSED).model_dump(mode="json"),
            ], indent=2),
            encoding="utf-8",
        )

        result = runner.invoke(
            main_cli,
            [
                "issue-sync",
                "export",
                str(findings_file),
                "--target",
                "github",
                "--repo",
                "org/repo",
                "--assignee",
                "alice",
            ],
        )

        assert result.exit_code == 0, result.output
        rendered = json.loads(result.output)
        assert rendered["generated_items"] == 1
        assert rendered["items"][0]["repo"] == "org/repo"
        assert rendered["items"][0]["payload"]["assignees"] == ["alice"]


def test_issue_sync_cli_can_include_closed_for_jira() -> None:
    from cli.main import cli as main_cli

    runner = CliRunner()
    with runner.isolated_filesystem():
        findings_file = Path("findings.json")
        findings_file.write_text(
            json.dumps([
                _finding(finding_id="open1").model_dump(mode="json"),
                _finding(finding_id="closed1", status=FindingStatus.CLOSED).model_dump(mode="json"),
            ], indent=2),
            encoding="utf-8",
        )
        output_file = Path("jira-export.json")

        result = runner.invoke(
            main_cli,
            [
                "issue-sync",
                "export",
                str(findings_file),
                "--target",
                "jira",
                "--project-key",
                "SEC",
                "--component",
                "appsec",
                "--include-closed",
                "--output",
                str(output_file),
            ],
        )

        assert result.exit_code == 0, result.output
        rendered = json.loads(output_file.read_text(encoding="utf-8"))
        assert rendered["generated_items"] == 2
        assert rendered["items"][0]["project_key"] == "SEC"
        assert rendered["items"][0]["payload"]["fields"]["components"] == [{"name": "appsec"}]


def test_issue_sync_cli_rejects_symlinked_output_file() -> None:
    from cli.main import cli as main_cli

    runner = CliRunner()
    with runner.isolated_filesystem():
        findings_file = Path("findings.json")
        findings_file.write_text(
            json.dumps([_finding().model_dump(mode="json")], indent=2),
            encoding="utf-8",
        )
        real_output = Path("real-export.json")
        real_output.write_text("placeholder", encoding="utf-8")
        linked_output = Path("jira-export.json")
        linked_output.symlink_to(real_output)

        result = runner.invoke(
            main_cli,
            [
                "issue-sync",
                "export",
                str(findings_file),
                "--target",
                "jira",
                "--project-key",
                "SEC",
                "--output",
                str(linked_output),
            ],
        )

        assert result.exit_code != 0
        assert "must not be a symlink" in result.output
        assert real_output.read_text(encoding="utf-8") == "placeholder"


def test_issue_sync_cli_rejects_symlinked_output_directory() -> None:
    from cli.main import cli as main_cli

    runner = CliRunner()
    with runner.isolated_filesystem():
        findings_file = Path("findings.json")
        findings_file.write_text(
            json.dumps([_finding().model_dump(mode="json")], indent=2),
            encoding="utf-8",
        )
        real_dir = Path("real-exports")
        real_dir.mkdir()
        linked_dir = Path("exports-link")
        linked_dir.symlink_to(real_dir, target_is_directory=True)

        result = runner.invoke(
            main_cli,
            [
                "issue-sync",
                "export",
                str(findings_file),
                "--target",
                "jira",
                "--project-key",
                "SEC",
                "--output",
                str(linked_dir / "jira-export.json"),
            ],
        )

        assert result.exit_code != 0
        assert "symlinked directories" in result.output
        assert not (real_dir / "jira-export.json").exists()
