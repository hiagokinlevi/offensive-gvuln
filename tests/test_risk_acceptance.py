"""Testes para fluxo de risk acceptance com assinatura de aprovador."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from vuln_management.models import Finding, FindingStatus, Severity
from vuln_management.risk_acceptance import (
    apply_risk_acceptance_to_finding,
    create_risk_acceptance_record,
    find_expiring_records,
    verify_risk_acceptance_record,
    verify_risk_acceptance_signature,
)


def _make_finding(status: FindingStatus = FindingStatus.TRIAGED) -> Finding:
    """Cria finding base para os cenários de teste."""
    return Finding(
        title="Hardcoded credential in API service",
        severity=Severity.HIGH,
        status=status,
        description="Credential appears in source code repository.",
        affected_asset="api.internal.local",
    )


class TestRiskAcceptanceCore:
    def test_create_record_signature_is_valid(self) -> None:
        finding = _make_finding()
        record = create_risk_acceptance_record(
            finding_id=finding.id,
            requested_by="analyst@example.com",
            approved_by="manager@example.com",
            reason="Temporary business dependency requires delayed remediation.",
            expires_at=datetime.now(timezone.utc) + timedelta(days=15),
            signing_key="team-shared-key",
            compensating_controls=["WAF hardening", "daily monitoring"],
            policy_reference="GRC-RISK-2026-01",
        )
        assert verify_risk_acceptance_signature(record, signing_key="team-shared-key")

    def test_tampered_record_fails_signature_validation(self) -> None:
        finding = _make_finding()
        record = create_risk_acceptance_record(
            finding_id=finding.id,
            requested_by="analyst@example.com",
            approved_by="manager@example.com",
            reason="Temporary acceptance.",
            expires_at=datetime.now(timezone.utc) + timedelta(days=10),
            signing_key="team-shared-key",
        )
        tampered = record.model_copy(update={"reason": "Tampered approval reason"})
        assert not verify_risk_acceptance_signature(tampered, signing_key="team-shared-key")

    def test_requested_and_approved_by_must_be_different(self) -> None:
        finding = _make_finding()
        with pytest.raises(ValueError, match="must be different"):
            create_risk_acceptance_record(
                finding_id=finding.id,
                requested_by="same@example.com",
                approved_by="same@example.com",
                reason="Should fail due to governance policy.",
                expires_at=datetime.now(timezone.utc) + timedelta(days=5),
                signing_key="k",
            )

    def test_verify_record_expired(self) -> None:
        finding = _make_finding()
        approved_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        record = create_risk_acceptance_record(
            finding_id=finding.id,
            requested_by="analyst@example.com",
            approved_by="manager@example.com",
            reason="Accepted only for migration window.",
            expires_at=datetime(2026, 1, 10, tzinfo=timezone.utc),
            signing_key="team-shared-key",
            approved_at=approved_at,
        )
        valid, reason = verify_risk_acceptance_record(
            record,
            signing_key="team-shared-key",
            reference_time=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )
        assert not valid
        assert reason == "expired"

    def test_find_expiring_records(self) -> None:
        finding = _make_finding()
        now = datetime(2026, 4, 1, tzinfo=timezone.utc)
        record_soon = create_risk_acceptance_record(
            finding_id=finding.id,
            requested_by="a@example.com",
            approved_by="b@example.com",
            reason="Soon expires",
            expires_at=now + timedelta(days=5),
            signing_key="k",
            approved_at=now,
        )
        record_late = create_risk_acceptance_record(
            finding_id=finding.id,
            requested_by="a@example.com",
            approved_by="b@example.com",
            reason="Late expires",
            expires_at=now + timedelta(days=45),
            signing_key="k",
            approved_at=now,
        )
        expiring = find_expiring_records([record_soon, record_late], days=10, reference_time=now)
        assert [r.record_id for r in expiring] == [record_soon.record_id]

    def test_apply_record_to_finding_transitions_to_risk_accepted(self) -> None:
        finding = _make_finding(status=FindingStatus.TRIAGED)
        record = create_risk_acceptance_record(
            finding_id=finding.id,
            requested_by="analyst@example.com",
            approved_by="manager@example.com",
            reason="Accepted after stakeholder sign-off.",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            signing_key="governance-key",
        )
        transition_name = apply_risk_acceptance_to_finding(
            finding,
            record=record,
            signing_key="governance-key",
            actor="governance-bot@example.com",
        )
        assert transition_name == "accept_risk"
        assert finding.status == FindingStatus.RISK_ACCEPTED
        assert finding.remediation_records[-1].to_status == FindingStatus.RISK_ACCEPTED

    def test_apply_record_with_mismatched_finding_id_raises(self) -> None:
        finding = _make_finding()
        record = create_risk_acceptance_record(
            finding_id="another-finding-id",
            requested_by="analyst@example.com",
            approved_by="manager@example.com",
            reason="Mismatch should fail.",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            signing_key="governance-key",
        )
        with pytest.raises(ValueError, match="does not match"):
            apply_risk_acceptance_to_finding(
                finding,
                record=record,
                signing_key="governance-key",
                actor="governance-bot@example.com",
            )


class TestRiskAcceptanceCli:
    def test_create_verify_and_apply_flow(self) -> None:
        from cli.main import cli as main_cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            finding = _make_finding(status=FindingStatus.TRIAGED)
            finding_file = Path("findings.json")
            finding_file.write_text(
                json.dumps([finding.model_dump(mode="json")], indent=2, default=str),
                encoding="utf-8",
            )

            record_file = "risk-record.json"
            create_result = runner.invoke(
                main_cli,
                [
                    "risk-acceptance",
                    "create",
                    "--finding-id",
                    finding.id,
                    "--requested-by",
                    "analyst@example.com",
                    "--approved-by",
                    "manager@example.com",
                    "--reason",
                    "Approved by governance committee.",
                    "--expires-at",
                    "2026-12-31T23:59:59Z",
                    "--output",
                    record_file,
                ],
                env={"GVULN_APPROVER_SIGNING_KEY": "team-key"},
            )
            assert create_result.exit_code == 0, create_result.output

            verify_result = runner.invoke(
                main_cli,
                ["risk-acceptance", "verify", record_file],
                env={"GVULN_APPROVER_SIGNING_KEY": "team-key"},
            )
            assert verify_result.exit_code == 0, verify_result.output
            assert "valid" in verify_result.output.lower()

            apply_result = runner.invoke(
                main_cli,
                [
                    "risk-acceptance",
                    "apply",
                    str(finding_file),
                    "--record-file",
                    record_file,
                    "--id",
                    finding.id[:8],
                    "--actor",
                    "governance-bot@example.com",
                    "--save",
                ],
                env={"GVULN_APPROVER_SIGNING_KEY": "team-key"},
            )
            assert apply_result.exit_code == 0, apply_result.output

            saved = json.loads(finding_file.read_text(encoding="utf-8"))
            assert saved[0]["status"] == "risk_accepted"

    def test_verify_with_wrong_key_fails(self) -> None:
        from cli.main import cli as main_cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            finding = _make_finding()
            record = create_risk_acceptance_record(
                finding_id=finding.id,
                requested_by="analyst@example.com",
                approved_by="manager@example.com",
                reason="Signed with a different key.",
                expires_at=datetime.now(timezone.utc) + timedelta(days=10),
                signing_key="correct-key",
            )
            record_file = Path("record.json")
            record_file.write_text(
                json.dumps(record.model_dump(mode="json"), indent=2),
                encoding="utf-8",
            )

            result = runner.invoke(
                main_cli,
                ["risk-acceptance", "verify", str(record_file)],
                env={"GVULN_APPROVER_SIGNING_KEY": "wrong-key"},
            )
            assert result.exit_code == 1
            assert "invalid_signature" in result.output

