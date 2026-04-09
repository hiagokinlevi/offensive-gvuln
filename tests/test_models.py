"""Tests for Finding and RemediationRecord models."""
from __future__ import annotations
import pytest
from vuln_management.models import Finding, FindingStatus, Severity


def _make_finding(status: FindingStatus = FindingStatus.OPEN) -> Finding:
    f = Finding(
        title="Test Finding",
        severity=Severity.HIGH,
        description="A test vulnerability.",
        affected_asset="app.example.com",
        status=status,
    )
    return f


class TestFindingIsOpen:
    def test_open_status_is_open(self):
        """OPEN status should be considered open/active."""
        f = _make_finding(FindingStatus.OPEN)
        assert f.is_open() is True

    def test_triaged_status_is_open(self):
        """TRIAGED status still requires active attention."""
        f = _make_finding(FindingStatus.TRIAGED)
        assert f.is_open() is True

    def test_in_remediation_is_open(self):
        """IN_REMEDIATION status is active."""
        f = _make_finding(FindingStatus.IN_REMEDIATION)
        assert f.is_open() is True

    def test_remediated_is_open(self):
        """REMEDIATED still awaits verification — remains open."""
        f = _make_finding(FindingStatus.REMEDIATED)
        assert f.is_open() is True

    def test_retest_scheduled_is_open(self):
        """RETEST_SCHEDULED is still in-flight."""
        f = _make_finding(FindingStatus.RETEST_SCHEDULED)
        assert f.is_open() is True

    def test_closed_is_not_open(self):
        """CLOSED findings should not be considered open."""
        f = _make_finding(FindingStatus.CLOSED)
        assert f.is_open() is False

    def test_risk_accepted_is_not_open(self):
        """RISK_ACCEPTED findings are resolved — not open."""
        f = _make_finding(FindingStatus.RISK_ACCEPTED)
        assert f.is_open() is False

    def test_false_positive_is_not_open(self):
        """FALSE_POSITIVE findings are resolved — not open."""
        f = _make_finding(FindingStatus.FALSE_POSITIVE)
        assert f.is_open() is False


class TestFindingDefaults:
    def test_id_is_uuid_string(self):
        """Auto-generated ID should be a non-empty string."""
        f = _make_finding()
        assert isinstance(f.id, str)
        assert len(f.id) == 36  # standard UUID4 length

    def test_remediation_records_start_empty(self):
        """New finding should have no remediation records."""
        f = _make_finding()
        assert f.remediation_records == []

    def test_default_status_is_open(self):
        """Default status should be OPEN."""
        f = Finding(
            title="X",
            severity=Severity.LOW,
            description="desc",
            affected_asset="host",
        )
        assert f.status == FindingStatus.OPEN
