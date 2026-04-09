"""Tests for VulnerabilityTracker state machine."""
from __future__ import annotations
import pytest
from vuln_management.models import Finding, FindingStatus, Severity
from vuln_management.tracker import VulnerabilityTracker


def _tracker_with_finding(status: FindingStatus = FindingStatus.OPEN) -> tuple[VulnerabilityTracker, Finding]:
    tracker = VulnerabilityTracker()
    finding = Finding(
        title="SQL Injection in login form",
        severity=Severity.CRITICAL,
        description="Classic SQL injection via username parameter.",
        affected_asset="auth.example.com",
        status=status,
    )
    tracker.add(finding)
    return tracker, finding


class TestValidTransitions:
    def test_open_to_triaged_succeeds(self):
        """OPEN → TRIAGED is a valid transition."""
        tracker, finding = _tracker_with_finding(FindingStatus.OPEN)
        updated = tracker.transition(finding.id, FindingStatus.TRIAGED, actor="analyst@example.com")
        assert updated.status == FindingStatus.TRIAGED

    def test_triaged_to_in_remediation_succeeds(self):
        """TRIAGED → IN_REMEDIATION is a valid transition."""
        tracker, finding = _tracker_with_finding(FindingStatus.TRIAGED)
        updated = tracker.transition(finding.id, FindingStatus.IN_REMEDIATION, actor="dev@example.com")
        assert updated.status == FindingStatus.IN_REMEDIATION

    def test_open_to_false_positive_succeeds(self):
        """OPEN → FALSE_POSITIVE is a valid transition."""
        tracker, finding = _tracker_with_finding(FindingStatus.OPEN)
        updated = tracker.transition(finding.id, FindingStatus.FALSE_POSITIVE, actor="analyst@example.com")
        assert updated.status == FindingStatus.FALSE_POSITIVE

    def test_remediated_to_closed_succeeds(self):
        """REMEDIATED → CLOSED is a valid transition."""
        tracker, finding = _tracker_with_finding(FindingStatus.REMEDIATED)
        updated = tracker.transition(finding.id, FindingStatus.CLOSED, actor="manager@example.com")
        assert updated.status == FindingStatus.CLOSED


class TestInvalidTransitions:
    def test_open_to_closed_raises_value_error(self):
        """OPEN → CLOSED must be rejected — skips mandatory triage."""
        tracker, finding = _tracker_with_finding(FindingStatus.OPEN)
        with pytest.raises(ValueError, match="not allowed"):
            tracker.transition(finding.id, FindingStatus.CLOSED, actor="attacker")

    def test_open_to_remediated_raises_value_error(self):
        """OPEN → REMEDIATED is an invalid jump."""
        tracker, finding = _tracker_with_finding(FindingStatus.OPEN)
        with pytest.raises(ValueError):
            tracker.transition(finding.id, FindingStatus.REMEDIATED, actor="dev")

    def test_closed_to_open_raises_value_error(self):
        """CLOSED is a terminal state — no transitions allowed."""
        tracker, finding = _tracker_with_finding(FindingStatus.CLOSED)
        with pytest.raises(ValueError):
            tracker.transition(finding.id, FindingStatus.OPEN, actor="dev")

    def test_risk_accepted_to_anything_raises(self):
        """RISK_ACCEPTED is terminal — no further transitions."""
        tracker, finding = _tracker_with_finding(FindingStatus.RISK_ACCEPTED)
        with pytest.raises(ValueError):
            tracker.transition(finding.id, FindingStatus.TRIAGED, actor="dev")


class TestRemediationRecordAudit:
    def test_record_appended_after_transition(self):
        """Each valid transition must append exactly one RemediationRecord."""
        tracker, finding = _tracker_with_finding(FindingStatus.OPEN)
        assert len(finding.remediation_records) == 0
        tracker.transition(finding.id, FindingStatus.TRIAGED, actor="analyst", note="Confirmed by analyst")
        assert len(finding.remediation_records) == 1

    def test_record_captures_correct_metadata(self):
        """Record must store from_status, to_status, and actor."""
        tracker, finding = _tracker_with_finding(FindingStatus.OPEN)
        tracker.transition(finding.id, FindingStatus.TRIAGED, actor="alice", note="Triaged after review")
        rec = finding.remediation_records[0]
        assert rec.from_status == FindingStatus.OPEN
        assert rec.to_status == FindingStatus.TRIAGED
        assert rec.actor == "alice"
        assert rec.note == "Triaged after review"

    def test_multiple_transitions_accumulate_records(self):
        """Two transitions should produce two audit records."""
        tracker, finding = _tracker_with_finding(FindingStatus.OPEN)
        tracker.transition(finding.id, FindingStatus.TRIAGED, actor="alice")
        tracker.transition(finding.id, FindingStatus.IN_REMEDIATION, actor="bob")
        assert len(finding.remediation_records) == 2


class TestTrackerLookup:
    def test_get_existing_finding(self):
        tracker, finding = _tracker_with_finding()
        result = tracker.get(finding.id)
        assert result.id == finding.id

    def test_get_missing_finding_raises_key_error(self):
        tracker, _ = _tracker_with_finding()
        with pytest.raises(KeyError):
            tracker.get("nonexistent-id")

    def test_list_open_excludes_closed(self):
        tracker = VulnerabilityTracker()
        open_f = Finding(title="A", severity=Severity.HIGH, description="d", affected_asset="h", status=FindingStatus.OPEN)
        closed_f = Finding(title="B", severity=Severity.LOW, description="d", affected_asset="h", status=FindingStatus.CLOSED)
        tracker.add(open_f)
        tracker.add(closed_f)
        open_list = tracker.list_open()
        assert open_f in open_list
        assert closed_f not in open_list
