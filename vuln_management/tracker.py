"""
Vulnerability tracker with enforced state transitions.

Valid transitions enforce a controlled remediation workflow —
arbitrary status jumps are rejected to maintain audit integrity.
"""
from __future__ import annotations
from .models import Finding, FindingStatus, RemediationRecord

_VALID_TRANSITIONS: dict[FindingStatus, set[FindingStatus]] = {
    FindingStatus.OPEN: {FindingStatus.TRIAGED, FindingStatus.FALSE_POSITIVE},
    FindingStatus.TRIAGED: {FindingStatus.IN_REMEDIATION, FindingStatus.RISK_ACCEPTED},
    FindingStatus.IN_REMEDIATION: {FindingStatus.REMEDIATED},
    FindingStatus.REMEDIATED: {FindingStatus.RETEST_SCHEDULED, FindingStatus.CLOSED},
    FindingStatus.RETEST_SCHEDULED: {FindingStatus.CLOSED, FindingStatus.IN_REMEDIATION},
    FindingStatus.CLOSED: set(),
    FindingStatus.RISK_ACCEPTED: set(),
    FindingStatus.FALSE_POSITIVE: set(),
}


class VulnerabilityTracker:
    def __init__(self) -> None:
        self._findings: dict[str, Finding] = {}

    def add(self, finding: Finding) -> None:
        self._findings[finding.id] = finding

    def get(self, finding_id: str) -> Finding:
        if finding_id not in self._findings:
            raise KeyError(f"Finding {finding_id!r} not found")
        return self._findings[finding_id]

    def transition(self, finding_id: str, to_status: FindingStatus, actor: str, note: str = "") -> Finding:
        finding = self.get(finding_id)
        allowed = _VALID_TRANSITIONS.get(finding.status, set())
        if to_status not in allowed:
            raise ValueError(
                f"Transition {finding.status.value} → {to_status.value} is not allowed. "
                f"Valid next states: {[s.value for s in allowed]}"
            )
        record = RemediationRecord(from_status=finding.status, to_status=to_status, actor=actor, note=note)
        finding.remediation_records.append(record)
        finding.status = to_status
        return finding

    def list_open(self) -> list[Finding]:
        return [f for f in self._findings.values() if f.is_open()]

    def all(self) -> list[Finding]:
        return list(self._findings.values())
