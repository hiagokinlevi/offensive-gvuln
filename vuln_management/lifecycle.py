"""
Vulnerability Lifecycle State Machine
========================================
Enforces valid state transitions for vulnerability findings and records
each transition in the finding's remediation history.

State graph:
                    ┌─────────────┐
             ┌─────▶│   TRIAGED   │◀─────────┐
             │      └──────┬──────┘          │
             │             │                 │
        ┌────┴────┐        ▼           ┌─────┴──────┐
        │  OPEN   │  IN_REMEDIATION    │  REOPENED  │
        └────┬────┘        │           │ (→ TRIAGED)│
             │             │           └────────────┘
             │             ▼
             │      ┌────────────┐
             ├─────▶│ REMEDIATED │
             │      └──────┬─────┘
             │             │
             │             ▼
             │      ┌───────────────────┐
             │      │ RETEST_SCHEDULED  │
             │      └──────────┬────────┘
             │                 │ (pass)         (fail → TRIAGED)
             │                 ▼
             │           ┌─────────┐
             ├──────────▶│ CLOSED  │
             │           └─────────┘
             │
             ├──────────▶ RISK_ACCEPTED
             └──────────▶ FALSE_POSITIVE

Transition rules are encoded in ALLOWED_TRANSITIONS.
Any transition not in the map raises InvalidTransitionError.

Usage:
    from vuln_management.lifecycle import transition, can_transition
    from vuln_management.models import Finding, FindingStatus

    finding = Finding(...)
    transition(finding, FindingStatus.TRIAGED, actor="analyst@example.com", note="Root cause confirmed")
    print(finding.status)  # FindingStatus.TRIAGED
"""
from __future__ import annotations

from vuln_management.models import Finding, FindingStatus, RemediationRecord


# ---------------------------------------------------------------------------
# Allowed state transition map
# ---------------------------------------------------------------------------
# Maps (from_status, to_status) → human-readable transition name.
# Any pair NOT in this dict is invalid and will raise InvalidTransitionError.

ALLOWED_TRANSITIONS: dict[tuple[FindingStatus, FindingStatus], str] = {
    # Initial triage
    (FindingStatus.OPEN,           FindingStatus.TRIAGED):            "triage",
    # Skip-triage fast path (e.g., automated scanner finding immediately in remediation)
    (FindingStatus.OPEN,           FindingStatus.IN_REMEDIATION):     "expedite_to_remediation",
    # Triage → begin fix
    (FindingStatus.TRIAGED,        FindingStatus.IN_REMEDIATION):     "start_remediation",
    # Triage → accept risk (no fix planned)
    (FindingStatus.TRIAGED,        FindingStatus.RISK_ACCEPTED):      "accept_risk",
    # Triage → false positive (invalid finding)
    (FindingStatus.TRIAGED,        FindingStatus.FALSE_POSITIVE):     "mark_false_positive",
    # Remediation complete — schedule verification
    (FindingStatus.IN_REMEDIATION, FindingStatus.REMEDIATED):         "mark_remediated",
    # Remediation complete — schedule retest
    (FindingStatus.REMEDIATED,     FindingStatus.RETEST_SCHEDULED):   "schedule_retest",
    # Retest passed — close the finding
    (FindingStatus.RETEST_SCHEDULED, FindingStatus.CLOSED):           "close_verified",
    # Retest failed — return to triage for re-analysis
    (FindingStatus.RETEST_SCHEDULED, FindingStatus.TRIAGED):          "retest_failed",
    # Direct close without formal retest (low severity or non-critical fix)
    (FindingStatus.REMEDIATED,     FindingStatus.CLOSED):             "close_without_retest",
    # Risk accepted can be closed (e.g., risk period expires)
    (FindingStatus.RISK_ACCEPTED,  FindingStatus.CLOSED):             "close_risk_accepted",
    # False positive close
    (FindingStatus.FALSE_POSITIVE, FindingStatus.CLOSED):             "close_false_positive",
    # Reopen closed findings (regression)
    (FindingStatus.CLOSED,         FindingStatus.TRIAGED):            "reopen",
    # Open → risk accepted (fast path for informational findings)
    (FindingStatus.OPEN,           FindingStatus.RISK_ACCEPTED):      "accept_risk_from_open",
    # Open → false positive (scanner-confirmed false positive without triage)
    (FindingStatus.OPEN,           FindingStatus.FALSE_POSITIVE):     "mark_false_positive_from_open",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class InvalidTransitionError(ValueError):
    """Raised when a requested state transition is not allowed."""

    def __init__(
        self,
        from_status: FindingStatus,
        to_status: FindingStatus,
        finding_id: str = "",
    ) -> None:
        finding_note = f" (finding {finding_id})" if finding_id else ""
        valid_targets = sorted(
            t.value for (f, t) in ALLOWED_TRANSITIONS if f == from_status
        )
        super().__init__(
            f"Cannot transition from '{from_status.value}' to '{to_status.value}'"
            f"{finding_note}. "
            f"Valid targets from '{from_status.value}': {valid_targets or ['none']}"
        )
        self.from_status = from_status
        self.to_status = to_status


# ---------------------------------------------------------------------------
# State machine functions
# ---------------------------------------------------------------------------

def can_transition(
    finding: Finding,
    to_status: FindingStatus,
) -> bool:
    """
    Return True if the transition from finding.status → to_status is valid.

    Does NOT mutate the finding.
    """
    return (finding.status, to_status) in ALLOWED_TRANSITIONS


def transition(
    finding: Finding,
    to_status: FindingStatus,
    actor: str,
    note: str = "",
) -> str:
    """
    Apply a lifecycle transition to a Finding, recording the change in history.

    Args:
        finding:   The Finding object to mutate.
        to_status: Target status.
        actor:     Identifier of who/what initiated the transition (e.g., email, system name).
        note:      Optional note attached to the transition record.

    Returns:
        The human-readable transition name (from ALLOWED_TRANSITIONS).

    Raises:
        InvalidTransitionError: If the transition is not allowed.
        ValueError: If actor is empty.
    """
    if not actor.strip():
        raise ValueError("actor must not be empty")

    transition_name = ALLOWED_TRANSITIONS.get((finding.status, to_status))
    if transition_name is None:
        raise InvalidTransitionError(finding.status, to_status, finding_id=finding.id)

    # Record the transition
    record = RemediationRecord(
        from_status=finding.status,
        to_status=to_status,
        actor=actor,
        note=note,
    )
    finding.remediation_records.append(record)
    finding.status = to_status

    return transition_name


def valid_transitions_from(status: FindingStatus) -> list[FindingStatus]:
    """
    Return the list of valid target statuses from the given status.

    Args:
        status: A FindingStatus value.

    Returns:
        List of FindingStatus values that can be transitioned to.
    """
    return [to for (frm, to) in ALLOWED_TRANSITIONS if frm == status]


def lifecycle_path(finding: Finding) -> list[str]:
    """
    Return the ordered list of status values this finding has passed through,
    derived from its remediation_records history.

    The path starts at the initial state (inferred as OPEN if no records
    predate the first transition) and includes the current status.

    Args:
        finding: The Finding object.

    Returns:
        List of status value strings in chronological order.
    """
    if not finding.remediation_records:
        return [finding.status.value]

    # Sort records by timestamp
    sorted_records = sorted(
        finding.remediation_records, key=lambda r: r.timestamp
    )

    path: list[str] = [sorted_records[0].from_status.value]
    for record in sorted_records:
        path.append(record.to_status.value)

    return path
