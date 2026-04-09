"""
SLA breach engine.

SLA windows are measured from finding.discovered_at:
  CRITICAL = 24 h, HIGH = 7 days, MEDIUM = 30 days, LOW = 90 days, INFO = no SLA
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from .models import Finding, Severity

SLA_HOURS: dict[Severity, int | None] = {
    Severity.CRITICAL: 24,
    Severity.HIGH:     7 * 24,
    Severity.MEDIUM:   30 * 24,
    Severity.LOW:      90 * 24,
    Severity.INFO:     None,   # No SLA for informational findings
}


def compute_sla(finding: Finding) -> dict:
    """Return SLA metadata for a single finding."""
    hours = SLA_HOURS.get(finding.severity)
    if hours is None:
        return {"has_sla": False}

    deadline = finding.discovered_at + timedelta(hours=hours)
    now = datetime.now(timezone.utc)
    remaining = deadline - now
    breached = now > deadline

    return {
        "has_sla": True,
        "deadline": deadline.isoformat(),
        "breached": breached,
        "remaining_hours": round(remaining.total_seconds() / 3600, 1),
    }


def find_breached(findings: list[Finding]) -> list[tuple[Finding, dict]]:
    """Return (finding, sla_info) pairs where the SLA has been breached."""
    result = []
    for f in findings:
        if not f.is_open():
            continue
        sla = compute_sla(f)
        if sla.get("breached"):
            result.append((f, sla))
    return result
