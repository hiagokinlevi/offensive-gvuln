"""
SLA Breach Report with Escalation Tiers
=========================================
Extends the basic sla_engine with escalation severity tiers, trend analysis,
and formatted report output.

Escalation model:
  - WARNING:  ≥50% of SLA window elapsed (but not yet breached)
  - BREACHED: SLA deadline has passed
  - CRITICAL_BREACH: SLA breached by ≥100% of the original window
                     (i.e. finding is 2x overdue)

Usage:
    from vuln_management.sla_report import build_sla_report, format_sla_report

    report = build_sla_report(tracker.all())
    print(format_sla_report(report))
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from vuln_management.models import Finding, Severity
from vuln_management.sla_engine import SLA_HOURS


# ---------------------------------------------------------------------------
# Escalation tiers
# ---------------------------------------------------------------------------

class EscalationTier(str):
    """Escalation status for a finding's SLA."""
    ON_TRACK = "on_track"
    WARNING = "warning"           # ≥50% of window elapsed
    BREACHED = "breached"         # Past deadline
    CRITICAL_BREACH = "critical_breach"  # Overdue by ≥ the original window


# ---------------------------------------------------------------------------
# Per-finding SLA status
# ---------------------------------------------------------------------------

@dataclass
class FindingSLAStatus:
    """Detailed SLA status for a single finding."""

    finding: Finding
    has_sla: bool
    elapsed_hours: float          # Hours since discovery
    window_hours: Optional[float] # SLA window in hours (None for INFO)
    deadline: Optional[datetime]
    remaining_hours: float        # Negative if breached
    elapsed_pct: float            # 0.0–1.0+ (can exceed 1.0 if breached)
    escalation: str               # EscalationTier value


# ---------------------------------------------------------------------------
# Report container
# ---------------------------------------------------------------------------

@dataclass
class SLAReport:
    """Aggregated SLA compliance report."""

    generated_at: datetime
    total_open: int
    on_track: list[FindingSLAStatus] = field(default_factory=list)
    warning: list[FindingSLAStatus] = field(default_factory=list)
    breached: list[FindingSLAStatus] = field(default_factory=list)
    critical_breach: list[FindingSLAStatus] = field(default_factory=list)
    no_sla: list[FindingSLAStatus] = field(default_factory=list)

    @property
    def breach_count(self) -> int:
        return len(self.breached) + len(self.critical_breach)

    @property
    def compliance_rate(self) -> float:
        """
        Fraction of SLA-governed open findings that are on-track or in warning.

        Returns 1.0 (100%) if there are no SLA-governed findings.
        """
        governed = len(self.on_track) + len(self.warning) + self.breach_count
        if governed == 0:
            return 1.0
        return (len(self.on_track) + len(self.warning)) / governed


# ---------------------------------------------------------------------------
# Computation
# ---------------------------------------------------------------------------

def _compute_finding_sla(finding: Finding, now: datetime) -> FindingSLAStatus:
    """Compute the SLA status for a single finding."""
    window_hours = SLA_HOURS.get(finding.severity)

    if window_hours is None:
        return FindingSLAStatus(
            finding=finding,
            has_sla=False,
            elapsed_hours=0.0,
            window_hours=None,
            deadline=None,
            remaining_hours=0.0,
            elapsed_pct=0.0,
            escalation=EscalationTier.ON_TRACK,
        )

    discovered = finding.discovered_at
    if discovered.tzinfo is None:
        discovered = discovered.replace(tzinfo=timezone.utc)

    elapsed = (now - discovered).total_seconds() / 3600
    deadline = discovered + timedelta(hours=window_hours)
    remaining = (deadline - now).total_seconds() / 3600
    elapsed_pct = elapsed / window_hours if window_hours > 0 else 0.0

    # Determine escalation tier
    if remaining < 0:
        # Already breached — check if critical breach (overdue ≥ 100% of window)
        overdue_hours = -remaining
        if overdue_hours >= window_hours:
            escalation = EscalationTier.CRITICAL_BREACH
        else:
            escalation = EscalationTier.BREACHED
    elif elapsed_pct >= 0.5:
        escalation = EscalationTier.WARNING
    else:
        escalation = EscalationTier.ON_TRACK

    return FindingSLAStatus(
        finding=finding,
        has_sla=True,
        elapsed_hours=round(elapsed, 1),
        window_hours=float(window_hours),
        deadline=deadline,
        remaining_hours=round(remaining, 1),
        elapsed_pct=round(elapsed_pct, 3),
        escalation=escalation,
    )


def build_sla_report(
    findings: list[Finding],
    now: Optional[datetime] = None,
) -> SLAReport:
    """
    Build a complete SLA report for a list of findings.

    Only open findings are evaluated (closed/risk-accepted/false-positive
    findings no longer have SLA obligations).

    Args:
        findings: List of Finding objects (from tracker.all()).
        now:      Reference datetime for SLA calculations (default: UTC now).
                  Useful for deterministic testing.

    Returns:
        SLAReport with findings grouped by escalation tier.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    report = SLAReport(generated_at=now, total_open=0)

    for finding in findings:
        if not finding.is_open():
            continue

        report.total_open += 1
        status = _compute_finding_sla(finding, now)

        if not status.has_sla:
            report.no_sla.append(status)
        elif status.escalation == EscalationTier.CRITICAL_BREACH:
            report.critical_breach.append(status)
        elif status.escalation == EscalationTier.BREACHED:
            report.breached.append(status)
        elif status.escalation == EscalationTier.WARNING:
            report.warning.append(status)
        else:
            report.on_track.append(status)

    # Sort each tier by remaining_hours (most urgent first)
    for tier_list in [report.critical_breach, report.breached, report.warning]:
        tier_list.sort(key=lambda s: s.remaining_hours)

    return report


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def format_sla_report(report: SLAReport) -> str:
    """
    Format an SLAReport as a human-readable text report.

    Suitable for terminal output, Slack messages, or ticket descriptions.
    """
    lines: list[str] = [
        f"SLA Compliance Report — {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"=" * 60,
        f"Open findings:     {report.total_open}",
        f"Compliance rate:   {report.compliance_rate * 100:.0f}%",
        f"Critical breaches: {len(report.critical_breach)}",
        f"Breached:          {len(report.breached)}",
        f"Warning (≥50%):    {len(report.warning)}",
        f"On track:          {len(report.on_track)}",
        f"No SLA (INFO):     {len(report.no_sla)}",
        f"",
    ]

    def _add_tier(tier_name: str, statuses: list[FindingSLAStatus]) -> None:
        if not statuses:
            return
        lines.append(f"{'─' * 60}")
        lines.append(f"[{tier_name}] ({len(statuses)} findings)")
        lines.append(f"{'─' * 60}")
        for s in statuses:
            f = s.finding
            if s.remaining_hours < 0:
                time_info = f"OVERDUE by {abs(s.remaining_hours):.1f}h"
            else:
                time_info = f"{s.remaining_hours:.1f}h remaining ({s.elapsed_pct * 100:.0f}% elapsed)"
            lines.append(
                f"  [{f.severity.value.upper():<8}] {f.title[:55]:<55} | {time_info}"
            )
        lines.append("")

    _add_tier("CRITICAL BREACH", report.critical_breach)
    _add_tier("BREACHED", report.breached)
    _add_tier("WARNING", report.warning)
    _add_tier("ON TRACK", report.on_track)

    lines.append(f"{'─' * 60}")
    lines.append(
        f"SLA compliance: {len(report.on_track) + len(report.warning)} / "
        f"{report.total_open - len(report.no_sla)} governed findings on track"
    )

    return "\n".join(lines)
