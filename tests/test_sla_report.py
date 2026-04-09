"""
Unit tests for vuln_management/sla_report.py
"""
from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vuln_management.models import Finding, FindingStatus, Severity
from vuln_management.sla_engine import SLA_HOURS
from vuln_management.sla_report import (
    EscalationTier,
    SLAReport,
    build_sla_report,
    format_sla_report,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


def _finding(
    severity: Severity = Severity.HIGH,
    hours_ago: float = 0.0,
    status: FindingStatus = FindingStatus.OPEN,
) -> Finding:
    discovered = _NOW - timedelta(hours=hours_ago)
    return Finding(
        title=f"{severity.value} finding ({hours_ago}h ago)",
        severity=severity,
        status=status,
        description="Test finding",
        affected_asset="test-asset",
        discovered_at=discovered,
    )


def _sla_window(severity: Severity) -> float:
    """Return the SLA window in hours for the given severity."""
    return float(SLA_HOURS[severity])


# ---------------------------------------------------------------------------
# EscalationTier assignment
# ---------------------------------------------------------------------------


class TestEscalationTierAssignment(unittest.TestCase):

    def test_on_track_when_less_than_50_percent_elapsed(self):
        """Finding discovered < 50% of window ago → ON TRACK."""
        window = _sla_window(Severity.CRITICAL)  # 24h
        finding = _finding(Severity.CRITICAL, hours_ago=window * 0.3)
        report = build_sla_report([finding], now=_NOW)
        self.assertEqual(len(report.on_track), 1)
        self.assertEqual(report.on_track[0].escalation, EscalationTier.ON_TRACK)

    def test_warning_when_50_to_100_percent_elapsed(self):
        """Finding at 60% of window → WARNING."""
        window = _sla_window(Severity.HIGH)  # 168h
        finding = _finding(Severity.HIGH, hours_ago=window * 0.6)
        report = build_sla_report([finding], now=_NOW)
        self.assertEqual(len(report.warning), 1)
        self.assertEqual(report.warning[0].escalation, EscalationTier.WARNING)

    def test_breached_when_past_deadline(self):
        """Finding past its deadline but < 2x overdue → BREACHED."""
        window = _sla_window(Severity.CRITICAL)  # 24h
        finding = _finding(Severity.CRITICAL, hours_ago=window * 1.5)
        report = build_sla_report([finding], now=_NOW)
        self.assertEqual(len(report.breached), 1)
        self.assertEqual(report.breached[0].escalation, EscalationTier.BREACHED)

    def test_critical_breach_when_2x_overdue(self):
        """Finding overdue by ≥ 100% of window → CRITICAL_BREACH."""
        window = _sla_window(Severity.CRITICAL)  # 24h
        finding = _finding(Severity.CRITICAL, hours_ago=window * 2.5)
        report = build_sla_report([finding], now=_NOW)
        self.assertEqual(len(report.critical_breach), 1)
        self.assertEqual(report.critical_breach[0].escalation, EscalationTier.CRITICAL_BREACH)

    def test_info_finding_has_no_sla(self):
        """INFO findings have no SLA window → no_sla bucket."""
        finding = _finding(Severity.INFO, hours_ago=999)
        report = build_sla_report([finding], now=_NOW)
        self.assertEqual(len(report.no_sla), 1)
        self.assertFalse(report.no_sla[0].has_sla)

    def test_exactly_at_50_percent_is_warning(self):
        """At exactly 50% elapsed, should be WARNING not ON TRACK."""
        window = _sla_window(Severity.HIGH)
        finding = _finding(Severity.HIGH, hours_ago=window * 0.5)
        report = build_sla_report([finding], now=_NOW)
        self.assertEqual(len(report.warning), 1)


# ---------------------------------------------------------------------------
# Closed findings excluded
# ---------------------------------------------------------------------------


class TestClosedFindingsExcluded(unittest.TestCase):

    def test_closed_finding_not_in_report(self):
        closed = _finding(Severity.CRITICAL, hours_ago=999, status=FindingStatus.CLOSED)
        report = build_sla_report([closed], now=_NOW)
        self.assertEqual(report.total_open, 0)

    def test_risk_accepted_finding_not_in_report(self):
        risk = _finding(Severity.HIGH, hours_ago=999, status=FindingStatus.RISK_ACCEPTED)
        report = build_sla_report([risk], now=_NOW)
        self.assertEqual(report.total_open, 0)

    def test_mixed_open_and_closed(self):
        open_finding = _finding(Severity.HIGH, hours_ago=10, status=FindingStatus.OPEN)
        closed = _finding(Severity.CRITICAL, hours_ago=999, status=FindingStatus.CLOSED)
        report = build_sla_report([open_finding, closed], now=_NOW)
        self.assertEqual(report.total_open, 1)


# ---------------------------------------------------------------------------
# SLAReport properties
# ---------------------------------------------------------------------------


class TestSLAReportProperties(unittest.TestCase):

    def test_breach_count(self):
        crit_window = _sla_window(Severity.CRITICAL)
        findings = [
            _finding(Severity.CRITICAL, hours_ago=crit_window * 1.5),  # breached
            _finding(Severity.CRITICAL, hours_ago=crit_window * 2.5),  # critical breach
        ]
        report = build_sla_report(findings, now=_NOW)
        self.assertEqual(report.breach_count, 2)

    def test_compliance_rate_100_when_all_on_track(self):
        window = _sla_window(Severity.HIGH)
        findings = [_finding(Severity.HIGH, hours_ago=window * 0.1)]
        report = build_sla_report(findings, now=_NOW)
        self.assertEqual(report.compliance_rate, 1.0)

    def test_compliance_rate_0_when_all_breached(self):
        window = _sla_window(Severity.CRITICAL)
        findings = [_finding(Severity.CRITICAL, hours_ago=window * 1.5)]
        report = build_sla_report(findings, now=_NOW)
        self.assertEqual(report.compliance_rate, 0.0)

    def test_compliance_rate_excludes_no_sla(self):
        """INFO findings should not affect compliance rate."""
        window = _sla_window(Severity.HIGH)
        on_track = _finding(Severity.HIGH, hours_ago=window * 0.1)
        info = _finding(Severity.INFO, hours_ago=999)
        report = build_sla_report([on_track, info], now=_NOW)
        self.assertEqual(report.compliance_rate, 1.0)

    def test_empty_findings_compliance_100(self):
        report = build_sla_report([], now=_NOW)
        self.assertEqual(report.compliance_rate, 1.0)


# ---------------------------------------------------------------------------
# FindingSLAStatus correctness
# ---------------------------------------------------------------------------


class TestFindingSLAStatusValues(unittest.TestCase):

    def test_elapsed_hours_correct(self):
        finding = _finding(Severity.HIGH, hours_ago=10.0)
        report = build_sla_report([finding], now=_NOW)
        on_track_and_warning = report.on_track + report.warning
        self.assertTrue(on_track_and_warning)
        status = on_track_and_warning[0]
        self.assertAlmostEqual(status.elapsed_hours, 10.0, delta=0.1)

    def test_remaining_hours_negative_when_breached(self):
        window = _sla_window(Severity.CRITICAL)
        finding = _finding(Severity.CRITICAL, hours_ago=window + 5)
        report = build_sla_report([finding], now=_NOW)
        all_breached = report.breached + report.critical_breach
        self.assertTrue(all_breached)
        self.assertLess(all_breached[0].remaining_hours, 0)

    def test_elapsed_pct_above_1_when_breached(self):
        window = _sla_window(Severity.CRITICAL)
        finding = _finding(Severity.CRITICAL, hours_ago=window * 1.5)
        report = build_sla_report([finding], now=_NOW)
        breached = report.breached + report.critical_breach
        self.assertTrue(breached)
        self.assertGreater(breached[0].elapsed_pct, 1.0)


# ---------------------------------------------------------------------------
# Sorting within tiers
# ---------------------------------------------------------------------------


class TestTierSorting(unittest.TestCase):

    def test_breached_sorted_most_overdue_first(self):
        """Most overdue findings should appear first in the breached tier."""
        window = _sla_window(Severity.CRITICAL)
        slightly_breached = _finding(Severity.CRITICAL, hours_ago=window + 1)
        very_breached = _finding(Severity.CRITICAL, hours_ago=window + 10)
        report = build_sla_report([slightly_breached, very_breached], now=_NOW)
        all_breached = report.breached + report.critical_breach
        if len(all_breached) >= 2:
            # Most negative remaining_hours should come first
            self.assertLessEqual(
                all_breached[0].remaining_hours,
                all_breached[1].remaining_hours,
            )


# ---------------------------------------------------------------------------
# format_sla_report
# ---------------------------------------------------------------------------


class TestFormatSLAReport(unittest.TestCase):

    def test_format_contains_compliance_rate(self):
        window = _sla_window(Severity.HIGH)
        report = build_sla_report([_finding(Severity.HIGH, hours_ago=window * 0.1)], now=_NOW)
        text = format_sla_report(report)
        self.assertIn("Compliance rate", text)

    def test_format_contains_breach_count(self):
        window = _sla_window(Severity.CRITICAL)
        report = build_sla_report([_finding(Severity.CRITICAL, hours_ago=window * 1.5)], now=_NOW)
        text = format_sla_report(report)
        self.assertIn("BREACHED", text)

    def test_format_empty_report(self):
        report = build_sla_report([], now=_NOW)
        text = format_sla_report(report)
        self.assertIn("SLA Compliance Report", text)
        self.assertIn("100%", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
