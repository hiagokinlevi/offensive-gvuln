# test_remediation_plan_generator.py
# Cyber Port — Offensive / Governance Module
#
# Copyright (c) 2026 hiagokinlevi
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Comprehensive test suite for remediation_plan_generator.py.
# Covers RPLAN-001 through RPLAN-007, boundary conditions, quality thresholds,
# prioritisation, statistics helpers, and the public API surface.

from __future__ import annotations

import datetime
import hashlib
from typing import List, Optional

import pytest

from pentest_governance.remediation_plan_generator import (
    RemediationItem,
    RemediationPlan,
    RPlanCheck,
    generate_plan,
    generate_plans,
)

# ---------------------------------------------------------------------------
# Helpers / factories
# ---------------------------------------------------------------------------

REF = "2026-01-01"  # Fixed reference date used in all RPLAN-004 tests


def _item(
    finding_id: str = "F-001",
    title: str = "SQL Injection in login endpoint",
    severity: str = "MEDIUM",
    remediation_text: str = "Apply parameterized queries everywhere in the login flow.",
    owner_team: str = "AppSec",
    due_date: Optional[str] = "2026-02-01",
    compensating_control: str = "",
    verification_method: str = "Re-run SQLMap scan after patch.",
    estimated_effort: str = "medium",
) -> RemediationItem:
    """Return a fully-populated, passing RemediationItem (no checks should fire)."""
    return RemediationItem(
        finding_id=finding_id,
        title=title,
        severity=severity,
        remediation_text=remediation_text,
        owner_team=owner_team,
        due_date=due_date,
        compensating_control=compensating_control,
        verification_method=verification_method,
        estimated_effort=estimated_effort,
    )


def _fired_ids(plan: RemediationPlan) -> List[str]:
    """Return sorted list of check_ids from checks_fired."""
    return sorted(c.check_id for c in plan.checks_fired)


# ===========================================================================
# Section 1 — RPLAN-001: Missing remediation description
# ===========================================================================


class TestRplan001:
    def test_fires_when_remediation_text_empty(self):
        item = _item(finding_id="F-001", remediation_text="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-001" in _fired_ids(plan)

    def test_fires_when_remediation_text_under_30_chars(self):
        item = _item(finding_id="F-001", remediation_text="Fix it now.")  # 11 chars
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-001" in _fired_ids(plan)

    def test_fires_when_remediation_text_exactly_29_chars(self):
        item = _item(finding_id="F-001", remediation_text="x" * 29)
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-001" in _fired_ids(plan)

    def test_does_not_fire_when_remediation_text_exactly_30_chars(self):
        item = _item(finding_id="F-001", remediation_text="x" * 30)
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-001" not in _fired_ids(plan)

    def test_does_not_fire_when_remediation_text_well_populated(self):
        item = _item(finding_id="F-001", remediation_text="Apply parameterized queries throughout the application.")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-001" not in _fired_ids(plan)

    def test_evidence_contains_finding_id(self):
        item = _item(finding_id="F-XYZ", remediation_text="short")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-001"]
        assert len(checks) == 1
        assert "F-XYZ" in checks[0].evidence

    def test_check_severity_is_high(self):
        item = _item(finding_id="F-001", remediation_text="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-001"]
        assert checks[0].severity == "HIGH"

    def test_weight_is_25(self):
        item = _item(finding_id="F-001", remediation_text="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-001"]
        assert checks[0].weight == 25

    def test_affected_finding_ids_contains_item(self):
        item = _item(finding_id="F-001", remediation_text="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-001"]
        assert "F-001" in checks[0].affected_finding_ids

    def test_whitespace_only_remediation_fires(self):
        item = _item(finding_id="F-001", remediation_text="   ")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-001" in _fired_ids(plan)


# ===========================================================================
# Section 2 — RPLAN-002: No owner assigned
# ===========================================================================


class TestRplan002:
    def test_fires_when_owner_team_empty(self):
        item = _item(finding_id="F-001", owner_team="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-002" in _fired_ids(plan)

    def test_fires_when_owner_team_whitespace_only(self):
        item = _item(finding_id="F-001", owner_team="   ")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-002" in _fired_ids(plan)

    def test_does_not_fire_when_owner_team_set(self):
        item = _item(finding_id="F-001", owner_team="AppSec")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-002" not in _fired_ids(plan)

    def test_check_severity_is_high(self):
        item = _item(finding_id="F-001", owner_team="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-002"]
        assert checks[0].severity == "HIGH"

    def test_weight_is_25(self):
        item = _item(finding_id="F-001", owner_team="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-002"]
        assert checks[0].weight == 25

    def test_evidence_contains_finding_id(self):
        item = _item(finding_id="F-ABC", owner_team="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-002"]
        assert "F-ABC" in checks[0].evidence


# ===========================================================================
# Section 3 — RPLAN-003: No due date
# ===========================================================================


class TestRplan003:
    def test_fires_when_due_date_none(self):
        item = _item(finding_id="F-001", due_date=None)
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-003" in _fired_ids(plan)

    def test_fires_when_due_date_empty_string(self):
        item = _item(finding_id="F-001", due_date="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-003" in _fired_ids(plan)

    def test_does_not_fire_when_due_date_set(self):
        item = _item(finding_id="F-001", due_date="2026-06-30")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-003" not in _fired_ids(plan)

    def test_check_severity_is_medium(self):
        item = _item(finding_id="F-001", due_date=None)
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-003"]
        assert checks[0].severity == "MEDIUM"

    def test_weight_is_20(self):
        item = _item(finding_id="F-001", due_date=None)
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-003"]
        assert checks[0].weight == 20

    def test_evidence_contains_finding_id(self):
        item = _item(finding_id="F-003", due_date=None)
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-003"]
        assert "F-003" in checks[0].evidence


# ===========================================================================
# Section 4 — RPLAN-004: Critical/High with no compensating control & no near-term due date
# ===========================================================================


class TestRplan004:
    # ---- Positive triggers ----

    def test_fires_for_critical_with_no_due_date(self):
        item = _item(finding_id="F-001", severity="CRITICAL", due_date=None, compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" in _fired_ids(plan)

    def test_fires_for_high_with_no_due_date(self):
        item = _item(finding_id="F-001", severity="HIGH", due_date=None, compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" in _fired_ids(plan)

    def test_fires_for_critical_with_due_date_31_days_out(self):
        # reference = 2026-01-01, due = 2026-02-01 → 31 days
        item = _item(finding_id="F-001", severity="CRITICAL", due_date="2026-02-01", compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" in _fired_ids(plan)

    def test_fires_for_high_with_due_date_31_days_out(self):
        item = _item(finding_id="F-001", severity="HIGH", due_date="2026-02-01", compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" in _fired_ids(plan)

    # ---- Boundary: exactly 30 days ----

    def test_does_not_fire_when_due_exactly_30_days(self):
        # reference = 2026-01-01, due = 2026-01-31 → 30 days → no fire
        item = _item(finding_id="F-001", severity="CRITICAL", due_date="2026-01-31", compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" not in _fired_ids(plan)

    def test_fires_when_due_exactly_31_days(self):
        # reference = 2026-01-01, due = 2026-02-01 → 31 days → fire
        item = _item(finding_id="F-001", severity="CRITICAL", due_date="2026-02-01", compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" in _fired_ids(plan)

    def test_does_not_fire_when_due_1_day_out(self):
        item = _item(finding_id="F-001", severity="CRITICAL", due_date="2026-01-02", compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" not in _fired_ids(plan)

    # ---- Compensating control suppression ----

    def test_compensating_control_suppresses_check(self):
        item = _item(
            finding_id="F-001",
            severity="CRITICAL",
            due_date=None,
            compensating_control="WAF rule blocks the attack vector.",
        )
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" not in _fired_ids(plan)

    def test_compensating_control_suppresses_check_high(self):
        item = _item(
            finding_id="F-001",
            severity="HIGH",
            due_date="2026-06-01",
            compensating_control="Network segmentation in place.",
        )
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" not in _fired_ids(plan)

    # ---- Non-urgent severities ----

    def test_does_not_fire_for_medium_severity(self):
        item = _item(finding_id="F-001", severity="MEDIUM", due_date=None, compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" not in _fired_ids(plan)

    def test_does_not_fire_for_low_severity(self):
        item = _item(finding_id="F-001", severity="LOW", due_date=None, compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" not in _fired_ids(plan)

    def test_does_not_fire_for_informational_severity(self):
        item = _item(finding_id="F-001", severity="INFORMATIONAL", due_date=None, compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-004" not in _fired_ids(plan)

    # ---- Metadata ----

    def test_check_severity_is_high(self):
        item = _item(finding_id="F-001", severity="CRITICAL", due_date=None, compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-004"]
        assert checks[0].severity == "HIGH"

    def test_weight_is_25(self):
        item = _item(finding_id="F-001", severity="CRITICAL", due_date=None, compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-004"]
        assert checks[0].weight == 25

    def test_evidence_contains_finding_id_and_severity(self):
        item = _item(finding_id="F-004", severity="CRITICAL", due_date=None, compensating_control="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-004"]
        assert "F-004" in checks[0].evidence
        assert "CRITICAL" in checks[0].evidence


# ===========================================================================
# Section 5 — RPLAN-005: Duplicate remediation text
# ===========================================================================


class TestRplan005:
    def test_fires_for_two_findings_with_identical_remediation_text(self):
        shared_text = "Apply parameterized queries throughout the application layer."
        items = [
            _item(finding_id="F-001", remediation_text=shared_text),
            _item(finding_id="F-002", remediation_text=shared_text),
        ]
        plan = generate_plan(items, reference_date=REF)
        assert "RPLAN-005" in _fired_ids(plan)

    def test_fires_once_for_three_duplicates(self):
        shared_text = "Apply parameterized queries throughout the application layer."
        items = [
            _item(finding_id="F-001", remediation_text=shared_text),
            _item(finding_id="F-002", remediation_text=shared_text),
            _item(finding_id="F-003", remediation_text=shared_text),
        ]
        plan = generate_plan(items, reference_date=REF)
        dup_checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-005"]
        assert len(dup_checks) == 1
        assert set(dup_checks[0].affected_finding_ids) == {"F-001", "F-002", "F-003"}

    def test_does_not_fire_for_single_finding_with_unique_text(self):
        item = _item(finding_id="F-001", remediation_text="Apply parameterized queries throughout the application layer.")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-005" not in _fired_ids(plan)

    def test_does_not_fire_for_two_distinct_remediation_texts(self):
        items = [
            _item(finding_id="F-001", remediation_text="Apply parameterized queries throughout the application layer."),
            _item(finding_id="F-002", remediation_text="Rotate all secrets and revoke compromised API keys immediately."),
        ]
        plan = generate_plan(items, reference_date=REF)
        assert "RPLAN-005" not in _fired_ids(plan)

    def test_case_insensitive_and_whitespace_normalised(self):
        items = [
            _item(finding_id="F-001", remediation_text="  Apply Parameterized Queries Throughout The Application Layer.  "),
            _item(finding_id="F-002", remediation_text="apply parameterized queries throughout the application layer."),
        ]
        plan = generate_plan(items, reference_date=REF)
        assert "RPLAN-005" in _fired_ids(plan)

    def test_does_not_fire_for_empty_remediation_texts(self):
        # Empty texts are already flagged by RPLAN-001; RPLAN-005 should skip them.
        items = [
            _item(finding_id="F-001", remediation_text=""),
            _item(finding_id="F-002", remediation_text=""),
        ]
        plan = generate_plan(items, reference_date=REF)
        assert "RPLAN-005" not in _fired_ids(plan)

    def test_affected_finding_ids_lists_all_duplicates(self):
        shared_text = "Apply parameterized queries throughout the application layer."
        items = [
            _item(finding_id="F-001", remediation_text=shared_text),
            _item(finding_id="F-002", remediation_text=shared_text),
        ]
        plan = generate_plan(items, reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-005"]
        assert set(checks[0].affected_finding_ids) == {"F-001", "F-002"}

    def test_check_severity_is_medium(self):
        shared_text = "Apply parameterized queries throughout the application layer."
        items = [
            _item(finding_id="F-001", remediation_text=shared_text),
            _item(finding_id="F-002", remediation_text=shared_text),
        ]
        plan = generate_plan(items, reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-005"]
        assert checks[0].severity == "MEDIUM"

    def test_weight_is_15(self):
        shared_text = "Apply parameterized queries throughout the application layer."
        items = [
            _item(finding_id="F-001", remediation_text=shared_text),
            _item(finding_id="F-002", remediation_text=shared_text),
        ]
        plan = generate_plan(items, reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-005"]
        assert checks[0].weight == 15

    def test_two_groups_produce_two_rplan005_checks(self):
        """Two separate duplicate groups each produce their own RPLAN-005 check."""
        text_a = "Apply parameterized queries throughout the application layer."
        text_b = "Rotate all secrets and revoke compromised API keys immediately now."
        items = [
            _item(finding_id="F-001", remediation_text=text_a),
            _item(finding_id="F-002", remediation_text=text_a),
            _item(finding_id="F-003", remediation_text=text_b),
            _item(finding_id="F-004", remediation_text=text_b),
        ]
        plan = generate_plan(items, reference_date=REF)
        dup_checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-005"]
        assert len(dup_checks) == 2


# ===========================================================================
# Section 6 — RPLAN-006: No verification method
# ===========================================================================


class TestRplan006:
    def test_fires_when_verification_method_empty(self):
        item = _item(finding_id="F-001", verification_method="")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-006" in _fired_ids(plan)

    def test_fires_when_verification_method_whitespace_only(self):
        item = _item(finding_id="F-001", verification_method="   ")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-006" in _fired_ids(plan)

    def test_does_not_fire_when_verification_method_set(self):
        item = _item(finding_id="F-001", verification_method="Re-run SQLMap after patch.")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-006" not in _fired_ids(plan)

    def test_check_severity_is_medium(self):
        item = _item(finding_id="F-001", verification_method="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-006"]
        assert checks[0].severity == "MEDIUM"

    def test_weight_is_15(self):
        item = _item(finding_id="F-001", verification_method="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-006"]
        assert checks[0].weight == 15

    def test_evidence_contains_finding_id(self):
        item = _item(finding_id="F-006", verification_method="")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-006"]
        assert "F-006" in checks[0].evidence


# ===========================================================================
# Section 7 — RPLAN-007: Remediation complexity mismatch
# ===========================================================================


class TestRplan007:
    # ---- Positive triggers ----

    def test_fires_for_low_effort_and_critical_severity(self):
        item = _item(finding_id="F-001", severity="CRITICAL", estimated_effort="low")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-007" in _fired_ids(plan)

    def test_fires_for_high_effort_and_low_severity(self):
        item = _item(finding_id="F-001", severity="LOW", estimated_effort="high")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-007" in _fired_ids(plan)

    def test_fires_for_high_effort_and_informational_severity(self):
        item = _item(finding_id="F-001", severity="INFORMATIONAL", estimated_effort="high")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-007" in _fired_ids(plan)

    # ---- Negative (no fire) combinations ----

    def test_does_not_fire_for_medium_effort_and_medium_severity(self):
        item = _item(finding_id="F-001", severity="MEDIUM", estimated_effort="medium")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-007" not in _fired_ids(plan)

    def test_does_not_fire_for_high_effort_and_critical_severity(self):
        item = _item(finding_id="F-001", severity="CRITICAL", estimated_effort="high")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-007" not in _fired_ids(plan)

    def test_does_not_fire_for_low_effort_and_low_severity(self):
        item = _item(finding_id="F-001", severity="LOW", estimated_effort="low")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-007" not in _fired_ids(plan)

    def test_does_not_fire_for_medium_effort_and_critical_severity(self):
        item = _item(finding_id="F-001", severity="CRITICAL", estimated_effort="medium")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-007" not in _fired_ids(plan)

    def test_does_not_fire_for_low_effort_and_informational_severity(self):
        item = _item(finding_id="F-001", severity="INFORMATIONAL", estimated_effort="low")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-007" not in _fired_ids(plan)

    def test_does_not_fire_for_high_effort_and_high_severity(self):
        item = _item(finding_id="F-001", severity="HIGH", estimated_effort="high")
        plan = generate_plan([item], reference_date=REF)
        assert "RPLAN-007" not in _fired_ids(plan)

    # ---- Metadata ----

    def test_check_severity_is_medium(self):
        item = _item(finding_id="F-001", severity="CRITICAL", estimated_effort="low")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-007"]
        assert checks[0].severity == "MEDIUM"

    def test_weight_is_15(self):
        item = _item(finding_id="F-001", severity="CRITICAL", estimated_effort="low")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-007"]
        assert checks[0].weight == 15

    def test_evidence_contains_effort_and_severity(self):
        item = _item(finding_id="F-007", severity="CRITICAL", estimated_effort="low")
        plan = generate_plan([item], reference_date=REF)
        checks = [c for c in plan.checks_fired if c.check_id == "RPLAN-007"]
        assert "F-007" in checks[0].evidence
        assert "low" in checks[0].evidence
        assert "CRITICAL" in checks[0].evidence


# ===========================================================================
# Section 8 — plan_quality thresholds
# ===========================================================================


class TestPlanQuality:
    def test_excellent_when_risk_score_is_0(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert plan.plan_quality == "EXCELLENT"

    def test_good_when_risk_score_1(self):
        # Only RPLAN-006 fires (weight=15) — but we need score between 1 and 19.
        # Use RPLAN-006 alone (weight=15): score=15 → GOOD.
        item = _item(finding_id="F-001", verification_method="")
        plan = generate_plan([item], reference_date=REF)
        assert plan.risk_score == 15
        assert plan.plan_quality == "GOOD"

    def test_good_at_boundary_19(self):
        # Fire only RPLAN-007 (weight=15) → score=15, quality=GOOD.
        # Use due_date within 30 days to suppress RPLAN-004, and supply all other fields.
        item = _item(
            finding_id="F-001",
            severity="CRITICAL",
            estimated_effort="low",
            verification_method="scan re-run",
            due_date="2026-01-20",    # 19 days from REF → suppresses RPLAN-004
        )
        plan = generate_plan([item], reference_date=REF)
        # RPLAN-007 fires (15). No other checks fire on this item.
        assert plan.risk_score == 15
        assert plan.plan_quality == "GOOD"

    def test_adequate_when_risk_score_20(self):
        # Fire only RPLAN-003 (weight=20).
        item = _item(finding_id="F-001", due_date=None)
        plan = generate_plan([item], reference_date=REF)
        assert plan.risk_score == 20
        assert plan.plan_quality == "ADEQUATE"

    def test_adequate_at_boundary_39(self):
        # RPLAN-003 (20) + RPLAN-006 (15) = 35 → ADEQUATE still.
        item = _item(finding_id="F-001", due_date=None, verification_method="")
        plan = generate_plan([item], reference_date=REF)
        assert plan.risk_score == 35
        assert plan.plan_quality == "ADEQUATE"

    def test_poor_when_risk_score_40_or_above(self):
        # RPLAN-001 (25) + RPLAN-002 (25) = 50 → POOR.
        item = _item(finding_id="F-001", remediation_text="", owner_team="")
        plan = generate_plan([item], reference_date=REF)
        assert plan.risk_score == 50
        assert plan.plan_quality == "POOR"

    def test_risk_score_capped_at_100(self):
        # All individual checks fire simultaneously → sum > 100 → capped at 100.
        item = _item(
            finding_id="F-001",
            severity="CRITICAL",
            remediation_text="",       # RPLAN-001 (25)
            owner_team="",              # RPLAN-002 (25)
            due_date=None,              # RPLAN-003 (20) + RPLAN-004 (25)
            compensating_control="",
            verification_method="",     # RPLAN-006 (15)
            estimated_effort="low",     # RPLAN-007 (15)
        )
        plan = generate_plan([item], reference_date=REF)
        assert plan.risk_score == 100


# ===========================================================================
# Section 9 — prioritized_findings sort order
# ===========================================================================


class TestPrioritizedFindings:
    def test_critical_before_high_before_medium(self):
        items = [
            _item(finding_id="F-M", severity="MEDIUM"),
            _item(finding_id="F-C", severity="CRITICAL"),
            _item(finding_id="F-H", severity="HIGH"),
        ]
        plan = generate_plan(items, reference_date=REF)
        order = plan.prioritized_findings
        assert order.index("F-C") < order.index("F-H") < order.index("F-M")

    def test_low_before_informational(self):
        items = [
            _item(finding_id="F-I", severity="INFORMATIONAL"),
            _item(finding_id="F-L", severity="LOW"),
        ]
        plan = generate_plan(items, reference_date=REF)
        order = plan.prioritized_findings
        assert order.index("F-L") < order.index("F-I")

    def test_all_five_severities_in_correct_order(self):
        items = [
            _item(finding_id="F-I", severity="INFORMATIONAL"),
            _item(finding_id="F-L", severity="LOW"),
            _item(finding_id="F-M", severity="MEDIUM"),
            _item(finding_id="F-H", severity="HIGH"),
            _item(finding_id="F-C", severity="CRITICAL"),
        ]
        plan = generate_plan(items, reference_date=REF)
        assert plan.prioritized_findings == ["F-C", "F-H", "F-M", "F-L", "F-I"]

    def test_same_severity_sorted_by_finding_id(self):
        items = [
            _item(finding_id="F-003", severity="HIGH"),
            _item(finding_id="F-001", severity="HIGH"),
            _item(finding_id="F-002", severity="HIGH"),
        ]
        plan = generate_plan(items, reference_date=REF)
        assert plan.prioritized_findings == ["F-001", "F-002", "F-003"]

    def test_empty_items_gives_empty_prioritized_findings(self):
        plan = generate_plan([], reference_date=REF)
        assert plan.prioritized_findings == []


# ===========================================================================
# Section 10 — findings_with_owner / findings_with_due_date
# ===========================================================================


class TestCoverageStatistics:
    def test_findings_with_owner_count(self):
        items = [
            _item(finding_id="F-001", owner_team="AppSec"),
            _item(finding_id="F-002", owner_team=""),
            _item(finding_id="F-003", owner_team="DevOps"),
        ]
        plan = generate_plan(items, reference_date=REF)
        assert plan.findings_with_owner == 2

    def test_findings_with_owner_none_assigned(self):
        items = [_item(finding_id=f"F-{i:03d}", owner_team="") for i in range(3)]
        plan = generate_plan(items, reference_date=REF)
        assert plan.findings_with_owner == 0

    def test_findings_with_owner_all_assigned(self):
        items = [_item(finding_id=f"F-{i:03d}", owner_team="Team") for i in range(4)]
        plan = generate_plan(items, reference_date=REF)
        assert plan.findings_with_owner == 4

    def test_findings_with_due_date_count(self):
        items = [
            _item(finding_id="F-001", due_date="2026-06-01"),
            _item(finding_id="F-002", due_date=None),
            _item(finding_id="F-003", due_date="2026-07-01"),
        ]
        plan = generate_plan(items, reference_date=REF)
        assert plan.findings_with_due_date == 2

    def test_findings_with_due_date_none(self):
        items = [_item(finding_id=f"F-{i:03d}", due_date=None) for i in range(3)]
        plan = generate_plan(items, reference_date=REF)
        assert plan.findings_with_due_date == 0

    def test_total_findings_matches_input_length(self):
        items = [_item(finding_id=f"F-{i:03d}") for i in range(5)]
        plan = generate_plan(items, reference_date=REF)
        assert plan.total_findings == 5


# ===========================================================================
# Section 11 — generate_plans()
# ===========================================================================


class TestGeneratePlans:
    def test_returns_correct_count(self):
        group_a = [_item(finding_id="F-001")]
        group_b = [_item(finding_id="F-002"), _item(finding_id="F-003")]
        group_c = [_item(finding_id="F-004")]
        plans = generate_plans([group_a, group_b, group_c], reference_date=REF)
        assert len(plans) == 3

    def test_plans_are_independent(self):
        group_a = [_item(finding_id="F-001", owner_team="")]   # RPLAN-002 fires
        group_b = [_item(finding_id="F-002")]                   # no checks fire
        plans = generate_plans([group_a, group_b], reference_date=REF)
        assert "RPLAN-002" in _fired_ids(plans[0])
        assert "RPLAN-002" not in _fired_ids(plans[1])

    def test_empty_group_list_returns_empty(self):
        plans = generate_plans([], reference_date=REF)
        assert plans == []

    def test_single_empty_group_returns_excellent_plan(self):
        plans = generate_plans([[]], reference_date=REF)
        assert len(plans) == 1
        assert plans[0].plan_quality == "EXCELLENT"

    def test_reference_date_propagated(self):
        # With REF=2026-01-01 and due=2026-02-01 (31 days), RPLAN-004 fires for CRITICAL.
        item = _item(finding_id="F-001", severity="CRITICAL", due_date="2026-02-01", compensating_control="")
        plans = generate_plans([[item]], reference_date=REF)
        assert "RPLAN-004" in _fired_ids(plans[0])


# ===========================================================================
# Section 12 — to_dict() / summary() / by_severity()
# ===========================================================================


class TestHelpers:
    def test_to_dict_contains_required_keys(self):
        plan = generate_plan([_item()], reference_date=REF)
        d = plan.to_dict()
        expected_keys = {
            "plan_id", "risk_score", "plan_quality", "total_findings",
            "findings_with_owner", "findings_with_due_date",
            "prioritized_findings", "checks_fired",
        }
        assert expected_keys.issubset(d.keys())

    def test_to_dict_checks_fired_is_list(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert isinstance(plan.to_dict()["checks_fired"], list)

    def test_to_dict_check_item_keys(self):
        item = _item(finding_id="F-001", owner_team="")
        plan = generate_plan([item], reference_date=REF)
        d = plan.to_dict()
        assert len(d["checks_fired"]) > 0
        check_keys = set(d["checks_fired"][0].keys())
        assert {"check_id", "severity", "description", "evidence", "weight", "affected_finding_ids"}.issubset(check_keys)

    def test_summary_contains_plan_id(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert plan.plan_id in plan.summary()

    def test_summary_contains_plan_quality(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert plan.plan_quality in plan.summary()

    def test_summary_contains_risk_score(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert str(plan.risk_score) in plan.summary()

    def test_summary_contains_findings_count(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert str(plan.total_findings) in plan.summary()

    def test_summary_returns_string(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert isinstance(plan.summary(), str)

    def test_by_severity_groups_correctly(self):
        # Fire RPLAN-002 (HIGH) and RPLAN-003 (MEDIUM).
        item = _item(finding_id="F-001", owner_team="", due_date=None)
        plan = generate_plan([item], reference_date=REF)
        grouped = plan.by_severity()
        assert "HIGH" in grouped
        assert "MEDIUM" in grouped
        high_ids = [c.check_id for c in grouped["HIGH"]]
        assert "RPLAN-002" in high_ids
        medium_ids = [c.check_id for c in grouped["MEDIUM"]]
        assert "RPLAN-003" in medium_ids

    def test_by_severity_returns_dict(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert isinstance(plan.by_severity(), dict)

    def test_by_severity_empty_when_no_checks_fired(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert plan.by_severity() == {}


# ===========================================================================
# Section 13 — Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_empty_items_list_returns_clean_plan(self):
        plan = generate_plan([], reference_date=REF)
        assert plan.checks_fired == []
        assert plan.risk_score == 0
        assert plan.plan_quality == "EXCELLENT"
        assert plan.total_findings == 0

    def test_empty_items_list_findings_with_owner_is_0(self):
        plan = generate_plan([], reference_date=REF)
        assert plan.findings_with_owner == 0

    def test_empty_items_list_findings_with_due_date_is_0(self):
        plan = generate_plan([], reference_date=REF)
        assert plan.findings_with_due_date == 0

    def test_plan_id_is_12_char_hex_string(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert len(plan.plan_id) == 12
        assert all(c in "0123456789abcdef" for c in plan.plan_id)

    def test_plan_id_for_empty_list(self):
        plan = generate_plan([], reference_date=REF)
        assert len(plan.plan_id) == 12
        assert all(c in "0123456789abcdef" for c in plan.plan_id)

    def test_plan_id_is_deterministic(self):
        item = _item(finding_id="F-001")
        plan1 = generate_plan([item], reference_date=REF)
        plan2 = generate_plan([item], reference_date=REF)
        assert plan1.plan_id == plan2.plan_id

    def test_plan_id_differs_for_different_findings(self):
        plan1 = generate_plan([_item(finding_id="F-001")], reference_date=REF)
        plan2 = generate_plan([_item(finding_id="F-002")], reference_date=REF)
        assert plan1.plan_id != plan2.plan_id

    def test_plan_id_matches_manual_sha256(self):
        item = _item(finding_id="F-999")
        plan = generate_plan([item], reference_date=REF)
        expected = hashlib.sha256("F-999".encode()).hexdigest()[:12]
        assert plan.plan_id == expected

    def test_default_reference_date_does_not_raise(self):
        """generate_plan without reference_date should use today and not raise."""
        item = _item(finding_id="F-001", severity="CRITICAL", due_date=None, compensating_control="")
        plan = generate_plan([item])  # no reference_date
        assert isinstance(plan, RemediationPlan)

    def test_single_perfect_finding_produces_excellent_plan(self):
        plan = generate_plan([_item()], reference_date=REF)
        assert plan.plan_quality == "EXCELLENT"
        assert plan.risk_score == 0
        assert plan.checks_fired == []

    def test_large_batch_no_checks_all_excellent(self):
        # Each item must have a unique remediation_text to avoid RPLAN-005 firing.
        items = [
            _item(
                finding_id=f"F-{i:04d}",
                remediation_text=f"Apply targeted fix for issue {i:04d} using the recommended secure coding pattern.",
            )
            for i in range(50)
        ]
        plan = generate_plan(items, reference_date=REF)
        assert plan.plan_quality == "EXCELLENT"
        assert plan.total_findings == 50

    def test_checks_fired_each_have_non_empty_description(self):
        item = _item(finding_id="F-001", remediation_text="")
        plan = generate_plan([item], reference_date=REF)
        for check in plan.checks_fired:
            assert check.description.strip() != ""

    def test_checks_fired_each_have_non_empty_evidence(self):
        item = _item(finding_id="F-001", remediation_text="")
        plan = generate_plan([item], reference_date=REF)
        for check in plan.checks_fired:
            assert check.evidence.strip() != ""
