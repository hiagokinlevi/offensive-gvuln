# test_finding_quality_checker.py
# Cyber Port — tests for pentest_governance.finding_quality_checker
#
# Copyright (c) 2026 hiagokinlevi
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# Run with:  python -m pytest tests/test_finding_quality_checker.py -q

from __future__ import annotations

import sys
import os

# Allow imports from project root without an installed package.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pentest_governance.finding_quality_checker import (
    FINDQFinding,
    FINDQResult,
    PentestFinding,
    _GENERIC_TITLES,
    _MIN_TITLE_LENGTH,
    check,
    check_many,
    report_summary,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_clean_finding(**overrides) -> PentestFinding:
    """Return a fully-populated, no-issue PentestFinding; override any field."""
    defaults = dict(
        finding_id="F-001",
        title="Reflected XSS via search parameter",  # 34 chars, not in generic list
        severity="MEDIUM",
        cvss_score=5.0,
        cwe_id="CWE-79",
        affected_asset="app.example.com/search",
        evidence="Payload: <script>alert(1)</script>",
        remediation="Encode all output using htmlspecialchars().",
        effort_days=3,
    )
    defaults.update(overrides)
    return PentestFinding(**defaults)


def _fired_ids(result: FINDQResult):
    """Return sorted list of check_ids that fired."""
    return sorted(qf.check_id for qf in result.quality_findings)


# ===========================================================================
# FINDQ-001 — Missing CVSS base score
# ===========================================================================


def test_findq001_fires_when_cvss_is_none():
    f = _make_clean_finding(cvss_score=None)
    r = check(f)
    assert "FINDQ-001" in _fired_ids(r)


def test_findq001_does_not_fire_when_cvss_is_zero():
    f = _make_clean_finding(cvss_score=0.0)
    r = check(f)
    assert "FINDQ-001" not in _fired_ids(r)


def test_findq001_does_not_fire_when_cvss_is_ten():
    f = _make_clean_finding(cvss_score=10.0)
    r = check(f)
    assert "FINDQ-001" not in _fired_ids(r)


def test_findq001_does_not_fire_when_cvss_is_midrange():
    f = _make_clean_finding(cvss_score=7.5)
    r = check(f)
    assert "FINDQ-001" not in _fired_ids(r)


def test_findq001_severity_label_is_high():
    f = _make_clean_finding(cvss_score=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-001")
    assert qf.severity == "HIGH"


def test_findq001_weight_is_25():
    f = _make_clean_finding(cvss_score=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-001")
    assert qf.weight == 25


def test_findq001_detail_mentions_finding_id():
    f = _make_clean_finding(finding_id="ABC-999", cvss_score=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-001")
    assert "ABC-999" in qf.detail


# ===========================================================================
# FINDQ-002 — Missing proof-of-concept or evidence
# ===========================================================================


def test_findq002_fires_when_evidence_is_none():
    f = _make_clean_finding(evidence=None)
    r = check(f)
    assert "FINDQ-002" in _fired_ids(r)


def test_findq002_fires_when_evidence_is_empty_string():
    f = _make_clean_finding(evidence="")
    r = check(f)
    assert "FINDQ-002" in _fired_ids(r)


def test_findq002_fires_when_evidence_is_whitespace_only():
    f = _make_clean_finding(evidence="   ")
    r = check(f)
    assert "FINDQ-002" in _fired_ids(r)


def test_findq002_does_not_fire_when_evidence_is_present():
    f = _make_clean_finding(evidence="See screenshot attached.")
    r = check(f)
    assert "FINDQ-002" not in _fired_ids(r)


def test_findq002_does_not_fire_when_evidence_is_single_char():
    f = _make_clean_finding(evidence="x")
    r = check(f)
    assert "FINDQ-002" not in _fired_ids(r)


def test_findq002_severity_label_is_high():
    f = _make_clean_finding(evidence=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-002")
    assert qf.severity == "HIGH"


def test_findq002_weight_is_25():
    f = _make_clean_finding(evidence=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-002")
    assert qf.weight == 25


def test_findq002_fires_independently_of_cvss():
    # CVSS is set but evidence is missing — only FINDQ-002 should fire (plus others)
    f = _make_clean_finding(cvss_score=8.5, evidence=None)
    r = check(f)
    assert "FINDQ-001" not in _fired_ids(r)
    assert "FINDQ-002" in _fired_ids(r)


# ===========================================================================
# FINDQ-003 — Critical/High finding lacks remediation steps
# ===========================================================================


def test_findq003_fires_for_critical_with_no_remediation():
    f = _make_clean_finding(severity="CRITICAL", remediation=None)
    r = check(f)
    assert "FINDQ-003" in _fired_ids(r)


def test_findq003_fires_for_high_with_no_remediation():
    f = _make_clean_finding(severity="HIGH", remediation=None)
    r = check(f)
    assert "FINDQ-003" in _fired_ids(r)


def test_findq003_fires_for_high_with_empty_remediation():
    f = _make_clean_finding(severity="HIGH", remediation="")
    r = check(f)
    assert "FINDQ-003" in _fired_ids(r)


def test_findq003_fires_for_high_with_whitespace_remediation():
    f = _make_clean_finding(severity="HIGH", remediation="   ")
    r = check(f)
    assert "FINDQ-003" in _fired_ids(r)


def test_findq003_does_not_fire_for_medium_with_no_remediation():
    # MEDIUM severity must NOT trigger FINDQ-003
    f = _make_clean_finding(severity="MEDIUM", remediation=None)
    r = check(f)
    assert "FINDQ-003" not in _fired_ids(r)


def test_findq003_does_not_fire_for_low_with_no_remediation():
    f = _make_clean_finding(severity="LOW", remediation=None)
    r = check(f)
    assert "FINDQ-003" not in _fired_ids(r)


def test_findq003_does_not_fire_for_info_with_no_remediation():
    f = _make_clean_finding(severity="INFO", remediation=None)
    r = check(f)
    assert "FINDQ-003" not in _fired_ids(r)


def test_findq003_does_not_fire_when_critical_has_remediation():
    f = _make_clean_finding(severity="CRITICAL", remediation="Patch now.")
    r = check(f)
    assert "FINDQ-003" not in _fired_ids(r)


def test_findq003_severity_label_is_critical():
    f = _make_clean_finding(severity="CRITICAL", remediation=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-003")
    assert qf.severity == "CRITICAL"


def test_findq003_weight_is_40():
    f = _make_clean_finding(severity="CRITICAL", remediation=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-003")
    assert qf.weight == 40


def test_findq003_detail_mentions_severity():
    f = _make_clean_finding(severity="HIGH", remediation=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-003")
    assert "HIGH" in qf.detail


# ===========================================================================
# FINDQ-004 — Finding title is too generic or too short
# ===========================================================================


def test_findq004_fires_for_title_shorter_than_20_chars():
    # 15 chars, not in generic list
    f = _make_clean_finding(title="Short vuln title")  # 16 chars
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_title_exactly_19_chars():
    title = "A" * 19
    f = _make_clean_finding(title=title)
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_does_not_fire_for_title_exactly_20_chars():
    title = "A" * 20  # length == _MIN_TITLE_LENGTH, NOT less than
    f = _make_clean_finding(title=title)
    r = check(f)
    assert "FINDQ-004" not in _fired_ids(r)


def test_findq004_does_not_fire_for_title_longer_than_20_chars():
    f = _make_clean_finding(title="Stored XSS in comment section via markup")
    r = check(f)
    assert "FINDQ-004" not in _fired_ids(r)


def test_findq004_fires_for_generic_title_sql_injection():
    f = _make_clean_finding(title="SQL Injection")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_xss():
    f = _make_clean_finding(title="XSS")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_csrf():
    f = _make_clean_finding(title="CSRF")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_rce():
    f = _make_clean_finding(title="RCE")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_broken_authentication():
    f = _make_clean_finding(title="Broken Authentication")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_idor():
    f = _make_clean_finding(title="IDOR")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_case_insensitive():
    f = _make_clean_finding(title="sql injection")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_ssrf():
    f = _make_clean_finding(title="SSRF")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_lfi():
    f = _make_clean_finding(title="LFI")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_rfi():
    f = _make_clean_finding(title="RFI")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_command_injection():
    f = _make_clean_finding(title="Command Injection")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_path_traversal():
    f = _make_clean_finding(title="Path Traversal")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_fires_for_generic_title_open_redirect():
    f = _make_clean_finding(title="Open Redirect")
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_does_not_fire_for_specific_long_generic_like_title():
    # Contains "sql injection" as a substring but is NOT an exact match
    f = _make_clean_finding(title="Blind SQL Injection in login endpoint")
    r = check(f)
    assert "FINDQ-004" not in _fired_ids(r)


def test_findq004_fires_for_title_with_only_whitespace_padded_short_content():
    # Title with leading spaces: stripped length < 20
    f = _make_clean_finding(title="   short   ")  # stripped = "short" = 5 chars
    r = check(f)
    assert "FINDQ-004" in _fired_ids(r)


def test_findq004_severity_label_is_medium():
    f = _make_clean_finding(title="XSS")
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-004")
    assert qf.severity == "MEDIUM"


def test_findq004_weight_is_15():
    f = _make_clean_finding(title="XSS")
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-004")
    assert qf.weight == 15


# ===========================================================================
# FINDQ-005 — Missing affected asset or component
# ===========================================================================


def test_findq005_fires_when_affected_asset_is_none():
    f = _make_clean_finding(affected_asset=None)
    r = check(f)
    assert "FINDQ-005" in _fired_ids(r)


def test_findq005_fires_when_affected_asset_is_empty():
    f = _make_clean_finding(affected_asset="")
    r = check(f)
    assert "FINDQ-005" in _fired_ids(r)


def test_findq005_fires_when_affected_asset_is_whitespace():
    f = _make_clean_finding(affected_asset="   ")
    r = check(f)
    assert "FINDQ-005" in _fired_ids(r)


def test_findq005_does_not_fire_when_affected_asset_is_present():
    f = _make_clean_finding(affected_asset="api.example.com/login")
    r = check(f)
    assert "FINDQ-005" not in _fired_ids(r)


def test_findq005_severity_label_is_high():
    f = _make_clean_finding(affected_asset=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-005")
    assert qf.severity == "HIGH"


def test_findq005_weight_is_20():
    f = _make_clean_finding(affected_asset=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-005")
    assert qf.weight == 20


def test_findq005_detail_mentions_finding_id():
    f = _make_clean_finding(finding_id="F-777", affected_asset=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-005")
    assert "F-777" in qf.detail


# ===========================================================================
# FINDQ-006 — Missing CWE classification
# ===========================================================================


def test_findq006_fires_when_cwe_id_is_none():
    f = _make_clean_finding(cwe_id=None)
    r = check(f)
    assert "FINDQ-006" in _fired_ids(r)


def test_findq006_fires_when_cwe_id_is_empty():
    f = _make_clean_finding(cwe_id="")
    r = check(f)
    assert "FINDQ-006" in _fired_ids(r)


def test_findq006_fires_when_cwe_id_is_whitespace():
    f = _make_clean_finding(cwe_id="  ")
    r = check(f)
    assert "FINDQ-006" in _fired_ids(r)


def test_findq006_does_not_fire_when_cwe_id_is_set():
    f = _make_clean_finding(cwe_id="CWE-89")
    r = check(f)
    assert "FINDQ-006" not in _fired_ids(r)


def test_findq006_does_not_fire_for_any_nonempty_cwe():
    f = _make_clean_finding(cwe_id="CWE-1234")
    r = check(f)
    assert "FINDQ-006" not in _fired_ids(r)


def test_findq006_severity_label_is_medium():
    f = _make_clean_finding(cwe_id=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-006")
    assert qf.severity == "MEDIUM"


def test_findq006_weight_is_15():
    f = _make_clean_finding(cwe_id=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-006")
    assert qf.weight == 15


# ===========================================================================
# FINDQ-007 — Critical/High finding lacks remediation effort estimate
# ===========================================================================


def test_findq007_fires_for_critical_with_no_effort():
    f = _make_clean_finding(severity="CRITICAL", effort_days=None)
    r = check(f)
    assert "FINDQ-007" in _fired_ids(r)


def test_findq007_fires_for_high_with_no_effort():
    f = _make_clean_finding(severity="HIGH", effort_days=None)
    r = check(f)
    assert "FINDQ-007" in _fired_ids(r)


def test_findq007_does_not_fire_for_medium_with_no_effort():
    f = _make_clean_finding(severity="MEDIUM", effort_days=None)
    r = check(f)
    assert "FINDQ-007" not in _fired_ids(r)


def test_findq007_does_not_fire_for_low_with_no_effort():
    f = _make_clean_finding(severity="LOW", effort_days=None)
    r = check(f)
    assert "FINDQ-007" not in _fired_ids(r)


def test_findq007_does_not_fire_for_info_with_no_effort():
    f = _make_clean_finding(severity="INFO", effort_days=None)
    r = check(f)
    assert "FINDQ-007" not in _fired_ids(r)


def test_findq007_does_not_fire_when_high_has_effort():
    f = _make_clean_finding(severity="HIGH", effort_days=5)
    r = check(f)
    assert "FINDQ-007" not in _fired_ids(r)


def test_findq007_does_not_fire_when_critical_has_effort_zero():
    # effort_days=0 is a value (zero-day fix), not None
    f = _make_clean_finding(severity="CRITICAL", effort_days=0)
    r = check(f)
    assert "FINDQ-007" not in _fired_ids(r)


def test_findq007_severity_label_is_medium():
    f = _make_clean_finding(severity="HIGH", effort_days=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-007")
    assert qf.severity == "MEDIUM"


def test_findq007_weight_is_15():
    f = _make_clean_finding(severity="HIGH", effort_days=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-007")
    assert qf.weight == 15


def test_findq007_detail_mentions_severity():
    f = _make_clean_finding(severity="CRITICAL", effort_days=None)
    r = check(f)
    qf = next(x for x in r.quality_findings if x.check_id == "FINDQ-007")
    assert "CRITICAL" in qf.detail


# ===========================================================================
# Risk score and quality grade
# ===========================================================================


def test_risk_score_zero_for_clean_finding():
    f = _make_clean_finding()
    r = check(f)
    assert r.risk_score == 0


def test_quality_grade_pass_for_zero_risk():
    f = _make_clean_finding()
    r = check(f)
    assert r.quality_grade == "PASS"


def test_quality_grade_warn_for_risk_score_15():
    # Only FINDQ-004 fires (weight=15)
    f = _make_clean_finding(title="XSS")  # short+generic → FINDQ-004 w=15
    r = check(f)
    assert r.risk_score == 15
    assert r.quality_grade == "WARN"


def test_quality_grade_warn_for_risk_score_30():
    # FINDQ-004 (15) + FINDQ-006 (15) = 30 → WARN boundary
    f = _make_clean_finding(title="XSS", cwe_id=None)
    r = check(f)
    assert r.risk_score == 30
    assert r.quality_grade == "WARN"


def test_quality_grade_fail_for_risk_score_31():
    # FINDQ-004 (15) + FINDQ-006 (15) + FINDQ-007 (15) = 45 — but HIGH needed for 007
    # Use HIGH + missing cwe + generic title + no effort = 15+15+15=45
    f = _make_clean_finding(severity="HIGH", title="XSS", cwe_id=None, effort_days=None)
    r = check(f)
    assert r.risk_score > 30
    assert r.quality_grade == "FAIL"


def test_risk_score_capped_at_100():
    # Fire all 7 checks: weights = 25+25+40+15+20+15+15 = 155 → capped at 100
    f = PentestFinding(
        finding_id="F-MAX",
        title="XSS",           # FINDQ-004
        severity="CRITICAL",   # enables FINDQ-003 and FINDQ-007
        cvss_score=None,       # FINDQ-001
        cwe_id=None,           # FINDQ-006
        affected_asset=None,   # FINDQ-005
        evidence=None,         # FINDQ-002
        remediation=None,      # FINDQ-003
        effort_days=None,      # FINDQ-007
    )
    r = check(f)
    assert r.risk_score == 100
    assert r.quality_grade == "FAIL"


def test_risk_score_sum_of_fired_check_weights():
    # FINDQ-001 (25) + FINDQ-002 (25) = 50
    f = _make_clean_finding(cvss_score=None, evidence=None)
    r = check(f)
    assert r.risk_score == 50


def test_risk_score_single_check_findq003():
    # Only FINDQ-003 fires (weight=40)
    f = _make_clean_finding(severity="HIGH", remediation=None)
    r = check(f)
    assert "FINDQ-003" in _fired_ids(r)
    fired = _fired_ids(r)
    assert r.risk_score == sum(
        qf.weight for qf in r.quality_findings
    )


def test_quality_grade_fail_for_risk_score_above_30():
    # All checks fired → grade must be FAIL
    f = PentestFinding(
        finding_id="F-FAIL",
        title="RCE",
        severity="HIGH",
        cvss_score=None,
        cwe_id=None,
        affected_asset=None,
        evidence=None,
        remediation=None,
        effort_days=None,
    )
    r = check(f)
    assert r.quality_grade == "FAIL"


# ===========================================================================
# FINDQResult helpers: to_dict, summary, by_severity
# ===========================================================================


def test_to_dict_contains_expected_keys():
    f = _make_clean_finding(cvss_score=None)
    r = check(f)
    d = r.to_dict()
    assert "finding_id" in d
    assert "finding_title" in d
    assert "risk_score" in d
    assert "quality_grade" in d
    assert "quality_findings" in d


def test_to_dict_quality_findings_is_list():
    f = _make_clean_finding(cvss_score=None)
    r = check(f)
    d = r.to_dict()
    assert isinstance(d["quality_findings"], list)


def test_to_dict_finding_entry_has_check_id():
    f = _make_clean_finding(cvss_score=None)
    r = check(f)
    d = r.to_dict()
    entry = next(e for e in d["quality_findings"] if e["check_id"] == "FINDQ-001")
    assert entry["check_id"] == "FINDQ-001"


def test_to_dict_clean_finding_has_empty_quality_findings():
    f = _make_clean_finding()
    r = check(f)
    d = r.to_dict()
    assert d["quality_findings"] == []
    assert d["risk_score"] == 0
    assert d["quality_grade"] == "PASS"


def test_summary_contains_finding_id():
    f = _make_clean_finding(finding_id="F-TEST")
    r = check(f)
    s = r.summary()
    assert "F-TEST" in s


def test_summary_contains_quality_grade():
    f = _make_clean_finding()
    r = check(f)
    s = r.summary()
    assert "PASS" in s


def test_summary_contains_risk_score():
    f = _make_clean_finding(cvss_score=None)
    r = check(f)
    s = r.summary()
    assert str(r.risk_score) in s


def test_summary_is_string():
    f = _make_clean_finding()
    r = check(f)
    assert isinstance(r.summary(), str)


def test_by_severity_groups_correctly():
    # Fire FINDQ-001 (HIGH) and FINDQ-004 (MEDIUM)
    f = _make_clean_finding(cvss_score=None, title="XSS")
    r = check(f)
    grouped = r.by_severity()
    high_ids = [qf.check_id for qf in grouped.get("HIGH", [])]
    medium_ids = [qf.check_id for qf in grouped.get("MEDIUM", [])]
    assert "FINDQ-001" in high_ids
    assert "FINDQ-004" in medium_ids


def test_by_severity_returns_dict():
    f = _make_clean_finding()
    r = check(f)
    assert isinstance(r.by_severity(), dict)


def test_by_severity_empty_for_clean_finding():
    f = _make_clean_finding()
    r = check(f)
    assert r.by_severity() == {}


def test_by_severity_critical_group_for_findq003():
    f = _make_clean_finding(severity="CRITICAL", remediation=None)
    r = check(f)
    grouped = r.by_severity()
    critical_ids = [qf.check_id for qf in grouped.get("CRITICAL", [])]
    assert "FINDQ-003" in critical_ids


# ===========================================================================
# check_many
# ===========================================================================


def test_check_many_returns_list():
    findings = [_make_clean_finding(finding_id=f"F-{i:03d}") for i in range(5)]
    results = check_many(findings)
    assert isinstance(results, list)


def test_check_many_length_matches_input():
    findings = [_make_clean_finding(finding_id=f"F-{i:03d}") for i in range(7)]
    results = check_many(findings)
    assert len(results) == 7


def test_check_many_empty_list():
    results = check_many([])
    assert results == []


def test_check_many_order_preserved():
    ids = ["ALPHA", "BETA", "GAMMA"]
    findings = [_make_clean_finding(finding_id=fid) for fid in ids]
    results = check_many(findings)
    assert [r.finding_id for r in results] == ids


def test_check_many_each_result_is_findq_result():
    findings = [_make_clean_finding()]
    results = check_many(findings)
    assert isinstance(results[0], FINDQResult)


def test_check_many_mixed_severities():
    findings = [
        _make_clean_finding(finding_id="F-C", severity="CRITICAL", remediation=None, effort_days=None),
        _make_clean_finding(finding_id="F-M", severity="MEDIUM"),
    ]
    results = check_many(findings)
    critical_result = next(r for r in results if r.finding_id == "F-C")
    medium_result = next(r for r in results if r.finding_id == "F-M")
    assert "FINDQ-003" in _fired_ids(critical_result)
    assert "FINDQ-003" not in _fired_ids(medium_result)


# ===========================================================================
# report_summary
# ===========================================================================


def test_report_summary_total_count():
    findings = [_make_clean_finding(finding_id=f"F-{i}") for i in range(4)]
    results = check_many(findings)
    s = report_summary(results)
    assert s["total"] == 4


def test_report_summary_pass_count():
    findings = [_make_clean_finding(finding_id=f"F-{i}") for i in range(3)]
    results = check_many(findings)
    s = report_summary(results)
    assert s["pass_count"] == 3
    assert s["warn_count"] == 0
    assert s["fail_count"] == 0


def test_report_summary_fail_count():
    bad = PentestFinding(
        finding_id="F-BAD",
        title="RCE",
        severity="CRITICAL",
        cvss_score=None,
        cwe_id=None,
        affected_asset=None,
        evidence=None,
        remediation=None,
        effort_days=None,
    )
    results = check_many([bad])
    s = report_summary(results)
    assert s["fail_count"] == 1
    assert s["pass_count"] == 0


def test_report_summary_warn_count():
    # FINDQ-006 only (weight=15) → WARN
    warn_finding = _make_clean_finding(cwe_id=None)
    results = check_many([warn_finding])
    s = report_summary(results)
    assert s["warn_count"] == 1


def test_report_summary_common_issues_contains_check_ids():
    bad = _make_clean_finding(cvss_score=None, evidence=None)
    results = check_many([bad])
    s = report_summary(results)
    assert "FINDQ-001" in s["common_issues"]
    assert "FINDQ-002" in s["common_issues"]


def test_report_summary_common_issues_counts_correctly():
    findings = [_make_clean_finding(finding_id=f"F-{i}", cvss_score=None) for i in range(4)]
    results = check_many(findings)
    s = report_summary(results)
    assert s["common_issues"]["FINDQ-001"] == 4


def test_report_summary_avg_risk_score_zero_for_clean():
    findings = [_make_clean_finding(finding_id=f"F-{i}") for i in range(5)]
    results = check_many(findings)
    s = report_summary(results)
    assert s["avg_risk_score"] == 0.0


def test_report_summary_avg_risk_score_computed():
    # Two findings: one clean (0) and one with FINDQ-001 (25) → avg = 12.5
    clean = _make_clean_finding(finding_id="F-CLEAN")
    dirty = _make_clean_finding(finding_id="F-DIRTY", cvss_score=None)
    results = check_many([clean, dirty])
    s = report_summary(results)
    assert s["avg_risk_score"] == 12.5


def test_report_summary_empty_list():
    s = report_summary([])
    assert s["total"] == 0
    assert s["pass_count"] == 0
    assert s["warn_count"] == 0
    assert s["fail_count"] == 0
    assert s["avg_risk_score"] == 0.0
    assert s["common_issues"] == {}


def test_report_summary_contains_required_keys():
    results = check_many([_make_clean_finding()])
    s = report_summary(results)
    for key in ("total", "pass_count", "warn_count", "fail_count", "avg_risk_score", "common_issues"):
        assert key in s


# ===========================================================================
# Integration / combined scenarios
# ===========================================================================


def test_all_seven_checks_fire_simultaneously():
    f = PentestFinding(
        finding_id="F-ALL",
        title="XSS",           # FINDQ-004 (short + generic)
        severity="CRITICAL",   # allows FINDQ-003 + FINDQ-007
        cvss_score=None,       # FINDQ-001
        cwe_id=None,           # FINDQ-006
        affected_asset=None,   # FINDQ-005
        evidence=None,         # FINDQ-002
        remediation=None,      # FINDQ-003
        effort_days=None,      # FINDQ-007
    )
    r = check(f)
    assert sorted(_fired_ids(r)) == [
        "FINDQ-001", "FINDQ-002", "FINDQ-003",
        "FINDQ-004", "FINDQ-005", "FINDQ-006", "FINDQ-007",
    ]


def test_no_checks_fire_for_perfect_high_finding():
    f = PentestFinding(
        finding_id="F-PERFECT",
        title="Blind SQL Injection in login endpoint via username parameter",
        severity="HIGH",
        cvss_score=8.8,
        cwe_id="CWE-89",
        affected_asset="app.example.com/api/login",
        evidence="sqlmap -u 'https://app.example.com/api/login' --dbs",
        remediation="Use parameterized queries / prepared statements.",
        effort_days=2,
    )
    r = check(f)
    assert _fired_ids(r) == []
    assert r.risk_score == 0
    assert r.quality_grade == "PASS"


def test_medium_severity_with_no_remediation_no_effort_only_fires_non_severity_checks():
    # MEDIUM should NOT trigger FINDQ-003 or FINDQ-007
    f = _make_clean_finding(severity="MEDIUM", remediation=None, effort_days=None)
    r = check(f)
    assert "FINDQ-003" not in _fired_ids(r)
    assert "FINDQ-007" not in _fired_ids(r)


def test_finding_id_propagated_to_result():
    f = _make_clean_finding(finding_id="MY-UNIQUE-ID")
    r = check(f)
    assert r.finding_id == "MY-UNIQUE-ID"


def test_finding_title_propagated_to_result():
    title = "Stored XSS in user profile bio field"
    f = _make_clean_finding(title=title)
    r = check(f)
    assert r.finding_title == title


def test_quality_findings_list_items_are_findq_finding_instances():
    f = _make_clean_finding(cvss_score=None)
    r = check(f)
    for qf in r.quality_findings:
        assert isinstance(qf, FINDQFinding)


def test_generic_titles_constant_includes_all_required_entries():
    required = {
        "sql injection", "xss", "csrf", "rce", "broken authentication",
        "idor", "ssrf", "lfi", "rfi", "command injection",
        "path traversal", "open redirect",
    }
    assert required.issubset(_GENERIC_TITLES)


def test_min_title_length_constant_is_20():
    assert _MIN_TITLE_LENGTH == 20


def test_check_many_all_failing_finding_ids_preserved():
    ids = [f"VULN-{i:04d}" for i in range(10)]
    findings = [
        PentestFinding(
            finding_id=fid,
            title="XSS",
            severity="HIGH",
            cvss_score=None,
            cwe_id=None,
            affected_asset=None,
            evidence=None,
            remediation=None,
            effort_days=None,
        )
        for fid in ids
    ]
    results = check_many(findings)
    assert [r.finding_id for r in results] == ids


def test_report_summary_common_issues_is_dict():
    results = check_many([_make_clean_finding(cvss_score=None)])
    s = report_summary(results)
    assert isinstance(s["common_issues"], dict)


def test_to_dict_each_quality_finding_has_weight():
    f = _make_clean_finding(cvss_score=None)
    r = check(f)
    d = r.to_dict()
    for entry in d["quality_findings"]:
        assert "weight" in entry
        assert isinstance(entry["weight"], int)


def test_findq003_and_findq007_both_fire_for_critical_no_remediation_no_effort():
    f = _make_clean_finding(severity="CRITICAL", remediation=None, effort_days=None)
    r = check(f)
    assert "FINDQ-003" in _fired_ids(r)
    assert "FINDQ-007" in _fired_ids(r)


def test_risk_score_equals_sum_of_weights():
    f = _make_clean_finding(cvss_score=None, cwe_id=None)  # 25 + 15 = 40
    r = check(f)
    expected = sum(qf.weight for qf in r.quality_findings)
    assert r.risk_score == expected


def test_effort_days_zero_does_not_trigger_findq007():
    # effort_days=0 is explicitly set (not None) → should not fire
    f = _make_clean_finding(severity="HIGH", effort_days=0)
    r = check(f)
    assert "FINDQ-007" not in _fired_ids(r)


def test_cvss_score_of_zero_does_not_trigger_findq001():
    f = _make_clean_finding(cvss_score=0.0)
    r = check(f)
    assert "FINDQ-001" not in _fired_ids(r)
