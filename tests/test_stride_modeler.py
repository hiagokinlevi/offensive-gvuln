"""
Tests for pentest_governance/stride_modeler.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from pentest_governance.stride_modeler import (
    Component,
    DataFlow,
    StrideCategory,
    StrideModeler,
    StrideReport,
    ThreatFinding,
    ThreatSeverity,
)


# ===========================================================================
# Helpers
# ===========================================================================

def _modeler(**kwargs) -> StrideModeler:
    return StrideModeler(**kwargs)


def _comp(**kwargs) -> Component:
    defaults = dict(name="TestComp", component_type="api",
                    is_authenticated=True, stores_sensitive_data=False,
                    is_publicly_accessible=False, has_logging=True)
    defaults.update(kwargs)
    return Component(**defaults)


def _flow(**kwargs) -> DataFlow:
    defaults = dict(name="TestFlow", source="A", destination="B",
                    is_encrypted=True, carries_credentials=False,
                    crosses_trust_boundary=False, is_logged=True)
    defaults.update(kwargs)
    return DataFlow(**defaults)


def _ids(report: StrideReport) -> set[str]:
    return {f.threat_id for f in report.findings}


# ===========================================================================
# ThreatFinding
# ===========================================================================

class TestThreatFinding:
    def _finding(self) -> ThreatFinding:
        return ThreatFinding(
            threat_id="STR-S-001",
            category=StrideCategory.SPOOFING,
            severity=ThreatSeverity.HIGH,
            target="WebAPI",
            title="Test threat",
            description="Detailed description",
            mitigation="Fix this",
            risk_score=35,
        )

    def test_to_dict_has_required_keys(self):
        d = self._finding().to_dict()
        for k in ("threat_id", "category", "severity", "target",
                  "title", "description", "mitigation", "risk_score"):
            assert k in d

    def test_category_serialized_as_string(self):
        assert self._finding().to_dict()["category"] == "SPOOFING"

    def test_severity_serialized_as_string(self):
        assert self._finding().to_dict()["severity"] == "HIGH"

    def test_risk_score_present(self):
        assert self._finding().to_dict()["risk_score"] == 35


# ===========================================================================
# StrideReport
# ===========================================================================

class TestStrideReport:
    def _report(self) -> StrideReport:
        f1 = ThreatFinding("STR-S-001", StrideCategory.SPOOFING, ThreatSeverity.CRITICAL,
                           "A", "t", "d", "m", 50)
        f2 = ThreatFinding("STR-T-001", StrideCategory.TAMPERING, ThreatSeverity.HIGH,
                           "B", "t", "d", "m", 35)
        f3 = ThreatFinding("STR-R-001", StrideCategory.REPUDIATION, ThreatSeverity.LOW,
                           "C", "t", "d", "m", 10)
        return StrideReport(findings=[f1, f2, f3], total_risk_score=95)

    def test_total_findings(self):
        assert self._report().total_findings == 3

    def test_critical_findings(self):
        assert len(self._report().critical_findings) == 1

    def test_high_findings(self):
        assert len(self._report().high_findings) == 1

    def test_findings_by_category(self):
        r = self._report()
        assert len(r.findings_by_category(StrideCategory.SPOOFING)) == 1
        assert len(r.findings_by_category(StrideCategory.DENIAL_OF_SERVICE)) == 0

    def test_findings_for_target(self):
        r = self._report()
        assert len(r.findings_for_target("A")) == 1
        assert len(r.findings_for_target("Z")) == 0

    def test_summary_contains_finding_count(self):
        assert "3" in self._report().summary()

    def test_summary_contains_risk_score(self):
        assert "95" in self._report().summary()

    def test_to_dict_keys(self):
        d = self._report().to_dict()
        for k in ("total_findings", "total_risk_score", "critical", "high",
                  "generated_at", "findings"):
            assert k in d

    def test_to_dict_findings_are_dicts(self):
        d = self._report().to_dict()
        assert all(isinstance(f, dict) for f in d["findings"])

    def test_empty_report(self):
        r = StrideReport()
        assert r.total_findings == 0
        assert r.total_risk_score == 0


# ===========================================================================
# STR-S-001: Unauthenticated component
# ===========================================================================

class TestSTRS001:
    def test_fires_for_unauthenticated_api(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=False, component_type="api"))
        r = m.analyze()
        assert "STR-S-001" in _ids(r)

    def test_not_fired_when_authenticated(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=True))
        r = m.analyze()
        assert "STR-S-001" not in _ids(r)

    def test_severity_is_high(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=False))
        r = m.analyze()
        f = next(f for f in r.findings if f.threat_id == "STR-S-001")
        assert f.severity == ThreatSeverity.HIGH


# ===========================================================================
# STR-T-001: Unauthenticated database write
# ===========================================================================

class TestSTRT001:
    def test_fires_for_unauthenticated_database(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=False, component_type="database"))
        r = m.analyze()
        assert "STR-T-001" in _ids(r)

    def test_not_fired_for_authenticated_database(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=True, component_type="database"))
        r = m.analyze()
        assert "STR-T-001" not in _ids(r)

    def test_not_fired_for_unauthenticated_api(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=False, component_type="api"))
        r = m.analyze()
        assert "STR-T-001" not in _ids(r)

    def test_severity_is_critical(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=False, component_type="database"))
        r = m.analyze()
        f = next(f for f in r.findings if f.threat_id == "STR-T-001")
        assert f.severity == ThreatSeverity.CRITICAL


# ===========================================================================
# STR-T-002: Sensitive data store without integrity
# ===========================================================================

class TestSTRT002:
    def test_fires_for_database_with_sensitive_data(self):
        m = _modeler()
        m.add_component(_comp(stores_sensitive_data=True, component_type="database"))
        r = m.analyze()
        assert "STR-T-002" in _ids(r)

    def test_fires_for_service_with_sensitive_data(self):
        m = _modeler()
        m.add_component(_comp(stores_sensitive_data=True, component_type="service"))
        r = m.analyze()
        assert "STR-T-002" in _ids(r)

    def test_not_fired_without_sensitive_data(self):
        m = _modeler()
        m.add_component(_comp(stores_sensitive_data=False, component_type="database"))
        r = m.analyze()
        assert "STR-T-002" not in _ids(r)


# ===========================================================================
# STR-R-001: No logging
# ===========================================================================

class TestSTRR001:
    def test_fires_when_no_logging(self):
        m = _modeler()
        m.add_component(_comp(has_logging=False))
        r = m.analyze()
        assert "STR-R-001" in _ids(r)

    def test_not_fired_when_logging_enabled(self):
        m = _modeler()
        m.add_component(_comp(has_logging=True))
        r = m.analyze()
        assert "STR-R-001" not in _ids(r)


# ===========================================================================
# STR-I-001: Sensitive data publicly accessible
# ===========================================================================

class TestSTRI001:
    def test_fires_for_public_sensitive_db(self):
        m = _modeler()
        m.add_component(_comp(stores_sensitive_data=True, is_publicly_accessible=True))
        r = m.analyze()
        assert "STR-I-001" in _ids(r)

    def test_not_fired_when_private(self):
        m = _modeler()
        m.add_component(_comp(stores_sensitive_data=True, is_publicly_accessible=False))
        r = m.analyze()
        assert "STR-I-001" not in _ids(r)

    def test_severity_is_critical(self):
        m = _modeler()
        m.add_component(_comp(stores_sensitive_data=True, is_publicly_accessible=True))
        r = m.analyze()
        f = next(f for f in r.findings if f.threat_id == "STR-I-001")
        assert f.severity == ThreatSeverity.CRITICAL


# ===========================================================================
# STR-I-002: Unauthenticated database exposes data
# ===========================================================================

class TestSTRI002:
    def test_fires_for_unauth_database(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=False, component_type="database"))
        r = m.analyze()
        assert "STR-I-002" in _ids(r)

    def test_not_fired_for_authenticated_database(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=True, component_type="database"))
        r = m.analyze()
        assert "STR-I-002" not in _ids(r)


# ===========================================================================
# STR-D-001: Public component without rate limiting
# ===========================================================================

class TestSTRD001:
    def test_fires_for_public_api(self):
        m = _modeler()
        m.add_component(_comp(is_publicly_accessible=True, component_type="api"))
        r = m.analyze()
        assert "STR-D-001" in _ids(r)

    def test_fires_for_public_service(self):
        m = _modeler()
        m.add_component(_comp(is_publicly_accessible=True, component_type="service"))
        r = m.analyze()
        assert "STR-D-001" in _ids(r)

    def test_not_fired_for_private_api(self):
        m = _modeler()
        m.add_component(_comp(is_publicly_accessible=False, component_type="api"))
        r = m.analyze()
        assert "STR-D-001" not in _ids(r)


# ===========================================================================
# STR-E-001: Unauthenticated API/service
# ===========================================================================

class TestSTRE001:
    def test_fires_for_unauth_api(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=False, component_type="api"))
        r = m.analyze()
        assert "STR-E-001" in _ids(r)

    def test_fires_for_unauth_service(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=False, component_type="service"))
        r = m.analyze()
        assert "STR-E-001" in _ids(r)

    def test_not_fired_for_authenticated(self):
        m = _modeler()
        m.add_component(_comp(is_authenticated=True, component_type="api"))
        r = m.analyze()
        assert "STR-E-001" not in _ids(r)

    def test_not_fired_for_unauth_database(self):
        # Database covered by T-001, not E-001
        m = _modeler()
        m.add_component(_comp(is_authenticated=False, component_type="database"))
        r = m.analyze()
        assert "STR-E-001" not in _ids(r)


# ===========================================================================
# STR-S-003: Credential flow over unencrypted channel
# ===========================================================================

class TestSTRS003:
    def test_fires_for_unencrypted_credential_flow(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=False, carries_credentials=True))
        r = m.analyze()
        assert "STR-S-003" in _ids(r)

    def test_not_fired_when_encrypted(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=True, carries_credentials=True))
        r = m.analyze()
        assert "STR-S-003" not in _ids(r)

    def test_not_fired_without_credentials(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=False, carries_credentials=False))
        r = m.analyze()
        assert "STR-S-003" not in _ids(r)

    def test_severity_is_critical(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=False, carries_credentials=True))
        r = m.analyze()
        f = next(f for f in r.findings if f.threat_id == "STR-S-003")
        assert f.severity == ThreatSeverity.CRITICAL


# ===========================================================================
# STR-T-003: Unencrypted flow allows tampering
# ===========================================================================

class TestSTRT003:
    def test_fires_for_unencrypted_flow(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=False))
        r = m.analyze()
        assert "STR-T-003" in _ids(r)

    def test_not_fired_when_encrypted(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=True))
        r = m.analyze()
        assert "STR-T-003" not in _ids(r)

    def test_severity_is_high(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=False))
        r = m.analyze()
        f = next(f for f in r.findings if f.threat_id == "STR-T-003")
        assert f.severity == ThreatSeverity.HIGH


# ===========================================================================
# STR-I-003: Credential interception on plaintext
# ===========================================================================

class TestSTRI003:
    def test_fires_for_plaintext_credential_flow(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=False, carries_credentials=True))
        r = m.analyze()
        assert "STR-I-003" in _ids(r)

    def test_not_fired_when_no_credentials(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=False, carries_credentials=False))
        r = m.analyze()
        assert "STR-I-003" not in _ids(r)


# ===========================================================================
# STR-E-003: Token substitution on credential flow
# ===========================================================================

class TestSTRE003:
    def test_fires_for_plaintext_credential_flow(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=False, carries_credentials=True))
        r = m.analyze()
        assert "STR-E-003" in _ids(r)

    def test_not_fired_when_encrypted(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=True, carries_credentials=True))
        r = m.analyze()
        assert "STR-E-003" not in _ids(r)


# ===========================================================================
# Risk score
# ===========================================================================

class TestRiskScore:
    def test_clean_system_zero_score(self):
        m = _modeler()
        m.add_component(_comp(
            is_authenticated=True,
            stores_sensitive_data=False,
            is_publicly_accessible=False,
            has_logging=True,
            component_type="api",
        ))
        m.add_data_flow(_flow(is_encrypted=True, carries_credentials=False))
        r = m.analyze()
        assert r.total_risk_score == 0

    def test_score_accumulates(self):
        m = _modeler()
        m.add_data_flow(_flow(is_encrypted=False, carries_credentials=True))
        r = m.analyze()
        # STR-S-003 (50) + STR-T-003 (30) + STR-I-003 (50) + STR-E-003 (35) = 165
        assert r.total_risk_score > 0

    def test_target_set_on_component_findings(self):
        m = _modeler()
        m.add_component(_comp(name="MyDB", is_authenticated=False, component_type="database"))
        r = m.analyze()
        for f in r.findings_for_target("MyDB"):
            assert f.target == "MyDB"

    def test_target_set_on_flow_findings(self):
        m = _modeler()
        m.add_data_flow(_flow(name="LoginFlow", is_encrypted=False, carries_credentials=True))
        r = m.analyze()
        for f in r.findings_for_target("LoginFlow"):
            assert f.target == "LoginFlow"


# ===========================================================================
# include_low_severity filter
# ===========================================================================

class TestIncludeLowSeverity:
    def test_low_excluded_when_flag_false(self):
        m = StrideModeler(include_low_severity=False)
        m.add_component(_comp(has_logging=False))  # STR-R-001 (MEDIUM, not LOW)
        m.add_data_flow(_flow(is_encrypted=False, crosses_trust_boundary=True, is_logged=False))
        # STR-R-003 is LOW
        r = m.analyze()
        low = [f for f in r.findings if f.severity == ThreatSeverity.LOW]
        assert len(low) == 0

    def test_low_included_by_default(self):
        m = StrideModeler(include_low_severity=True)
        m.add_data_flow(_flow(is_encrypted=False, crosses_trust_boundary=True, is_logged=False))
        r = m.analyze()
        low = [f for f in r.findings if f.severity == ThreatSeverity.LOW]
        assert len(low) > 0


# ===========================================================================
# Multiple components + flows
# ===========================================================================

class TestMultipleComponents:
    def test_multiple_components_analyzed(self):
        m = _modeler()
        m.add_component(_comp(name="API", is_authenticated=False, component_type="api"))
        m.add_component(_comp(name="DB", is_authenticated=False, component_type="database"))
        r = m.analyze()
        targets = {f.target for f in r.findings}
        assert "API" in targets
        assert "DB" in targets

    def test_empty_model_gives_no_findings(self):
        m = _modeler()
        r = m.analyze()
        assert r.total_findings == 0
        assert r.total_risk_score == 0

    def test_report_includes_component_list(self):
        m = _modeler()
        c = _comp(name="Svc")
        m.add_component(c)
        r = m.analyze()
        assert any(comp.name == "Svc" for comp in r.components)

    def test_report_includes_flow_list(self):
        m = _modeler()
        f = _flow(name="MyFlow")
        m.add_data_flow(f)
        r = m.analyze()
        assert any(fl.name == "MyFlow" for fl in r.data_flows)

    def test_all_stride_categories_coverable(self):
        """At least one finding per STRIDE category when worst-case inputs given."""
        m = _modeler()
        m.add_component(_comp(
            name="PubDB",
            component_type="database",
            is_authenticated=False,
            stores_sensitive_data=True,
            is_publicly_accessible=True,
            has_logging=False,
        ))
        m.add_data_flow(_flow(
            name="PlainCreds",
            is_encrypted=False,
            carries_credentials=True,
            crosses_trust_boundary=True,
            is_logged=False,
        ))
        r = m.analyze()
        cats = {f.category for f in r.findings}
        for cat in StrideCategory:
            assert cat in cats, f"No finding for category {cat}"
