"""
Tests for Cycle 10 offensive-gvuln additions:
  - vuln_management/cve_enrichment.py
  - pentest_governance/scope_document.py
"""
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from vuln_management.cve_enrichment import (
    CvssEnrichment,
    EnrichmentReport,
    EnrichmentResult,
    _parse_nvd_response,
    _score_to_severity_v3,
    _score_to_severity_v2,
    correlate_cvss_severity,
    enrich_findings,
)
from pentest_governance.scope_document import (
    BatchValidationReport,
    PortRestriction,
    ScopeDocument,
    ValidationResult,
)


# ===========================================================================
# CvssEnrichment dataclass
# ===========================================================================

class TestCvssEnrichment:
    def test_effective_score_prefers_v3(self):
        e = CvssEnrichment(cve_id="CVE-2021-44228", cvss_v3_score=10.0, cvss_v2_score=9.3)
        assert e.effective_score == 10.0

    def test_effective_score_falls_back_to_v2(self):
        e = CvssEnrichment(cve_id="CVE-X", cvss_v3_score=None, cvss_v2_score=7.5)
        assert e.effective_score == 7.5

    def test_effective_score_none_when_both_missing(self):
        e = CvssEnrichment(cve_id="CVE-X")
        assert e.effective_score is None

    def test_effective_severity_returns_v3(self):
        e = CvssEnrichment(cve_id="CVE-X", cvss_v3_severity="CRITICAL")
        assert e.effective_severity == "CRITICAL"

    def test_effective_severity_derives_from_v2_score(self):
        e = CvssEnrichment(cve_id="CVE-X", cvss_v2_score=8.0)
        assert e.effective_severity == "HIGH"

    def test_effective_severity_none_when_no_scores(self):
        e = CvssEnrichment(cve_id="CVE-X")
        assert e.effective_severity is None

    def test_source_is_nvd(self):
        e = CvssEnrichment(cve_id="CVE-X")
        assert e.source == "nvd"


class TestScoreToSeverity:
    def test_v3_critical(self):
        assert _score_to_severity_v3(9.8) == "CRITICAL"

    def test_v3_high(self):
        assert _score_to_severity_v3(8.1) == "HIGH"

    def test_v3_medium(self):
        assert _score_to_severity_v3(6.5) == "MEDIUM"

    def test_v3_low(self):
        assert _score_to_severity_v3(2.0) == "LOW"

    def test_v3_none(self):
        assert _score_to_severity_v3(0.0) == "NONE"

    def test_v2_high(self):
        assert _score_to_severity_v2(7.0) == "HIGH"

    def test_v2_medium(self):
        assert _score_to_severity_v2(5.0) == "MEDIUM"

    def test_v2_low(self):
        assert _score_to_severity_v2(2.0) == "LOW"


class TestParseNvdResponse:
    _NVD_SAMPLE = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2021-44228",
                    "descriptions": [
                        {"lang": "en", "value": "Apache Log4j2 JNDI remote code execution"},
                        {"lang": "de", "value": "Andere Sprache"},
                    ],
                    "published": "2021-12-10T00:00:00.000",
                    "lastModified": "2022-01-01T00:00:00.000",
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": 10.0,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    "baseSeverity": "CRITICAL",
                                }
                            }
                        ],
                        "cvssMetricV2": [
                            {
                                "cvssData": {
                                    "baseScore": 9.3,
                                    "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C",
                                }
                            }
                        ],
                    },
                    "weaknesses": [
                        {"description": [{"value": "CWE-917"}, {"value": "CWE-20"}]}
                    ],
                    "references": [
                        {"url": "https://logging.apache.org/log4j/2.x/security.html"},
                        {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
                    ],
                }
            }
        ]
    }

    def test_parses_cve_id(self):
        e = _parse_nvd_response(self._NVD_SAMPLE, "CVE-2021-44228")
        assert e.cve_id == "CVE-2021-44228"

    def test_parses_english_description(self):
        e = _parse_nvd_response(self._NVD_SAMPLE, "CVE-2021-44228")
        assert "Log4j" in e.description

    def test_parses_cvss_v3_score(self):
        e = _parse_nvd_response(self._NVD_SAMPLE, "CVE-2021-44228")
        assert e.cvss_v3_score == 10.0

    def test_parses_cvss_v3_severity(self):
        e = _parse_nvd_response(self._NVD_SAMPLE, "CVE-2021-44228")
        assert e.cvss_v3_severity == "CRITICAL"

    def test_parses_cvss_v2_score(self):
        e = _parse_nvd_response(self._NVD_SAMPLE, "CVE-2021-44228")
        assert e.cvss_v2_score == 9.3

    def test_parses_cwe_ids(self):
        e = _parse_nvd_response(self._NVD_SAMPLE, "CVE-2021-44228")
        assert "CWE-917" in e.cwe_ids
        assert "CWE-20" in e.cwe_ids

    def test_parses_references(self):
        e = _parse_nvd_response(self._NVD_SAMPLE, "CVE-2021-44228")
        assert len(e.references) >= 1

    def test_empty_vulnerabilities_returns_not_found(self):
        e = _parse_nvd_response({"vulnerabilities": []}, "CVE-X")
        assert e.cve_id == "CVE-X"
        assert "Not found" in e.description

    def test_references_capped_at_10(self):
        sample = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-X",
                        "descriptions": [],
                        "metrics": {},
                        "weaknesses": [],
                        "references": [{"url": f"https://ref{i}.com"} for i in range(15)],
                    }
                }
            ]
        }
        e = _parse_nvd_response(sample, "CVE-X")
        assert len(e.references) == 10


class TestEnrichmentReport:
    def test_coverage_pct_zero_when_no_findings(self):
        report = EnrichmentReport()
        assert report.coverage_pct == 0.0

    def test_coverage_pct_calculation(self):
        report = EnrichmentReport(
            total_findings=4,
            enriched_count=3,
        )
        assert report.coverage_pct == 75.0

    def test_summary_contains_counts(self):
        report = EnrichmentReport(total_findings=5, enriched_count=4, skipped_count=1)
        s = report.summary()
        assert "4" in s and "5" in s


class TestEnrichFindings:
    def test_skips_findings_without_cve_id(self):
        findings = [{"title": "XSS", "severity": "medium"}]
        report = enrich_findings(findings, request_delay=0)
        assert report.skipped_count == 1
        assert report.enriched_count == 0

    def test_skips_empty_cve_id(self):
        findings = [{"title": "X", "cve_id": ""}]
        report = enrich_findings(findings, request_delay=0)
        assert report.skipped_count == 1

    def test_handles_network_error_gracefully(self):
        """enrich_findings should catch errors and count them as errors, not raise."""
        findings = [{"cve_id": "CVE-2021-44228", "title": "Log4Shell"}]
        # Patch fetch_cve to simulate network failure
        with patch("vuln_management.cve_enrichment.fetch_cve") as mock_fetch:
            mock_fetch.side_effect = RuntimeError("network timeout")
            report = enrich_findings(findings, request_delay=0)
        assert report.error_count == 1
        assert report.enriched_count == 0

    def test_deduplicates_same_cve(self):
        """Two findings with the same CVE should only trigger one NVD fetch."""
        findings = [
            {"cve_id": "CVE-2021-44228", "title": "Finding 1"},
            {"cve_id": "CVE-2021-44228", "title": "Finding 2"},
        ]
        call_count = []
        fake_enrichment = CvssEnrichment(cve_id="CVE-2021-44228", cvss_v3_score=10.0)

        with patch("vuln_management.cve_enrichment.fetch_cve") as mock_fetch:
            mock_fetch.return_value = fake_enrichment
            report = enrich_findings(findings, request_delay=0)
            call_count.append(mock_fetch.call_count)

        assert call_count[0] == 1   # only fetched once
        assert report.enriched_count == 2

    def test_results_length_matches_findings(self):
        findings = [
            {"cve_id": "CVE-2021-44228"},
            {"title": "No CVE"},
        ]
        fake = CvssEnrichment(cve_id="CVE-2021-44228", cvss_v3_score=10.0)
        with patch("vuln_management.cve_enrichment.fetch_cve", return_value=fake):
            report = enrich_findings(findings, request_delay=0)
        assert len(report.results) == 2

    def test_accepts_object_with_cve_id_attribute(self):
        class FakeFinding:
            cve_id = "CVE-2021-44228"

        fake = CvssEnrichment(cve_id="CVE-2021-44228", cvss_v3_score=10.0)
        with patch("vuln_management.cve_enrichment.fetch_cve", return_value=fake):
            report = enrich_findings([FakeFinding()], request_delay=0)
        assert report.enriched_count == 1


class TestCorrelateCvssSeverity:
    def test_no_mismatch_when_matching(self):
        finding = {"severity": "critical"}
        enrichment = CvssEnrichment(cve_id="CVE-X", cvss_v3_severity="CRITICAL")
        result = correlate_cvss_severity(finding, enrichment)
        assert result["severity_mismatch"] is False

    def test_mismatch_detected(self):
        finding = {"severity": "medium"}
        enrichment = CvssEnrichment(cve_id="CVE-X", cvss_v3_score=10.0, cvss_v3_severity="CRITICAL")
        result = correlate_cvss_severity(finding, enrichment)
        assert result["severity_mismatch"] is True
        assert result["mismatch_detail"] is not None

    def test_no_mismatch_when_no_nvd_severity(self):
        finding = {"severity": "high"}
        enrichment = CvssEnrichment(cve_id="CVE-X")
        result = correlate_cvss_severity(finding, enrichment)
        assert result["severity_mismatch"] is False

    def test_result_has_required_keys(self):
        finding = {"severity": "high"}
        enrichment = CvssEnrichment(cve_id="CVE-X", cvss_v3_score=7.5, cvss_v3_severity="HIGH")
        result = correlate_cvss_severity(finding, enrichment)
        for key in ("cve_id", "internal_severity", "nvd_severity", "cvss_score", "severity_mismatch"):
            assert key in result

    def test_accepts_finding_object_with_severity_enum(self):
        """Finding.severity may be an enum with a .value attribute."""
        class FakeSeverity:
            value = "high"

        class FakeFinding:
            severity = FakeSeverity()

        enrichment = CvssEnrichment(cve_id="CVE-X", cvss_v3_severity="HIGH")
        result = correlate_cvss_severity(FakeFinding(), enrichment)
        assert result["internal_severity"] == "high"
        assert result["severity_mismatch"] is False


# ===========================================================================
# PortRestriction
# ===========================================================================

class TestPortRestriction:
    def test_all_ports_allowed_when_no_restriction(self):
        r = PortRestriction(target_pattern="api.example.com")
        assert r.port_allowed(443)
        assert r.port_allowed(80)
        assert r.port_allowed(None)

    def test_only_allowed_ports_pass(self):
        r = PortRestriction(target_pattern="api.example.com", allowed_ports=[443, 8443])
        assert r.port_allowed(443)
        assert not r.port_allowed(80)
        assert not r.port_allowed(22)

    def test_protocol_allowed(self):
        r = PortRestriction(target_pattern="host", allowed_protocols=["tcp"])
        assert r.protocol_allowed("tcp")
        assert not r.protocol_allowed("udp")

    def test_protocol_case_insensitive(self):
        r = PortRestriction(target_pattern="host", allowed_protocols=["TCP"])
        assert r.protocol_allowed("tcp")

    def test_none_port_always_allowed(self):
        r = PortRestriction(target_pattern="host", allowed_ports=[443])
        assert r.port_allowed(None)

    def test_none_protocol_always_allowed(self):
        r = PortRestriction(target_pattern="host", allowed_protocols=["tcp"])
        assert r.protocol_allowed(None)


# ===========================================================================
# ScopeDocument
# ===========================================================================

class TestScopeDocumentBasic:
    doc = ScopeDocument(
        engagement_id="ENG-2026-042",
        authorized_by="Alice Smith",
        scope_items=["10.0.1.0/24", "api.example.com", "*.staging.example.com"],
        exclusions=["10.0.1.1"],
    )

    def test_in_scope_target_allowed(self):
        r = self.doc.validate_target("api.example.com")
        assert r.allowed
        assert r.reason == "in_scope"

    def test_cidr_target_allowed(self):
        r = self.doc.validate_target("10.0.1.50")
        assert r.allowed

    def test_wildcard_target_allowed(self):
        r = self.doc.validate_target("dev.staging.example.com")
        assert r.allowed

    def test_excluded_target_blocked(self):
        r = self.doc.validate_target("10.0.1.1")
        assert not r.allowed
        assert r.reason == "excluded"

    def test_out_of_scope_blocked(self):
        r = self.doc.validate_target("8.8.8.8")
        assert not r.allowed
        assert r.reason == "out_of_scope"


class TestScopeDocumentTimeWindow:
    def test_target_blocked_before_valid_from(self):
        doc = ScopeDocument(
            engagement_id="E1",
            authorized_by="Bob",
            scope_items=["api.example.com"],
            valid_from="2099-01-01",
        )
        r = doc.validate_target("api.example.com")
        assert not r.allowed
        assert r.reason == "outside_window"

    def test_target_blocked_after_valid_until(self):
        doc = ScopeDocument(
            engagement_id="E2",
            authorized_by="Bob",
            scope_items=["api.example.com"],
            valid_until="2020-01-01",
        )
        r = doc.validate_target("api.example.com")
        assert not r.allowed
        assert r.reason == "expired"

    def test_target_allowed_within_window(self):
        doc = ScopeDocument(
            engagement_id="E3",
            authorized_by="Bob",
            scope_items=["api.example.com"],
            valid_from="2020-01-01",
            valid_until="2099-12-31",
        )
        r = doc.validate_target("api.example.com")
        assert r.allowed

    def test_is_active_with_future_until(self):
        doc = ScopeDocument(
            engagement_id="E",
            authorized_by="X",
            scope_items=[],
            valid_until="2099-12-31",
        )
        assert doc.is_active

    def test_is_expired_with_past_until(self):
        doc = ScopeDocument(
            engagement_id="E",
            authorized_by="X",
            scope_items=[],
            valid_until="2020-01-01",
        )
        assert doc.is_expired

    def test_no_window_is_always_active(self):
        doc = ScopeDocument(engagement_id="E", authorized_by="X", scope_items=[])
        assert doc.is_active

    def test_as_of_override(self):
        doc = ScopeDocument(
            engagement_id="E",
            authorized_by="X",
            scope_items=["api.example.com"],
            valid_from="2026-01-01",
            valid_until="2026-12-31",
        )
        r = doc.validate_target(
            "api.example.com", as_of=date(2026, 6, 15)
        )
        assert r.allowed


class TestScopeDocumentPortRestrictions:
    doc = ScopeDocument(
        engagement_id="E",
        authorized_by="X",
        scope_items=["api.example.com"],
        restrictions={
            "api.example.com": {"allowed_ports": [443, 8443], "allowed_protocols": ["tcp"]},
        },
    )

    def test_allowed_port_passes(self):
        r = self.doc.validate_target("api.example.com", port=443)
        assert r.allowed

    def test_blocked_port_fails(self):
        r = self.doc.validate_target("api.example.com", port=22)
        assert not r.allowed
        assert r.reason == "port_restricted"

    def test_blocked_protocol_fails(self):
        r = self.doc.validate_target("api.example.com", protocol="udp")
        assert not r.allowed
        assert r.reason == "protocol_restricted"

    def test_no_port_passes_when_restricted(self):
        # None port should pass even when port restriction exists
        r = self.doc.validate_target("api.example.com", port=None)
        assert r.allowed


class TestScopeDocumentBatch:
    doc = ScopeDocument(
        engagement_id="ENG-BATCH",
        authorized_by="X",
        scope_items=["10.0.1.0/24"],
        exclusions=["10.0.1.1"],
    )

    def test_batch_returns_report(self):
        targets = ["10.0.1.10", "10.0.1.1", "8.8.8.8"]
        report = self.doc.validate_batch(targets)
        assert isinstance(report, BatchValidationReport)
        assert len(report.results) == 3

    def test_allowed_count(self):
        targets = ["10.0.1.10", "10.0.1.20", "8.8.8.8"]
        report = self.doc.validate_batch(targets)
        assert report.allowed_count == 2

    def test_blocked_count(self):
        targets = ["10.0.1.10", "10.0.1.1"]
        report = self.doc.validate_batch(targets)
        assert report.blocked_count == 1

    def test_allowed_targets_list(self):
        targets = ["10.0.1.10", "8.8.8.8"]
        report = self.doc.validate_batch(targets)
        assert "10.0.1.10" in report.allowed_targets
        assert "8.8.8.8" not in report.allowed_targets

    def test_blocked_by_reason(self):
        targets = ["10.0.1.1", "8.8.8.8"]
        report = self.doc.validate_batch(targets)
        excluded = report.blocked_by_reason("excluded")
        assert len(excluded) == 1
        assert excluded[0].target == "10.0.1.1"

    def test_summary_contains_engagement_id(self):
        report = self.doc.validate_batch(["10.0.1.10"])
        assert "ENG-BATCH" in report.summary()


class TestScopeDocumentToDict:
    doc = ScopeDocument(
        engagement_id="ENG-DICT",
        authorized_by="Alice",
        scope_items=["api.example.com"],
        exclusions=["bad.example.com"],
        valid_from="2026-01-01",
        valid_until="2026-12-31",
        engagement_type="white_box",
        notes="Restricted to business hours only.",
    )

    def test_to_dict_has_required_keys(self):
        d = self.doc.to_dict()
        for key in ("engagement_id", "authorized_by", "scope_items", "exclusions",
                    "valid_from", "valid_until", "is_active", "is_expired"):
            assert key in d, f"Missing key: {key}"

    def test_engagement_id_correct(self):
        assert self.doc.to_dict()["engagement_id"] == "ENG-DICT"

    def test_scope_items_preserved(self):
        assert "api.example.com" in self.doc.to_dict()["scope_items"]

    def test_notes_preserved(self):
        assert "business hours" in self.doc.to_dict()["notes"]


class TestPortRestrictionFromDict:
    def test_port_restriction_from_dict_in_constructor(self):
        doc = ScopeDocument(
            engagement_id="E",
            authorized_by="X",
            scope_items=["host.example.com"],
            restrictions={"host.example.com": {"allowed_ports": [80, 443]}},
        )
        r = doc.validate_target("host.example.com", port=443)
        assert r.allowed

    def test_port_restriction_from_portrestriction_object(self):
        doc = ScopeDocument(
            engagement_id="E",
            authorized_by="X",
            scope_items=["host.example.com"],
            restrictions={
                "host.example.com": PortRestriction(
                    target_pattern="host.example.com",
                    allowed_ports=[443],
                )
            },
        )
        r = doc.validate_target("host.example.com", port=80)
        assert not r.allowed
