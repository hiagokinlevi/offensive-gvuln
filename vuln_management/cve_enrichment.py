"""
CVE Enrichment Pipeline
========================
Fetches CVSS scores and metadata from the NVD (National Vulnerability Database)
REST API v2.0 and correlates them with internal Finding records.

Features:
  - Fetch CVSS v3.1 (or v2.0 fallback) base scores and vectors from NVD API
  - Correlate enrichment with vuln_management.models.Finding objects
  - Batch enrichment with per-finding error handling
  - CvssEnrichment dataclass: authoritative NVD data for one CVE
  - EnrichmentResult: enriched Finding + enrichment metadata
  - EnrichmentReport: batch result with coverage stats and summary

NVD API endpoint (public, no auth required for low-rate queries):
    https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX

Rate limiting:
  - Without API key: 5 requests per 30 seconds
  - With API key (header: apiKey): 50 requests per 30 seconds
  - This module defaults to conservative 0.6s sleep between requests

Usage:
    from vuln_management.cve_enrichment import enrich_findings, fetch_cve

    enrichment = fetch_cve("CVE-2021-44228")   # Log4Shell
    print(enrichment.cvss_v3_score)             # 10.0
    print(enrichment.cvss_v3_severity)          # CRITICAL

    findings = [finding1, finding2]
    report = enrich_findings(findings)
    for r in report.results:
        if r.enriched:
            print(f"{r.finding.cve_id}: CVSS {r.enrichment.cvss_v3_score}")
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Optional

log = logging.getLogger(__name__)

# NVD CVE API v2.0 base URL
_NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_REQUEST_DELAY = 0.65  # seconds — stays under 5 req/30s public rate limit


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class CvssEnrichment:
    """
    CVSS enrichment data fetched from NVD for a single CVE.

    Attributes:
        cve_id:              CVE identifier (e.g. "CVE-2021-44228").
        description:         Brief English description from NVD.
        cvss_v3_score:       CVSS v3.1 base score (0.0–10.0), or None if unavailable.
        cvss_v3_vector:      CVSS v3.1 vector string, or None.
        cvss_v3_severity:    Textual severity: NONE/LOW/MEDIUM/HIGH/CRITICAL, or None.
        cvss_v2_score:       CVSS v2.0 score (fallback), or None.
        cvss_v2_vector:      CVSS v2.0 vector string, or None.
        published_date:      NVD published date (ISO 8601 string).
        last_modified:       NVD last-modified date (ISO 8601 string).
        cwe_ids:             List of CWE IDs associated with the CVE.
        references:          List of reference URLs (capped at 10).
        source:              Always "nvd" to identify the enrichment source.
    """
    cve_id:           str
    description:      str = ""
    cvss_v3_score:    Optional[float] = None
    cvss_v3_vector:   Optional[str] = None
    cvss_v3_severity: Optional[str] = None
    cvss_v2_score:    Optional[float] = None
    cvss_v2_vector:   Optional[str] = None
    published_date:   Optional[str] = None
    last_modified:    Optional[str] = None
    cwe_ids:          list[str] = field(default_factory=list)
    references:       list[str] = field(default_factory=list)
    source:           str = "nvd"

    @property
    def effective_score(self) -> Optional[float]:
        """Return CVSS v3.1 score if available, else v2.0 score."""
        return self.cvss_v3_score if self.cvss_v3_score is not None else self.cvss_v2_score

    @property
    def effective_severity(self) -> Optional[str]:
        """Return the severity string for the effective score."""
        if self.cvss_v3_severity:
            return self.cvss_v3_severity
        if self.cvss_v2_score is not None:
            return _score_to_severity_v2(self.cvss_v2_score)
        return None


@dataclass
class EnrichmentResult:
    """Result of enriching a single Finding with NVD data."""
    finding:     Any                         # vuln_management.models.Finding
    enriched:    bool = False                # True if NVD data was fetched successfully
    enrichment:  Optional[CvssEnrichment] = None
    error:       Optional[str] = None        # Error message if fetch failed


@dataclass
class EnrichmentReport:
    """Result of batch enrichment across multiple findings."""
    results:          list[EnrichmentResult] = field(default_factory=list)
    total_findings:   int = 0
    enriched_count:   int = 0
    skipped_count:    int = 0    # findings without cve_id
    error_count:      int = 0

    @property
    def coverage_pct(self) -> float:
        """Percentage of findings that were successfully enriched."""
        if self.total_findings == 0:
            return 0.0
        return round(self.enriched_count / self.total_findings * 100, 1)

    def summary(self) -> str:
        return (
            f"CVE enrichment: {self.enriched_count}/{self.total_findings} enriched "
            f"({self.coverage_pct}% coverage), "
            f"{self.skipped_count} skipped (no CVE ID), "
            f"{self.error_count} errors"
        )


# ---------------------------------------------------------------------------
# CVSS helpers
# ---------------------------------------------------------------------------

def _score_to_severity_v3(score: float) -> str:
    """Map CVSS v3.x base score to severity label per NIST scale."""
    if score == 0.0:
        return "NONE"
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    if score < 9.0:
        return "HIGH"
    return "CRITICAL"


def _score_to_severity_v2(score: float) -> str:
    """Map CVSS v2.0 base score to approximate severity label."""
    if score < 4.0:
        return "LOW"
    if score < 7.0:
        return "MEDIUM"
    return "HIGH"


# ---------------------------------------------------------------------------
# NVD API parsing
# ---------------------------------------------------------------------------

def _parse_nvd_response(data: dict[str, Any], cve_id: str) -> CvssEnrichment:
    """
    Parse an NVD API v2.0 response dict into a CvssEnrichment object.

    Expected structure:
      {
        "vulnerabilities": [{
          "cve": {
            "id": "CVE-...",
            "descriptions": [{"lang": "en", "value": "..."}],
            "published": "...",
            "lastModified": "...",
            "metrics": {
              "cvssMetricV31": [{"cvssData": {...}}],
              "cvssMetricV2":  [{"cvssData": {...}}]
            },
            "weaknesses": [{"description": [{"value": "CWE-..."}]}],
            "references": [{"url": "..."}]
          }
        }]
      }
    """
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return CvssEnrichment(cve_id=cve_id, description="Not found in NVD")

    cve_data = vulns[0].get("cve", {})

    # Description
    desc = ""
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # Published / modified dates
    published = cve_data.get("published", "")
    last_mod = cve_data.get("lastModified", "")

    # CVSS metrics
    metrics = cve_data.get("metrics", {})
    cvss_v3_score = cvss_v3_vector = cvss_v3_severity = None
    cvss_v2_score = cvss_v2_vector = None

    # Prefer v3.1, fall back to v3.0
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            cd = entries[0].get("cvssData", {})
            cvss_v3_score = cd.get("baseScore")
            cvss_v3_vector = cd.get("vectorString")
            cvss_v3_severity = cd.get("baseSeverity") or (
                _score_to_severity_v3(cvss_v3_score) if cvss_v3_score is not None else None
            )
            break

    v2_entries = metrics.get("cvssMetricV2", [])
    if v2_entries:
        cd = v2_entries[0].get("cvssData", {})
        cvss_v2_score = cd.get("baseScore")
        cvss_v2_vector = cd.get("vectorString")

    # CWE IDs
    cwe_ids: list[str] = []
    for weakness in cve_data.get("weaknesses", []):
        for d in weakness.get("description", []):
            val = d.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)

    # References (cap at 10)
    refs = [r.get("url", "") for r in cve_data.get("references", []) if r.get("url")][:10]

    return CvssEnrichment(
        cve_id=cve_data.get("id", cve_id),
        description=desc,
        cvss_v3_score=cvss_v3_score,
        cvss_v3_vector=cvss_v3_vector,
        cvss_v3_severity=cvss_v3_severity,
        cvss_v2_score=cvss_v2_score,
        cvss_v2_vector=cvss_v2_vector,
        published_date=published,
        last_modified=last_mod,
        cwe_ids=cwe_ids,
        references=refs,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fetch_cve(
    cve_id: str,
    api_key: Optional[str] = None,
    timeout: int = 10,
) -> CvssEnrichment:
    """
    Fetch CVSS enrichment data for a single CVE from the NVD API v2.0.

    Args:
        cve_id:   CVE identifier (e.g. "CVE-2021-44228"). Case-insensitive.
        api_key:  Optional NVD API key for higher rate limits.
        timeout:  HTTP request timeout in seconds (default: 10).

    Returns:
        CvssEnrichment with available CVSS data.

    Raises:
        RuntimeError: If urllib is unavailable or the request fails after retries.
    """
    import urllib.request
    import urllib.parse
    import json

    cve_id = cve_id.strip().upper()
    url = f"{_NVD_API_BASE}?cveId={urllib.parse.quote(cve_id)}"

    headers = {"Accept": "application/json"}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return _parse_nvd_response(data, cve_id)
    except Exception as exc:
        log.warning("NVD fetch failed for %s: %s", cve_id, exc)
        return CvssEnrichment(
            cve_id=cve_id,
            description=f"NVD fetch error: {exc}",
        )


def enrich_findings(
    findings: list[Any],
    api_key: Optional[str] = None,
    request_delay: float = _DEFAULT_REQUEST_DELAY,
    timeout: int = 10,
) -> EnrichmentReport:
    """
    Batch-enrich a list of Finding objects with NVD CVSS data.

    Iterates over findings that have a non-empty cve_id field, fetches
    enrichment data from NVD, and returns an EnrichmentReport.

    Findings without cve_id are counted as skipped but included in results
    with enriched=False so callers can still iterate over all findings.

    Args:
        findings:       List of vuln_management.models.Finding objects (or dicts
                        with a cve_id key).
        api_key:        Optional NVD API key.
        request_delay:  Seconds to sleep between NVD API calls (default 0.65s).
        timeout:        HTTP timeout per request.

    Returns:
        EnrichmentReport with per-finding EnrichmentResult entries.
    """
    report = EnrichmentReport(total_findings=len(findings))
    seen_cves: dict[str, CvssEnrichment] = {}  # cache to avoid duplicate fetches

    for finding in findings:
        # Get cve_id from Finding object or dict
        cve_id = None
        if isinstance(finding, dict):
            cve_id = finding.get("cve_id") or finding.get("cve") or ""
        elif hasattr(finding, "cve_id"):
            cve_id = finding.cve_id or ""
        cve_id = (cve_id or "").strip().upper()

        if not cve_id:
            report.results.append(EnrichmentResult(finding=finding, enriched=False))
            report.skipped_count += 1
            continue

        # Fetch or reuse from cache
        if cve_id in seen_cves:
            enrichment = seen_cves[cve_id]
            report.results.append(
                EnrichmentResult(finding=finding, enriched=True, enrichment=enrichment)
            )
            report.enriched_count += 1
            continue

        # Fetch from NVD
        try:
            enrichment = fetch_cve(cve_id, api_key=api_key, timeout=timeout)
            seen_cves[cve_id] = enrichment
            report.results.append(
                EnrichmentResult(finding=finding, enriched=True, enrichment=enrichment)
            )
            report.enriched_count += 1
        except Exception as exc:
            err = str(exc)
            log.warning("Enrichment failed for %s: %s", cve_id, err)
            report.results.append(
                EnrichmentResult(finding=finding, enriched=False, error=err)
            )
            report.error_count += 1

        # Rate-limit delay between NVD requests
        time.sleep(request_delay)

    return report


def correlate_cvss_severity(finding: Any, enrichment: CvssEnrichment) -> dict[str, Any]:
    """
    Produce a correlation dict comparing the internal finding severity
    with the NVD CVSS severity, flagging mismatches.

    Args:
        finding:     Finding object or dict with a severity field.
        enrichment:  CvssEnrichment from fetch_cve().

    Returns:
        Dict with: cve_id, internal_severity, nvd_severity, cvss_score,
                   severity_mismatch (bool), mismatch_detail (str or None).
    """
    # Normalize internal severity
    if isinstance(finding, dict):
        internal_sev = str(finding.get("severity", "")).lower()
    elif hasattr(finding, "severity"):
        sev = finding.severity
        internal_sev = sev.value if hasattr(sev, "value") else str(sev).lower()
    else:
        internal_sev = ""

    nvd_sev = (enrichment.effective_severity or "").lower()
    cvss_score = enrichment.effective_score

    # Map NONE → info for comparison
    nvd_sev_norm = "info" if nvd_sev == "none" else nvd_sev
    mismatch = bool(internal_sev and nvd_sev_norm and internal_sev != nvd_sev_norm)

    detail = None
    if mismatch:
        detail = (
            f"Internal severity '{internal_sev}' differs from NVD '{nvd_sev_norm}' "
            f"(CVSS {cvss_score})"
        )

    return {
        "cve_id":             enrichment.cve_id,
        "internal_severity":  internal_sev,
        "nvd_severity":       nvd_sev_norm,
        "cvss_score":         cvss_score,
        "severity_mismatch":  mismatch,
        "mismatch_detail":    detail,
    }
