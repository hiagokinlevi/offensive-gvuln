"""
Unit tests for vuln_management/evidence_bundle.py
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from vuln_management.evidence_bundle import generate_bundle, verify_bundle
from vuln_management.models import Finding, FindingStatus, Severity
from vuln_management.tracker import VulnerabilityTracker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BASE_TS = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def _finding(
    title: str = "Test Vulnerability",
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.OPEN,
    asset: str = "app.example.com",
    cvss: float = None,
    cve: str = None,
) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        status=status,
        description=f"Description of {title}.",
        affected_asset=asset,
        cvss_score=cvss,
        cve_id=cve,
        discovered_at=_BASE_TS,
    )


def _tracker(*findings: Finding) -> VulnerabilityTracker:
    t = VulnerabilityTracker()
    for f in findings:
        t.add(f)
    return t


# ---------------------------------------------------------------------------
# Bundle structure
# ---------------------------------------------------------------------------


class TestBundleStructure(unittest.TestCase):

    def _generate(self, tracker: VulnerabilityTracker, engagement_id: str = "TEST-001") -> Path:
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id=engagement_id,
                client_name="Test Client",
            )
            # Copy results out before temp dir is cleaned
            self._bundle_root = bundle
            self._manifest = json.loads((bundle / "manifest.json").read_text())
            self._sla_status = json.loads((bundle / "sla_status.json").read_text())
            self._summary_md = (bundle / "summary.md").read_text()
            self._findings_dir = bundle / "findings"
            self._finding_files = list(self._findings_dir.glob("*.json"))
            return bundle

    def test_bundle_creates_required_files(self):
        tracker = _tracker(_finding())
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="TEST-001",
            )
            self.assertTrue((bundle / "manifest.json").exists())
            self.assertTrue((bundle / "summary.md").exists())
            self.assertTrue((bundle / "sla_status.json").exists())
            self.assertTrue((bundle / "findings").is_dir())

    def test_manifest_has_correct_finding_count(self):
        tracker = _tracker(_finding("V1"), _finding("V2"), _finding("V3"))
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="TEST-002",
            )
            manifest = json.loads((bundle / "manifest.json").read_text())
        self.assertEqual(manifest["total_findings"], 3)

    def test_manifest_engagement_id_matches(self):
        tracker = _tracker(_finding())
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="PENTEST-2026-007",
                client_name="Acme Corp",
            )
            manifest = json.loads((bundle / "manifest.json").read_text())
        self.assertEqual(manifest["engagement_id"], "PENTEST-2026-007")
        self.assertEqual(manifest["client_name"], "Acme Corp")

    def test_one_json_file_per_finding(self):
        tracker = _tracker(_finding("A"), _finding("B"), _finding("C"))
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="TEST-003",
            )
            finding_files = list((bundle / "findings").glob("*.json"))
        self.assertEqual(len(finding_files), 3)

    def test_per_finding_json_has_required_fields(self):
        tracker = _tracker(_finding("TestVuln", cvss=7.5, cve="CVE-2026-1234"))
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="TEST-004",
            )
            finding_file = next((bundle / "findings").glob("*.json"))
            data = json.loads(finding_file.read_text())
        for key in ["id", "title", "severity", "status", "description",
                    "affected_asset", "cvss_score", "cve_id", "discovered_at",
                    "is_open", "remediation_history", "sla"]:
            self.assertIn(key, data, f"Missing key: {key}")

    def test_summary_md_contains_engagement_id(self):
        tracker = _tracker(_finding())
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="ENG-2026-ABCDE",
            )
            summary = (bundle / "summary.md").read_text()
        self.assertIn("ENG-2026-ABCDE", summary)

    def test_summary_md_contains_finding_titles(self):
        tracker = _tracker(_finding("SQL Injection in Login Form"))
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="TEST-005",
            )
            summary = (bundle / "summary.md").read_text()
        self.assertIn("SQL Injection in Login Form", summary)


# ---------------------------------------------------------------------------
# SLA status in bundle
# ---------------------------------------------------------------------------


class TestBundleSLAStatus(unittest.TestCase):

    def test_sla_status_has_generated_at(self):
        tracker = _tracker(_finding())
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="SLA-001",
            )
            sla = json.loads((bundle / "sla_status.json").read_text())
        self.assertIn("generated_at", sla)
        self.assertIn("open_findings_with_sla", sla)
        self.assertIn("breached_count", sla)

    def test_closed_findings_not_in_sla_status(self):
        """Closed findings should not appear in the SLA status list."""
        closed = _finding("Closed Vuln", status=FindingStatus.CLOSED)
        open_ = _finding("Open Vuln", status=FindingStatus.OPEN)
        tracker = _tracker(closed, open_)
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="SLA-002",
            )
            sla = json.loads((bundle / "sla_status.json").read_text())
        ids_in_sla = {e["finding_id"] for e in sla["open_findings_with_sla"]}
        self.assertNotIn(closed.id, ids_in_sla)


# ---------------------------------------------------------------------------
# Severity sorting in manifest
# ---------------------------------------------------------------------------


class TestManifestSorting(unittest.TestCase):

    def test_manifest_findings_sorted_critical_first(self):
        tracker = _tracker(
            _finding("Low Finding", severity=Severity.LOW),
            _finding("Critical Finding", severity=Severity.CRITICAL),
            _finding("High Finding", severity=Severity.HIGH),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="SORT-001",
            )
            manifest = json.loads((bundle / "manifest.json").read_text())

        severities = [f["severity"] for f in manifest["findings"]]
        rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.assertEqual([rank[s] for s in severities], sorted(rank[s] for s in severities))

    def test_empty_tracker_produces_valid_bundle(self):
        tracker = VulnerabilityTracker()
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="EMPTY-001",
            )
            manifest = json.loads((bundle / "manifest.json").read_text())
        self.assertEqual(manifest["total_findings"], 0)
        self.assertEqual(manifest["open_findings"], 0)


class TestBundleIntegrity(unittest.TestCase):

    def test_manifest_contains_integrity_entries(self):
        tracker = _tracker(_finding("Tamper Evidence"))
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="INTEGRITY-001",
            )
            manifest = json.loads((bundle / "manifest.json").read_text())

        self.assertEqual(manifest["integrity"]["algorithm"], "sha256")
        recorded_paths = {entry["path"] for entry in manifest["integrity"]["files"]}
        self.assertIn("summary.md", recorded_paths)
        self.assertTrue(any(path.startswith("findings/") for path in recorded_paths))

    def test_verify_bundle_accepts_pristine_bundle(self):
        tracker = _tracker(_finding("Clean Bundle"))
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="INTEGRITY-002",
            )
            result = verify_bundle(bundle)

        self.assertTrue(result.is_valid)
        self.assertEqual(result.expected_files, result.verified_files)
        self.assertEqual(result.missing_files, [])
        self.assertEqual(result.modified_files, [])
        self.assertEqual(result.unexpected_files, [])

    def test_verify_bundle_detects_modified_file(self):
        tracker = _tracker(_finding("Modified Summary"))
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="INTEGRITY-003",
            )
            (bundle / "summary.md").write_text("tampered", encoding="utf-8")
            result = verify_bundle(bundle)

        self.assertFalse(result.is_valid)
        self.assertIn("summary.md", result.modified_files)

    def test_verify_bundle_detects_missing_and_unexpected_files(self):
        tracker = _tracker(_finding("Missing And Unexpected"))
        with tempfile.TemporaryDirectory() as tmpdir:
            bundle = generate_bundle(
                tracker=tracker,
                output_dir=Path(tmpdir),
                engagement_id="INTEGRITY-004",
            )
            finding_file = next((bundle / "findings").glob("*.json"))
            missing_relative = finding_file.relative_to(bundle).as_posix()
            finding_file.unlink()
            extra_file = bundle / "notes.txt"
            extra_file.write_text("out-of-band artifact", encoding="utf-8")
            result = verify_bundle(bundle)

        self.assertFalse(result.is_valid)
        self.assertIn(missing_relative, result.missing_files)
        self.assertIn("notes.txt", result.unexpected_files)


if __name__ == "__main__":
    unittest.main(verbosity=2)
