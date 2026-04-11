"""
Evidence Bundle Generator
==========================
Packages vulnerability findings into a structured evidence bundle suitable
for formal pentest reporting, remediation handoff, and audit trails.

An evidence bundle is a directory containing:
  - manifest.json:       Machine-readable index of all findings
  - summary.md:          Human-readable executive summary
  - findings/<id>.json:  Per-finding detail including CVSS, status, and history
  - sla_status.json:     SLA compliance status for all open findings

Evidence bundles are self-contained — they include all data needed to
understand and act on findings without requiring access to the live tracker.

Usage:
    from vuln_management.tracker import VulnerabilityTracker
    from vuln_management.evidence_bundle import generate_bundle

    bundle_path = generate_bundle(
        tracker=tracker,
        output_dir=Path("./evidence"),
        engagement_id="PENTEST-2026-001",
        client_name="Example Corp",
    )
    print(f"Bundle written to: {bundle_path}")
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from vuln_management.models import Finding, FindingStatus, Severity
from vuln_management.sla_engine import compute_sla
from vuln_management.tracker import VulnerabilityTracker


# ---------------------------------------------------------------------------
# Severity score for sorting
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH:     1,
    Severity.MEDIUM:   2,
    Severity.LOW:      3,
    Severity.INFO:     4,
}


def _safe_bundle_component(value: str, *, label: str) -> str:
    """Restrict bundle-controlled path components to plain file/directory names."""
    normalized = value.strip()
    candidate = Path(normalized)
    if (
        not normalized
        or candidate.name != normalized
        or normalized in {".", ".."}
        or any(part in {".", ".."} for part in candidate.parts)
    ):
        raise ValueError(f"{label} must be a simple path component without traversal sequences")
    return normalized


def _finding_to_dict(finding: Finding) -> dict:
    """Serialize a Finding to a dict suitable for JSON output."""
    return {
        "id":             finding.id,
        "title":          finding.title,
        "severity":       finding.severity.value,
        "status":         finding.status.value,
        "description":    finding.description,
        "affected_asset": finding.affected_asset,
        "cvss_score":     finding.cvss_score,
        "cve_id":         finding.cve_id,
        "discovered_at":  finding.discovered_at.isoformat(),
        "is_open":        finding.is_open(),
        "remediation_history": [
            {
                "timestamp":   r.timestamp.isoformat(),
                "from_status": r.from_status.value,
                "to_status":   r.to_status.value,
                "actor":       r.actor,
                "note":        r.note,
            }
            for r in finding.remediation_records
        ],
        "sla": compute_sla(finding),
    }


def _severity_badge(severity: Severity) -> str:
    """Return a Markdown badge string for the severity level."""
    return {
        Severity.CRITICAL: "**CRITICAL**",
        Severity.HIGH:     "**HIGH**",
        Severity.MEDIUM:   "Medium",
        Severity.LOW:      "Low",
        Severity.INFO:     "Info",
    }.get(severity, severity.value)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_bundle_files(bundle_root: Path) -> list[Path]:
    return sorted(
        path.relative_to(bundle_root)
        for path in bundle_root.rglob("*")
        if path.is_file()
    )


def _build_integrity_entries(bundle_root: Path) -> list[dict[str, int | str]]:
    entries: list[dict[str, int | str]] = []
    for relative_path in _relative_bundle_files(bundle_root):
        if relative_path.as_posix() == "manifest.json":
            continue
        absolute_path = bundle_root / relative_path
        entries.append(
            {
                "path": relative_path.as_posix(),
                "sha256": _sha256_file(absolute_path),
                "size_bytes": absolute_path.stat().st_size,
            }
        )
    return entries


@dataclass
class BundleVerificationResult:
    """Outcome of evidence bundle integrity verification."""

    bundle_root: Path
    expected_files: int
    verified_files: int
    checked_at: str
    missing_files: list[str] = field(default_factory=list)
    modified_files: list[str] = field(default_factory=list)
    unexpected_files: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return not (self.missing_files or self.modified_files or self.unexpected_files)

    def to_dict(self) -> dict[str, object]:
        return {
            "bundle_root": str(self.bundle_root),
            "checked_at": self.checked_at,
            "expected_files": self.expected_files,
            "verified_files": self.verified_files,
            "is_valid": self.is_valid,
            "missing_files": self.missing_files,
            "modified_files": self.modified_files,
            "unexpected_files": self.unexpected_files,
        }


def generate_bundle(
    tracker: VulnerabilityTracker,
    output_dir: Path,
    engagement_id: str,
    client_name: str = "Unknown Client",
    assessor: str = "k1N Security",
) -> Path:
    """
    Generate a structured evidence bundle from a VulnerabilityTracker.

    Creates the following files inside output_dir/<engagement_id>/:
      - manifest.json
      - summary.md
      - findings/<finding_id>.json  (one per finding)
      - sla_status.json

    Args:
        tracker:       VulnerabilityTracker containing all findings.
        output_dir:    Base directory for bundle output.
        engagement_id: Unique identifier for this engagement (e.g. PENTEST-2026-001).
        client_name:   Client organization name for the summary report.
        assessor:      Name of the assessing team or individual.

    Returns:
        Path to the bundle root directory (output_dir/<engagement_id>).
    """
    safe_engagement_id = _safe_bundle_component(engagement_id, label="engagement_id")
    bundle_root = output_dir / safe_engagement_id
    findings_dir = bundle_root / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    all_findings = tracker.all()
    safe_finding_files = {
        finding.id: f"{_safe_bundle_component(finding.id, label='finding.id')}.json"
        for finding in all_findings
    }
    generated_at = datetime.now(timezone.utc).isoformat()

    # Sort by severity then by discovered_at
    sorted_findings = sorted(
        all_findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.discovered_at),
    )

    # -----------------------------------------------------------------------
    # manifest.json — machine-readable index
    # -----------------------------------------------------------------------
    severity_counts = {s.value: 0 for s in Severity}
    status_counts = {s.value: 0 for s in FindingStatus}
    for f in all_findings:
        severity_counts[f.severity.value] += 1
        status_counts[f.status.value] += 1

    manifest = {
        "engagement_id":   safe_engagement_id,
        "client_name":     client_name,
        "assessor":        assessor,
        "generated_at":    generated_at,
        "total_findings":  len(all_findings),
        "open_findings":   sum(1 for f in all_findings if f.is_open()),
        "severity_counts": severity_counts,
        "status_counts":   status_counts,
        "findings": [
            {
                "id":            f.id,
                "title":         f.title,
                "severity":      f.severity.value,
                "status":        f.status.value,
                "affected_asset": f.affected_asset,
                "is_open":       f.is_open(),
                "file":          f"findings/{safe_finding_files[f.id]}",
            }
            for f in sorted_findings
        ],
    }
    (bundle_root / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    # -----------------------------------------------------------------------
    # findings/<id>.json — per-finding detail
    # -----------------------------------------------------------------------
    for finding in all_findings:
        finding_path = findings_dir / safe_finding_files[finding.id]
        finding_path.write_text(
            json.dumps(_finding_to_dict(finding), indent=2), encoding="utf-8"
        )

    # -----------------------------------------------------------------------
    # sla_status.json — SLA compliance overview
    # -----------------------------------------------------------------------
    sla_entries = []
    for f in sorted_findings:
        if not f.is_open():
            continue
        sla = compute_sla(f)
        sla_entries.append({
            "finding_id":    f.id,
            "title":         f.title,
            "severity":      f.severity.value,
            "status":        f.status.value,
            "discovered_at": f.discovered_at.isoformat(),
            "sla":           sla,
        })

    (bundle_root / "sla_status.json").write_text(
        json.dumps({
            "generated_at": generated_at,
            "open_findings_with_sla": sla_entries,
            "breached_count": sum(1 for e in sla_entries if e["sla"].get("breached")),
        }, indent=2),
        encoding="utf-8",
    )

    # -----------------------------------------------------------------------
    # summary.md — human-readable executive summary
    # -----------------------------------------------------------------------
    lines = [
        f"# Evidence Bundle — {engagement_id}",
        f"",
        f"**Client:**     {client_name}  ",
        f"**Assessor:**   {assessor}  ",
        f"**Generated:**  {generated_at}  ",
        f"",
        f"---",
        f"",
        f"## Finding Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in Severity:
        count = severity_counts[sev.value]
        if count > 0:
            lines.append(f"| {_severity_badge(sev)} | {count} |")

    lines += [
        f"",
        f"**Total:** {len(all_findings)} findings "
        f"({sum(1 for f in all_findings if f.is_open())} open)",
        f"",
        f"---",
        f"",
        f"## Findings",
        f"",
    ]

    for f in sorted_findings:
        sla = compute_sla(f)
        sla_note = ""
        if sla.get("has_sla") and sla.get("breached"):
            sla_note = " ⚠ **SLA BREACHED**"
        elif sla.get("has_sla") and not sla.get("breached"):
            hrs = sla.get("remaining_hours", 0)
            if hrs < 24:
                sla_note = f" ⚠ SLA expires in {hrs:.1f}h"

        lines.append(
            f"### [{_severity_badge(f.severity)}] {f.title}{sla_note}"
        )
        lines += [
            f"",
            f"- **ID:** `{f.id}`",
            f"- **Asset:** {f.affected_asset}",
            f"- **Status:** {f.status.value}",
            f"- **Discovered:** {f.discovered_at.strftime('%Y-%m-%d %H:%M UTC')}",
        ]
        if f.cvss_score is not None:
            lines.append(f"- **CVSS:** {f.cvss_score:.1f}")
        if f.cve_id:
            lines.append(f"- **CVE:** {f.cve_id}")
        lines += [f"", f"{f.description}", f""]

    (bundle_root / "summary.md").write_text("\n".join(lines), encoding="utf-8")

    manifest_path = bundle_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["integrity"] = {
        "algorithm": "sha256",
        "files": _build_integrity_entries(bundle_root),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return bundle_root


def verify_bundle(bundle_root: Path) -> BundleVerificationResult:
    """Validate that an evidence bundle matches its manifest integrity block."""
    manifest_path = bundle_root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    integrity = manifest.get("integrity")
    if not integrity or integrity.get("algorithm") != "sha256":
        raise ValueError("Bundle manifest does not contain a supported integrity block.")

    expected_entries = integrity.get("files", [])
    expected_map = {
        entry["path"]: {
            "sha256": entry["sha256"],
            "size_bytes": entry["size_bytes"],
        }
        for entry in expected_entries
    }
    actual_paths = {
        path.as_posix()
        for path in _relative_bundle_files(bundle_root)
        if path.as_posix() != "manifest.json"
    }

    missing_files = sorted(path for path in expected_map if path not in actual_paths)
    unexpected_files = sorted(path for path in actual_paths if path not in expected_map)

    modified_files: list[str] = []
    verified_files = 0
    for relative_path, expected in expected_map.items():
        absolute_path = bundle_root / relative_path
        if not absolute_path.exists():
            continue
        verified_files += 1
        if absolute_path.stat().st_size != expected["size_bytes"] or _sha256_file(absolute_path) != expected["sha256"]:
            modified_files.append(relative_path)

    return BundleVerificationResult(
        bundle_root=bundle_root,
        expected_files=len(expected_map),
        verified_files=verified_files,
        checked_at=datetime.now(timezone.utc).isoformat(),
        missing_files=missing_files,
        modified_files=sorted(modified_files),
        unexpected_files=unexpected_files,
    )
