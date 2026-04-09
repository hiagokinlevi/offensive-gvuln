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

import json
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
    bundle_root = output_dir / engagement_id
    findings_dir = bundle_root / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    all_findings = tracker.all()
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
        "engagement_id":   engagement_id,
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
                "file":          f"findings/{f.id}.json",
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
        finding_path = findings_dir / f"{finding.id}.json"
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

    return bundle_root
