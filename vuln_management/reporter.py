"""
Report generator for vulnerability findings.

Supports three output formats: json, csv, markdown.
"""
from __future__ import annotations
import csv
import io
import json
from .models import Finding


def generate_report(findings: list[Finding], fmt: str = "markdown") -> str:
    """
    Generate a vulnerability report in the requested format.

    Args:
        findings: List of Finding objects to include.
        fmt:      Output format — 'json', 'csv', or 'markdown'.

    Returns:
        Report as a string.
    """
    if fmt == "json":
        return json.dumps([f.model_dump(mode="json") for f in findings], indent=2)

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=["id", "title", "severity", "status", "affected_asset", "cvss_score", "cve_id", "discovered_at"],
        )
        writer.writeheader()
        for f in findings:
            writer.writerow({
                "id": f.id, "title": f.title, "severity": f.severity.value,
                "status": f.status.value, "affected_asset": f.affected_asset,
                "cvss_score": f.cvss_score, "cve_id": f.cve_id,
                "discovered_at": f.discovered_at.isoformat(),
            })
        return output.getvalue()

    # Default: markdown
    lines = ["# Vulnerability Report\n", f"Total findings: {len(findings)}\n", "---\n"]
    for f in findings:
        lines.append(f"## [{f.severity.value.upper()}] {f.title}\n")
        lines.append(f"- **Status:** {f.status.value}\n")
        lines.append(f"- **Asset:** {f.affected_asset}\n")
        if f.cve_id:
            lines.append(f"- **CVE:** {f.cve_id}\n")
        if f.cvss_score is not None:
            lines.append(f"- **CVSS:** {f.cvss_score}\n")
        lines.append(f"\n{f.description}\n\n")
    return "".join(lines)
