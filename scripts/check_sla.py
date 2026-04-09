"""
CLI tool: check SLA status for all findings in a JSON database.

Usage:
    python scripts/check_sla.py --db findings.json
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

import click
from tabulate import tabulate

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vuln_management.models import Finding
from vuln_management.sla_engine import find_breached, compute_sla


@click.command()
@click.option(
    "--db",
    "db_path",
    default="findings.json",
    show_default=True,
    type=click.Path(exists=True, readable=True),
    help="Path to the findings JSON database.",
)
@click.option(
    "--all",
    "show_all",
    is_flag=True,
    default=False,
    help="Show all findings with SLA, not just breached ones.",
)
def check_sla(db_path: str, show_all: bool) -> None:
    """Check SLA status for vulnerability findings and report breaches."""
    raw = json.loads(Path(db_path).read_text())
    findings = [Finding(**f) for f in raw]

    if show_all:
        # Display every open finding that has an SLA
        rows = []
        for f in findings:
            if not f.is_open():
                continue
            sla = compute_sla(f)
            if not sla.get("has_sla"):
                continue
            status = "BREACHED" if sla["breached"] else f"{sla['remaining_hours']}h remaining"
            rows.append([
                f.id[:8],
                f.title,
                f.severity.value.upper(),
                f.discovered_at.strftime("%Y-%m-%d %H:%M UTC"),
                sla["deadline"][:19],
                status,
            ])
        if not rows:
            click.echo("No open findings with an SLA.")
            return
        click.echo(tabulate(
            rows,
            headers=["ID", "Title", "Severity", "Discovered At", "Deadline", "SLA Status"],
            tablefmt="grid",
        ))
    else:
        # Only breached findings
        breached = find_breached(findings)
        if not breached:
            click.echo("No SLA breaches detected.")
            return

        click.echo(f"\n[!] {len(breached)} SLA breach(es) detected:\n")
        rows = [
            [
                f.id[:8],
                f.title,
                f.severity.value.upper(),
                f.discovered_at.strftime("%Y-%m-%d %H:%M UTC"),
                sla["deadline"][:19],
                f"{abs(sla['remaining_hours'])}h overdue",
            ]
            for f, sla in breached
        ]
        click.echo(tabulate(
            rows,
            headers=["ID", "Title", "Severity", "Discovered At", "Deadline", "Overdue By"],
            tablefmt="grid",
        ))
        sys.exit(1)


if __name__ == "__main__":
    check_sla()
