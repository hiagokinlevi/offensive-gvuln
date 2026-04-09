"""
CLI tool: generate a vulnerability report from a findings JSON database.

Usage:
    python scripts/generate_report.py --db findings.json --format markdown --output report.md
    python scripts/generate_report.py --db findings.json --format csv
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

import click

# Allow running from repo root without installing the package
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vuln_management.models import Finding
from vuln_management.reporter import generate_report


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
    "--format",
    "fmt",
    default="markdown",
    show_default=True,
    type=click.Choice(["json", "csv", "markdown"], case_sensitive=False),
    help="Output format for the report.",
)
@click.option(
    "--output",
    "output_path",
    default=None,
    type=click.Path(writable=True),
    help="Write report to this file instead of stdout.",
)
@click.option(
    "--open-only",
    is_flag=True,
    default=False,
    help="Include only open findings in the report.",
)
def generate(db_path: str, fmt: str, output_path: str | None, open_only: bool) -> None:
    """Generate a vulnerability report in the requested format."""
    raw = json.loads(Path(db_path).read_text())
    findings = [Finding(**f) for f in raw]

    if open_only:
        findings = [f for f in findings if f.is_open()]
        click.echo(f"Filtered to {len(findings)} open finding(s).", err=True)

    report = generate_report(findings, fmt=fmt.lower())

    if output_path:
        Path(output_path).write_text(report)
        click.echo(f"Report written to {output_path}", err=True)
    else:
        click.echo(report)


if __name__ == "__main__":
    generate()
