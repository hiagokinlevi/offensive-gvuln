"""
Vulnerability management CLI.

Commands:
  check-sla       Report SLA breaches across all open findings
  generate-report Export findings in json, csv, or markdown format
  lifecycle       Query and manage vulnerability lifecycle state transitions
"""
import json
import sys
from pathlib import Path
import click
from vuln_management.models import Finding, FindingStatus
from vuln_management.sla_engine import find_breached
from vuln_management.reporter import generate_report
from vuln_management.lifecycle import (
    can_transition,
    lifecycle_path,
    transition,
    valid_transitions_from,
    InvalidTransitionError,
    ALLOWED_TRANSITIONS,
)


@click.group()
def cli() -> None:
    """k1n Vulnerability Governance — lifecycle management toolkit."""


@cli.command()
@click.argument("findings_file", type=click.Path(exists=True))
def check_sla(findings_file: str) -> None:
    """Report all open findings that have breached their SLA window."""
    raw = json.loads(Path(findings_file).read_text())
    findings = [Finding(**f) for f in raw]
    breached = find_breached(findings)

    if not breached:
        click.echo("No SLA breaches detected.")
        return

    click.echo(f"SLA BREACHES ({len(breached)} findings):\n")
    for finding, sla in breached:
        click.echo(
            f"  [{finding.severity.value.upper()}] {finding.title[:60]}\n"
            f"    Asset: {finding.affected_asset}\n"
            f"    Deadline: {sla['deadline']}\n"
        )
    sys.exit(1)


@cli.command()
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--format", "fmt", default="markdown", type=click.Choice(["json", "csv", "markdown"]), show_default=True)
@click.option("--output", "-o", default="-", help="Output file path (default: stdout)")
def generate(findings_file: str, fmt: str, output: str) -> None:
    """Generate a vulnerability report in the specified format."""
    raw = json.loads(Path(findings_file).read_text())
    findings = [Finding(**f) for f in raw]
    report = generate_report(findings, fmt=fmt)

    if output == "-":
        click.echo(report)
    else:
        Path(output).write_text(report)
        click.echo(f"Report written to {output}")


@cli.group()
def lifecycle() -> None:
    """Query and manage vulnerability lifecycle state transitions."""


@lifecycle.command("show")
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--id", "finding_id", default=None, help="Filter by finding ID prefix.")
def lifecycle_show(findings_file: str, finding_id: str | None) -> None:
    """Show the lifecycle path for findings (or a single finding by ID)."""
    raw = json.loads(Path(findings_file).read_text())
    findings = [Finding(**f) for f in raw]

    if finding_id:
        findings = [f for f in findings if f.id.startswith(finding_id)]
        if not findings:
            click.echo(f"No finding found with ID prefix: {finding_id}", err=True)
            sys.exit(2)

    for f in findings:
        path = lifecycle_path(f)
        path_str = " → ".join(path)
        click.echo(f"[{f.severity.value.upper()}] {f.title[:55]}")
        click.echo(f"  ID:     {f.id}")
        click.echo(f"  Status: {f.status.value}")
        click.echo(f"  Path:   {path_str}")
        click.echo("")


@lifecycle.command("transitions")
@click.argument("status")
def lifecycle_transitions(status: str) -> None:
    """List valid transitions from a given status value."""
    try:
        from_status = FindingStatus(status.lower())
    except ValueError:
        valid = [s.value for s in FindingStatus]
        click.echo(f"Unknown status '{status}'. Valid values: {valid}", err=True)
        sys.exit(2)

    targets = valid_transitions_from(from_status)
    if not targets:
        click.echo(f"No valid transitions from '{from_status.value}'.")
        return

    click.echo(f"Valid transitions from '{from_status.value}':")
    for to in targets:
        name = ALLOWED_TRANSITIONS[(from_status, to)]
        click.echo(f"  → {to.value:<25} ({name})")


@lifecycle.command("move")
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--id", "finding_id", required=True, help="Finding ID (or prefix) to transition.")
@click.option("--to", "to_status", required=True, help="Target status value.")
@click.option("--actor", required=True, help="Who is making this transition (e.g., email).")
@click.option("--note", default="", help="Optional note for the remediation record.")
@click.option("--save", is_flag=True, default=False,
              help="Write the updated findings back to the input file.")
def lifecycle_move(
    findings_file: str,
    finding_id: str,
    to_status: str,
    actor: str,
    note: str,
    save: bool,
) -> None:
    """
    Apply a lifecycle state transition to a finding and optionally save it.

    The transition is validated against the allowed transition graph.
    Use --save to persist the updated state back to the findings file.
    """
    raw = json.loads(Path(findings_file).read_text())
    findings = [Finding(**f) for f in raw]

    matches = [f for f in findings if f.id.startswith(finding_id)]
    if not matches:
        click.echo(f"No finding found with ID prefix: {finding_id}", err=True)
        sys.exit(2)
    if len(matches) > 1:
        click.echo(
            f"Ambiguous ID prefix '{finding_id}' matches {len(matches)} findings. "
            "Provide a longer prefix.", err=True,
        )
        sys.exit(2)

    finding = matches[0]

    try:
        target = FindingStatus(to_status.lower())
    except ValueError:
        click.echo(f"Unknown target status '{to_status}'.", err=True)
        sys.exit(2)

    try:
        transition_name = transition(finding, target, actor=actor, note=note)
    except InvalidTransitionError as exc:
        click.echo(f"Transition error: {exc}", err=True)
        sys.exit(1)

    click.echo(
        f"Transition '{transition_name}' applied: "
        f"{finding.remediation_records[-1].from_status.value} → {finding.status.value}"
    )
    click.echo(f"  Finding: {finding.title[:60]}")
    click.echo(f"  Actor:   {actor}")
    if note:
        click.echo(f"  Note:    {note}")

    if save:
        # Serialize updated findings back to file
        updated = [f.model_dump(mode="json") for f in findings]
        Path(findings_file).write_text(
            json.dumps(updated, indent=2, default=str),
            encoding="utf-8",
        )
        click.echo(f"  Saved:   {findings_file}")


if __name__ == "__main__":
    cli()
