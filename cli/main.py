"""
Vulnerability management CLI.

Commands:
  check-sla       Report SLA breaches across all open findings
  generate-report Export findings in json, csv, or markdown format
  evidence-bundle Build and verify tamper-evident evidence bundles
  issue-sync      Export GitHub/JIRA remediation payloads
  lifecycle       Query and manage vulnerability lifecycle state transitions
  notify-sla      Build or send Slack / Teams SLA notifications
  risk-acceptance Create, verify and apply signed risk acceptance records
"""
import json
import os
import sys
from datetime import datetime, timezone
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
from vuln_management.evidence_bundle import generate_bundle, verify_bundle
from vuln_management.risk_acceptance import (
    RiskAcceptanceRecord,
    apply_risk_acceptance_to_finding,
    create_risk_acceptance_record,
    find_expiring_records,
    verify_risk_acceptance_record,
)
from vuln_management.issue_sync import export_issue_sync_payloads
from vuln_management.retest import generate_retest_diff_report, schedule_retest
from vuln_management.sla_notifications import build_notification_payload, send_webhook_notification
from vuln_management.sla_report import build_sla_report
from vuln_management.tracker import VulnerabilityTracker


def _parse_datetime_utc(raw_value: str) -> datetime:
    """Parseia timestamp ISO-8601 e normaliza para UTC."""
    normalized = raw_value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _resolve_signing_key(signing_key: str | None) -> str:
    """Resolve chave de assinatura por opção explícita ou variável de ambiente."""
    resolved = (signing_key or os.getenv("GVULN_APPROVER_SIGNING_KEY", "")).strip()
    if not resolved:
        raise click.ClickException(
            "Missing signing key. Use --signing-key or set GVULN_APPROVER_SIGNING_KEY."
        )
    return resolved


def _validate_cli_output_path(path: str | Path) -> Path:
    """Reject symlinked output targets before exporting remediation artifacts."""
    candidate = Path(path).expanduser()
    if not candidate.is_absolute():
        candidate = (Path.cwd() / candidate).absolute()

    for parent in reversed(candidate.parents):
        if parent.is_symlink():
            raise click.ClickException("Output path must not traverse symlinked directories")
        if parent.exists() and not parent.is_dir():
            raise click.ClickException("Output parent path must be a directory")

    if candidate.is_symlink():
        raise click.ClickException("Output path must not be a symlink")
    if candidate.exists() and not candidate.is_file():
        raise click.ClickException("Output path must be a regular file")
    return candidate


@click.group()
def cli() -> None:
    """Offensive GVuln toolkit — lifecycle and governance automation."""


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


@cli.command("notify-sla")
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--channel", required=True, type=click.Choice(["slack", "teams"]), help="Webhook target type.")
@click.option("--webhook-url", default="", help="Webhook URL. Required unless --dry-run is used.")
@click.option(
    "--minimum-tier",
    default="breached",
    type=click.Choice(["warning", "breached", "critical-breach"]),
    show_default=True,
    help="Lowest escalation tier to include in the notification body.",
)
@click.option("--max-findings", default=5, type=int, show_default=True, help="Maximum findings listed in the payload.")
@click.option("--repository-label", default="offensive-gvuln", show_default=True, help="Repository label shown in the message.")
@click.option("--dry-run", is_flag=True, default=False, help="Print the JSON payload instead of sending it.")
@click.option("--output", "-o", default="-", help="Payload output path when using --dry-run.")
def notify_sla(
    findings_file: str,
    channel: str,
    webhook_url: str,
    minimum_tier: str,
    max_findings: int,
    repository_label: str,
    dry_run: bool,
    output: str,
) -> None:
    """Build or send a Slack / Teams SLA breach notification."""
    raw = json.loads(Path(findings_file).read_text(encoding="utf-8"))
    findings = [Finding(**item) for item in raw]
    report = build_sla_report(findings)

    try:
        payload = build_notification_payload(
            report,
            channel=channel,
            repository_label=repository_label,
            minimum_tier=minimum_tier,
            max_findings=max_findings,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    serialized = json.dumps(payload.body, indent=2)
    if dry_run:
        if output == "-":
            click.echo(serialized)
        else:
            Path(output).write_text(serialized, encoding="utf-8")
            click.echo(f"SLA notification payload written to {output}")
        return

    if not webhook_url.strip():
        raise click.ClickException("--webhook-url is required unless --dry-run is used")

    try:
        status_code = send_webhook_notification(webhook_url, payload)
    except Exception as exc:  # pragma: no cover - network failures depend on environment
        raise click.ClickException(f"Failed to deliver notification: {exc}") from exc

    click.echo(f"SLA notification delivered to {channel} webhook (HTTP {status_code})")


@cli.group("evidence-bundle")
def evidence_bundle() -> None:
    """Generate and verify tamper-evident evidence bundles."""


@evidence_bundle.command("generate")
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--engagement-id", required=True, help="Engagement identifier for the bundle root.")
@click.option("--output-dir", required=True, type=click.Path(file_okay=False), help="Directory where the bundle should be created.")
@click.option("--client-name", default="Unknown Client", show_default=True, help="Client organization name for the summary.")
@click.option("--assessor", default="k1N Security", show_default=True, help="Assessor name recorded in the manifest.")
def evidence_bundle_generate(
    findings_file: str,
    engagement_id: str,
    output_dir: str,
    client_name: str,
    assessor: str,
) -> None:
    """Generate a tamper-evident evidence bundle from findings JSON."""
    raw = json.loads(Path(findings_file).read_text(encoding="utf-8"))
    findings = [Finding(**f) for f in raw]
    tracker = VulnerabilityTracker()
    for finding in findings:
        tracker.add(finding)
    bundle_path = generate_bundle(
        tracker=tracker,
        output_dir=Path(output_dir),
        engagement_id=engagement_id,
        client_name=client_name,
        assessor=assessor,
    )
    click.echo(f"Evidence bundle written to {bundle_path}")


@evidence_bundle.command("verify")
@click.argument("bundle_dir", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--format", "fmt", default="text", type=click.Choice(["text", "json"]), show_default=True)
def evidence_bundle_verify(bundle_dir: Path, fmt: str) -> None:
    """Verify that a bundle still matches the manifest integrity metadata."""
    try:
        result = verify_bundle(bundle_dir)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    if fmt == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        status = "valid" if result.is_valid else "invalid"
        click.echo(
            f"Evidence bundle is {status}: expected={result.expected_files} verified={result.verified_files}"
        )
        for label, values in (
            ("Missing", result.missing_files),
            ("Modified", result.modified_files),
            ("Unexpected", result.unexpected_files),
        ):
            if values:
                click.echo(f"{label}:")
                for value in values:
                    click.echo(f"  - {value}")

    if not result.is_valid:
        sys.exit(1)


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


@cli.group()
def retest() -> None:
    """Plan verification work and compare retest snapshots."""


@retest.command("schedule")
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--id", "finding_id", required=True, help="Finding ID (or prefix) to schedule.")
@click.option("--due-at", required=True, help="Future ISO-8601 timestamp for the retest window.")
@click.option("--actor", required=True, help="Operator requesting the retest.")
@click.option("--environment", required=True, help="Environment to verify (prod, staging, etc.).")
@click.option("--scope", "scope_summary", required=True, help="Verification scope summary.")
@click.option("--note", default="", help="Optional lifecycle note override.")
@click.option("--save", is_flag=True, default=False, help="Persist the updated finding to disk.")
def retest_schedule(
    findings_file: str,
    finding_id: str,
    due_at: str,
    actor: str,
    environment: str,
    scope_summary: str,
    note: str,
    save: bool,
) -> None:
    """Attach a structured retest plan to a remediated finding."""
    raw = json.loads(Path(findings_file).read_text(encoding="utf-8"))
    findings = [Finding(**item) for item in raw]
    matches = [finding for finding in findings if finding.id.startswith(finding_id)]

    if not matches:
        click.echo(f"No finding found with ID prefix: {finding_id}", err=True)
        sys.exit(2)
    if len(matches) > 1:
        click.echo(
            f"Ambiguous ID prefix '{finding_id}' matches {len(matches)} findings. Provide a longer prefix.",
            err=True,
        )
        sys.exit(2)

    try:
        transition_name = schedule_retest(
            matches[0],
            due_at=_parse_datetime_utc(due_at),
            actor=actor,
            environment=environment,
            scope_summary=scope_summary,
            note=note,
        )
    except (ValueError, InvalidTransitionError) as exc:
        click.echo(f"Retest scheduling error: {exc}", err=True)
        sys.exit(1)

    plan = matches[0].retest_plan
    click.echo(f"Transition '{transition_name}' applied: finding={matches[0].id} status={matches[0].status.value}")
    click.echo(f"  Due at:      {plan.due_at.isoformat()}")
    click.echo(f"  Environment: {plan.environment}")
    click.echo(f"  Scope:       {plan.scope_summary}")

    if save:
        Path(findings_file).write_text(
            json.dumps([finding.model_dump(mode="json") for finding in findings], indent=2, default=str),
            encoding="utf-8",
        )
        click.echo(f"Saved updated findings to {findings_file}")


@retest.command("diff")
@click.argument("baseline_file", type=click.Path(exists=True))
@click.argument("candidate_file", type=click.Path(exists=True))
@click.option("--format", "fmt", default="markdown", type=click.Choice(["markdown", "json"]), show_default=True)
@click.option("--output", "-o", default="-", help="Output file path (default: stdout).")
def retest_diff(baseline_file: str, candidate_file: str, fmt: str, output: str) -> None:
    """Compare two findings snapshots and classify retest outcomes."""
    baseline_raw = json.loads(Path(baseline_file).read_text(encoding="utf-8"))
    candidate_raw = json.loads(Path(candidate_file).read_text(encoding="utf-8"))
    report = generate_retest_diff_report(
        [Finding(**item) for item in baseline_raw],
        [Finding(**item) for item in candidate_raw],
    )
    payload = report.to_markdown() if fmt == "markdown" else json.dumps(report.to_dict(), indent=2)

    if output == "-":
        click.echo(payload)
        return

    Path(output).write_text(payload, encoding="utf-8")
    click.echo(f"Retest diff report written to {output}")


@cli.group("issue-sync")
def issue_sync() -> None:
    """Export remediation issues for GitHub or JIRA."""


@issue_sync.command("export")
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--target", required=True, type=click.Choice(["github", "jira"]), help="Issue tracker target.")
@click.option("--repo", default=None, help="GitHub owner/repo target.")
@click.option("--project-key", default=None, help="JIRA project key.")
@click.option("--assignee", "assignees", multiple=True, help="GitHub assignee (repeatable).")
@click.option("--component", "components", multiple=True, help="JIRA component (repeatable).")
@click.option("--issue-type", default="Task", show_default=True, help="JIRA issue type name.")
@click.option("--milestone", type=int, default=None, help="Optional GitHub milestone number.")
@click.option("--include-closed", is_flag=True, default=False, help="Include closed/accepted findings.")
@click.option("--output", "-o", default="-", help="Output file path (default: stdout).")
def issue_sync_export(
    findings_file: str,
    target: str,
    repo: str | None,
    project_key: str | None,
    assignees: tuple[str, ...],
    components: tuple[str, ...],
    issue_type: str,
    milestone: int | None,
    include_closed: bool,
    output: str,
) -> None:
    """Export tracker-native issue payloads without requiring network access."""
    findings_raw = json.loads(Path(findings_file).read_text(encoding="utf-8"))
    findings = [Finding(**item) for item in findings_raw]
    try:
        payload = export_issue_sync_payloads(
            findings,
            target=target,
            repo=repo,
            project_key=project_key,
            assignees=assignees,
            components=components,
            issue_type=issue_type,
            milestone=milestone,
            only_open=not include_closed,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    rendered = json.dumps(payload, indent=2)
    if output == "-":
        click.echo(rendered)
        return

    output_path = _validate_cli_output_path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    click.echo(f"Issue sync export written to {output_path}")


@cli.group("risk-acceptance")
def risk_acceptance() -> None:
    """Manage signed risk acceptance workflow records."""


@risk_acceptance.command("create")
@click.option("--finding-id", required=True, help="Finding ID that will be risk accepted.")
@click.option("--requested-by", required=True, help="Requester identifier (email or username).")
@click.option("--approved-by", required=True, help="Approver identifier (email or username).")
@click.option("--reason", required=True, help="Business justification for risk acceptance.")
@click.option(
    "--expires-at",
    required=True,
    help="Expiration timestamp (ISO-8601), e.g. 2026-12-31T23:59:59Z.",
)
@click.option("--control", "controls", multiple=True, help="Compensating control (can be repeated).")
@click.option("--policy-ref", default=None, help="Optional policy reference.")
@click.option("--signing-key", default=None, help="Signing key or use GVULN_APPROVER_SIGNING_KEY.")
@click.option("--output", "-o", default="-", help="Output file path (default: stdout).")
def risk_acceptance_create(
    finding_id: str,
    requested_by: str,
    approved_by: str,
    reason: str,
    expires_at: str,
    controls: tuple[str, ...],
    policy_ref: str | None,
    signing_key: str | None,
    output: str,
) -> None:
    """Create a signed risk acceptance record."""
    key = _resolve_signing_key(signing_key)
    try:
        record = create_risk_acceptance_record(
            finding_id=finding_id,
            requested_by=requested_by,
            approved_by=approved_by,
            reason=reason,
            expires_at=_parse_datetime_utc(expires_at),
            signing_key=key,
            compensating_controls=controls,
            policy_reference=policy_ref,
        )
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc

    payload = json.dumps(record.model_dump(mode="json"), indent=2)
    if output == "-":
        click.echo(payload)
        return

    Path(output).write_text(payload, encoding="utf-8")
    click.echo(f"Risk acceptance record written to {output}")


@risk_acceptance.command("verify")
@click.argument("record_file", type=click.Path(exists=True))
@click.option("--signing-key", default=None, help="Signing key or use GVULN_APPROVER_SIGNING_KEY.")
@click.option("--reference-time", default=None, help="Optional ISO-8601 timestamp for expiry checks.")
def risk_acceptance_verify(
    record_file: str,
    signing_key: str | None,
    reference_time: str | None,
) -> None:
    """Verify signature and validity window of a risk acceptance record."""
    key = _resolve_signing_key(signing_key)
    raw = json.loads(Path(record_file).read_text(encoding="utf-8"))
    record = RiskAcceptanceRecord(**raw)
    reference = _parse_datetime_utc(reference_time) if reference_time else None
    valid, reason = verify_risk_acceptance_record(record, signing_key=key, reference_time=reference)
    if not valid:
        click.echo(f"Risk acceptance record is invalid: {reason}", err=True)
        sys.exit(1)

    click.echo(f"Risk acceptance record is valid: {record.record_id}")
    click.echo(f"  Finding:  {record.finding_id}")
    click.echo(f"  Approver: {record.approved_by}")
    click.echo(f"  Expires:  {record.expires_at.isoformat()}")


@risk_acceptance.command("expiring")
@click.argument("records_file", type=click.Path(exists=True))
@click.option("--days", type=int, default=30, show_default=True, help="Window in days.")
@click.option("--reference-time", default=None, help="Optional ISO-8601 timestamp for expiry checks.")
def risk_acceptance_expiring(records_file: str, days: int, reference_time: str | None) -> None:
    """List records that expire within N days."""
    if days < 0:
        raise click.ClickException("--days must be >= 0")

    raw = json.loads(Path(records_file).read_text(encoding="utf-8"))
    raw_records = raw if isinstance(raw, list) else [raw]
    records = [RiskAcceptanceRecord(**item) for item in raw_records]
    reference = _parse_datetime_utc(reference_time) if reference_time else None
    expiring = find_expiring_records(records, days=days, reference_time=reference)

    if not expiring:
        click.echo("No risk acceptance records expiring in the selected window.")
        return

    click.echo(f"Expiring records ({len(expiring)}):")
    for record in expiring:
        click.echo(
            f"  - {record.record_id} | finding={record.finding_id} | "
            f"expires_at={record.expires_at.isoformat()}"
        )


@risk_acceptance.command("apply")
@click.argument("findings_file", type=click.Path(exists=True))
@click.option("--record-file", required=True, type=click.Path(exists=True), help="Signed record file.")
@click.option("--id", "finding_id", required=True, help="Finding ID (or prefix) to apply acceptance.")
@click.option("--actor", required=True, help="Operator applying the approved acceptance.")
@click.option("--note", default="", help="Optional lifecycle note override.")
@click.option("--signing-key", default=None, help="Signing key or use GVULN_APPROVER_SIGNING_KEY.")
@click.option("--save", is_flag=True, default=False, help="Persist finding status update to file.")
def risk_acceptance_apply(
    findings_file: str,
    record_file: str,
    finding_id: str,
    actor: str,
    note: str,
    signing_key: str | None,
    save: bool,
) -> None:
    """Apply a verified risk acceptance record to a finding lifecycle."""
    key = _resolve_signing_key(signing_key)
    findings_raw = json.loads(Path(findings_file).read_text(encoding="utf-8"))
    findings = [Finding(**item) for item in findings_raw]
    matches = [f for f in findings if f.id.startswith(finding_id)]

    if not matches:
        click.echo(f"No finding found with ID prefix: {finding_id}", err=True)
        sys.exit(2)
    if len(matches) > 1:
        click.echo(
            f"Ambiguous ID prefix '{finding_id}' matches {len(matches)} findings. "
            "Provide a longer prefix.",
            err=True,
        )
        sys.exit(2)

    record_raw = json.loads(Path(record_file).read_text(encoding="utf-8"))
    record = RiskAcceptanceRecord(**record_raw)
    finding = matches[0]

    try:
        transition_name = apply_risk_acceptance_to_finding(
            finding,
            record=record,
            signing_key=key,
            actor=actor,
            note=note,
        )
    except ValueError as exc:
        click.echo(f"Risk acceptance apply error: {exc}", err=True)
        sys.exit(1)
    except InvalidTransitionError as exc:
        click.echo(f"Transition error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Transition '{transition_name}' applied: finding={finding.id} status={finding.status.value}")

    if save:
        updated = [f.model_dump(mode="json") for f in findings]
        Path(findings_file).write_text(
            json.dumps(updated, indent=2, default=str),
            encoding="utf-8",
        )
        click.echo(f"Saved updated findings to {findings_file}")


if __name__ == "__main__":
    cli()
