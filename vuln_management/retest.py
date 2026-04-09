"""Retest planning and diff reporting for vulnerability findings."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

from vuln_management.lifecycle import transition
from vuln_management.models import Finding, FindingStatus, RetestPlan


def _normalize_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def schedule_retest(
    finding: Finding,
    *,
    due_at: datetime,
    actor: str,
    environment: str,
    scope_summary: str,
    note: str = "",
) -> str:
    """Attach a structured retest plan and move the finding into verification."""
    normalized_due_at = _normalize_timestamp(due_at)
    if normalized_due_at <= datetime.now(timezone.utc):
        raise ValueError("retest due_at must be in the future")
    if not environment.strip():
        raise ValueError("environment must not be empty")
    if not scope_summary.strip():
        raise ValueError("scope_summary must not be empty")

    transition_name = transition(
        finding,
        FindingStatus.RETEST_SCHEDULED,
        actor=actor,
        note=note or f"Retest scheduled for {normalized_due_at.isoformat()}",
    )
    finding.retest_plan = RetestPlan(
        due_at=normalized_due_at,
        requested_by=actor.strip(),
        environment=environment.strip(),
        scope_summary=scope_summary.strip(),
    )
    return transition_name


@dataclass(slots=True)
class RetestDiffReport:
    fixed_findings: list[Finding]
    regressed_findings: list[Finding]
    unchanged_open_findings: list[Finding]
    newly_open_findings: list[Finding]
    closed_findings: list[Finding]

    @property
    def total_changes(self) -> int:
        return len(self.fixed_findings) + len(self.regressed_findings) + len(self.newly_open_findings)

    def to_markdown(self) -> str:
        sections: list[str] = [
            "# Retest Diff Report",
            "",
            f"- Fixed findings: **{len(self.fixed_findings)}**",
            f"- Regressed findings: **{len(self.regressed_findings)}**",
            f"- Newly opened findings: **{len(self.newly_open_findings)}**",
            f"- Still open findings: **{len(self.unchanged_open_findings)}**",
            f"- Closed/accepted findings in candidate snapshot: **{len(self.closed_findings)}**",
            "",
        ]

        def _append_block(title: str, findings: list[Finding]) -> None:
            sections.append(f"## {title}")
            if not findings:
                sections.append("- None")
                sections.append("")
                return
            for finding in findings:
                sections.append(
                    f"- `{finding.id}` | {finding.severity.value} | {finding.status.value} | {finding.title}"
                )
            sections.append("")

        _append_block("Fixed", self.fixed_findings)
        _append_block("Regressed", self.regressed_findings)
        _append_block("Newly Open", self.newly_open_findings)
        _append_block("Still Open", self.unchanged_open_findings)
        return "\n".join(sections).rstrip()

    def to_dict(self) -> dict[str, object]:
        return {
            "fixed_findings": [finding.model_dump(mode="json") for finding in self.fixed_findings],
            "regressed_findings": [finding.model_dump(mode="json") for finding in self.regressed_findings],
            "unchanged_open_findings": [
                finding.model_dump(mode="json") for finding in self.unchanged_open_findings
            ],
            "newly_open_findings": [finding.model_dump(mode="json") for finding in self.newly_open_findings],
            "closed_findings": [finding.model_dump(mode="json") for finding in self.closed_findings],
            "total_changes": self.total_changes,
        }


def generate_retest_diff_report(
    baseline_findings: list[Finding],
    candidate_findings: list[Finding],
) -> RetestDiffReport:
    """Compare pre- and post-retest snapshots and classify lifecycle changes."""
    baseline_by_id = {finding.id: finding for finding in baseline_findings}
    candidate_by_id = {finding.id: finding for finding in candidate_findings}

    fixed: list[Finding] = []
    regressed: list[Finding] = []
    unchanged_open: list[Finding] = []
    newly_open: list[Finding] = []
    closed: list[Finding] = []

    for finding_id, candidate in candidate_by_id.items():
        baseline = baseline_by_id.get(finding_id)
        if baseline is None:
            if candidate.is_open():
                newly_open.append(candidate)
            else:
                closed.append(candidate)
            continue

        if baseline.is_open() and not candidate.is_open():
            fixed.append(candidate)
        elif not baseline.is_open() and candidate.is_open():
            regressed.append(candidate)
        elif candidate.is_open():
            unchanged_open.append(candidate)
        else:
            closed.append(candidate)

    return RetestDiffReport(
        fixed_findings=sorted(fixed, key=lambda finding: finding.id),
        regressed_findings=sorted(regressed, key=lambda finding: finding.id),
        unchanged_open_findings=sorted(unchanged_open, key=lambda finding: finding.id),
        newly_open_findings=sorted(newly_open, key=lambda finding: finding.id),
        closed_findings=sorted(closed, key=lambda finding: finding.id),
    )
