"""Offline-safe issue tracker payload adapters for remediation workflows."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Any

from vuln_management.models import Finding, Severity
from vuln_management.sla_engine import compute_sla


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SENSITIVE_FIELD_NAME = (
    r"(?:[a-z0-9][a-z0-9._-]*?)?"
    r"(?:password|passwd|pwd|api[_-]?key|access[_-]?token|refresh[_-]?token|"
    r"session[_-]?token|webhook[_-]?url|secret|client[_-]?secret|private[_-]?key)"
    r"[a-z0-9._-]*"
)

_GITHUB_TOKEN_PATTERN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{20,255})\b"
)

_SENSITIVE_VALUE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            rf"(?i)([\"']?{_SENSITIVE_FIELD_NAME}[\"']?\s*:\s*[\"'])([^\"']+)([\"'])"
        ),
        r"\1[REDACTED]\3",
    ),
    (
        re.compile(
            rf"(?i)\b({_SENSITIVE_FIELD_NAME})\s*[:=]\s*([^\s,;]+)"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)([^@/\s]+)(@)"),
        r"\1[REDACTED]\3",
    ),
    (
        re.compile(
            r"(?i)([?&](?:sig|signature|x-amz-signature|x-goog-signature|x-ms-signature|access[_-]?token|refresh[_-]?token|api[_-]?key|apikey|client[_-]?secret)=)([^&#\s]+)"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)\b(bearer|basic|token)\s+[A-Za-z0-9._~+/=-]{12,}"),
        r"\1 [REDACTED]",
    ),
    (
        _GITHUB_TOKEN_PATTERN,
        "[GITHUB_TOKEN_REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b((?:__secure-|__host-)?(?:session(?:id)?|auth(?:entication)?(?:[_-]?token)?|"
            r"refresh[_-]?token|access[_-]?token|id[_-]?token|jwt|csrftoken|xsrf[_-]?token|"
            r"remember[_-]?token))\s*=\s*([^;\s]+)"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "[AWS_ACCESS_KEY_REDACTED]",
    ),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL),
        "[PRIVATE_KEY_REDACTED]",
    ),
)


def _normalize_due_date(value: str | None) -> str | None:
    if not value:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).date().isoformat()


def _finding_sort_key(finding: Finding) -> tuple[int, datetime, str]:
    return (
        _SEVERITY_ORDER.get(finding.severity, 99),
        finding.discovered_at,
        finding.id,
    )


def _github_labels(finding: Finding) -> list[str]:
    labels = [
        "security",
        "vulnerability",
        f"severity:{finding.severity.value}",
        f"status:{finding.status.value}",
        "workflow:gvuln",
    ]
    if finding.cve_id:
        labels.append(f"cve:{finding.cve_id.lower()}")
    return labels


def _jira_labels(finding: Finding) -> list[str]:
    labels = [
        "security",
        "gvuln",
        f"severity-{finding.severity.value}",
        finding.status.value.replace("_", "-"),
    ]
    if finding.cve_id:
        labels.append(finding.cve_id.lower())
    return labels


def redact_sensitive_text(value: str) -> str:
    """Redact common credential material before findings leave the local workspace."""
    redacted = value
    for pattern, replacement in _SENSITIVE_VALUE_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _issue_body(finding: Finding) -> str:
    sla = compute_sla(finding)
    affected_asset = redact_sensitive_text(finding.affected_asset)
    description = redact_sensitive_text(finding.description)
    lines = [
        "## Finding Summary",
        "",
        f"- Finding ID: `{finding.id}`",
        f"- Severity: `{finding.severity.value}`",
        f"- Status: `{finding.status.value}`",
        f"- Affected asset: `{affected_asset}`",
    ]
    if finding.cve_id:
        lines.append(f"- CVE: `{finding.cve_id}`")
    if finding.cvss_score is not None:
        lines.append(f"- CVSS: `{finding.cvss_score:.1f}`")
    if sla.get("has_sla"):
        deadline = sla.get("deadline")
        if deadline:
            lines.append(f"- SLA deadline: `{deadline}`")
        lines.append(f"- SLA breached: `{bool(sla.get('breached'))}`")

    lines.extend(
        [
            "",
            "## Description",
            "",
            description,
            "",
            "## Remediation Workflow Notes",
            "",
            "- Track verification evidence and status changes back in `offensive-gvuln`.",
            "- Close only after remediation is validated or an approved risk acceptance is attached.",
        ]
    )
    return "\n".join(lines)


@dataclass(slots=True)
class GitHubIssuePayload:
    title: str
    body: str
    labels: list[str]
    assignees: list[str]
    milestone: int | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "title": self.title,
            "body": self.body,
            "labels": self.labels,
            "assignees": self.assignees,
        }
        if self.milestone is not None:
            payload["milestone"] = self.milestone
        return payload


@dataclass(slots=True)
class JiraIssuePayload:
    summary: str
    description: str
    labels: list[str]
    issue_type: str
    priority: str
    components: list[str]
    due_date: str | None

    def to_dict(self, project_key: str) -> dict[str, Any]:
        fields: dict[str, Any] = {
            "project": {"key": project_key},
            "summary": self.summary,
            "description": self.description,
            "issuetype": {"name": self.issue_type},
            "priority": {"name": self.priority},
            "labels": self.labels,
        }
        if self.components:
            fields["components"] = [{"name": component} for component in self.components]
        if self.due_date:
            fields["duedate"] = self.due_date
        return {"fields": fields}


def build_github_issue_payload(
    finding: Finding,
    *,
    assignees: tuple[str, ...] = (),
    milestone: int | None = None,
) -> GitHubIssuePayload:
    return GitHubIssuePayload(
        title=f"[{finding.severity.value.upper()}] {finding.title}",
        body=_issue_body(finding),
        labels=_github_labels(finding),
        assignees=[assignee.strip() for assignee in assignees if assignee.strip()],
        milestone=milestone,
    )


def build_jira_issue_payload(
    finding: Finding,
    *,
    issue_type: str = "Task",
    components: tuple[str, ...] = (),
) -> JiraIssuePayload:
    priority_map = {
        Severity.CRITICAL: "Highest",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Medium",
        Severity.LOW: "Low",
        Severity.INFO: "Lowest",
    }
    due_date = _normalize_due_date(compute_sla(finding).get("deadline"))
    return JiraIssuePayload(
        summary=f"[{finding.severity.value.upper()}] {finding.title}",
        description=_issue_body(finding),
        labels=_jira_labels(finding),
        issue_type=issue_type,
        priority=priority_map[finding.severity],
        components=[component.strip() for component in components if component.strip()],
        due_date=due_date,
    )


def export_issue_sync_payloads(
    findings: list[Finding],
    *,
    target: str,
    repo: str | None = None,
    project_key: str | None = None,
    assignees: tuple[str, ...] = (),
    components: tuple[str, ...] = (),
    issue_type: str = "Task",
    milestone: int | None = None,
    only_open: bool = True,
) -> dict[str, Any]:
    normalized_target = target.strip().lower()
    if normalized_target not in {"github", "jira"}:
        raise ValueError("target must be either 'github' or 'jira'")
    if normalized_target == "github" and not (repo or "").strip():
        raise ValueError("repo is required for GitHub exports")
    if normalized_target == "jira" and not (project_key or "").strip():
        raise ValueError("project_key is required for JIRA exports")

    selected = [finding for finding in findings if finding.is_open()] if only_open else list(findings)
    sorted_findings = sorted(selected, key=_finding_sort_key)

    items: list[dict[str, Any]] = []
    for finding in sorted_findings:
        if normalized_target == "github":
            issue = build_github_issue_payload(finding, assignees=assignees, milestone=milestone)
            items.append(
                {
                    "finding_id": finding.id,
                    "target": "github",
                    "repo": repo,
                    "payload": issue.to_dict(),
                }
            )
        else:
            issue = build_jira_issue_payload(finding, issue_type=issue_type, components=components)
            items.append(
                {
                    "finding_id": finding.id,
                    "target": "jira",
                    "project_key": project_key,
                    "payload": issue.to_dict(project_key=project_key or ""),
                }
            )

    return {
        "target": normalized_target,
        "generated_items": len(items),
        "only_open": only_open,
        "items": items,
    }
