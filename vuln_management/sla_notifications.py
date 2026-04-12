"""Slack and Teams webhook notifications for SLA breach reporting."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import socket
from typing import Any
from urllib import parse, request

from vuln_management.sla_report import FindingSLAStatus, SLAReport


_TIER_ORDER = {
    "critical_breach": 0,
    "breached": 1,
    "warning": 2,
}


@dataclass(frozen=True, slots=True)
class NotificationPayload:
    """Serialized webhook payload plus a plain-text summary."""

    channel: str
    summary: str
    body: dict[str, Any]


def _resolve_global_webhook_ips(hostname: str, *, port: int) -> None:
    """Reject hostnames that resolve to loopback or other non-public addresses."""
    try:
        addrinfo = socket.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise ValueError("webhook_url hostname could not be resolved") from exc

    resolved_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for family, _, _, _, sockaddr in addrinfo:
        if family not in {socket.AF_INET, socket.AF_INET6}:
            continue
        try:
            resolved_ips.add(ipaddress.ip_address(sockaddr[0]))
        except ValueError:
            continue

    if not resolved_ips:
        raise ValueError("webhook_url hostname could not be resolved")
    if any(not ip_address.is_global for ip_address in resolved_ips):
        raise ValueError("webhook_url must not resolve to loopback or non-public IP addresses")


def _validate_webhook_url(webhook_url: str) -> str:
    normalized_url = webhook_url.strip()
    if not normalized_url:
        raise ValueError("webhook_url must not be empty")

    parsed = parse.urlsplit(normalized_url)
    if parsed.scheme.lower() != "https":
        raise ValueError("webhook_url must use https")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("webhook_url must include a hostname")
    if parsed.username or parsed.password:
        raise ValueError("webhook_url must not include embedded credentials")

    hostname = parsed.hostname.strip().rstrip(".")
    normalized_hostname = hostname.lower()
    if normalized_hostname == "localhost" or normalized_hostname.endswith(".localhost"):
        raise ValueError("webhook_url must not target localhost")

    try:
        ip_address = ipaddress.ip_address(hostname)
    except ValueError:
        _resolve_global_webhook_ips(hostname, port=parsed.port or 443)
        return normalized_url

    if not ip_address.is_global:
        raise ValueError("webhook_url must not target loopback or non-public IP addresses")
    return normalized_url


def _selected_statuses(report: SLAReport, minimum_tier: str) -> list[FindingSLAStatus]:
    normalized_tier = minimum_tier.strip().lower().replace("-", "_")
    if normalized_tier not in _TIER_ORDER:
        raise ValueError(f"unsupported minimum_tier: {minimum_tier}")

    ranked_statuses: list[tuple[int, FindingSLAStatus]] = []
    for status in report.critical_breach:
        ranked_statuses.append((_TIER_ORDER["critical_breach"], status))
    for status in report.breached:
        ranked_statuses.append((_TIER_ORDER["breached"], status))
    for status in report.warning:
        ranked_statuses.append((_TIER_ORDER["warning"], status))

    threshold = _TIER_ORDER[normalized_tier]
    selected = [status for rank, status in ranked_statuses if rank <= threshold]
    selected.sort(key=lambda item: (item.remaining_hours, item.finding.id))
    return selected


def _notification_summary(
    report: SLAReport,
    *,
    minimum_tier: str,
    max_findings: int,
) -> tuple[str, list[FindingSLAStatus]]:
    selected = _selected_statuses(report, minimum_tier)
    sample = selected[:max_findings]
    summary = (
        f"SLA alert: {len(report.critical_breach)} critical breach, "
        f"{len(report.breached)} breached, {len(report.warning)} warning, "
        f"{report.total_open} open findings."
    )
    return summary, sample


def build_notification_payload(
    report: SLAReport,
    *,
    channel: str,
    repository_label: str = "offensive-gvuln",
    minimum_tier: str = "breached",
    max_findings: int = 5,
) -> NotificationPayload:
    """Build a Slack or Teams webhook payload for the current SLA report."""
    normalized_channel = channel.strip().lower()
    if normalized_channel not in {"slack", "teams"}:
        raise ValueError(f"unsupported channel: {channel}")
    if max_findings <= 0:
        raise ValueError("max_findings must be > 0")

    summary, sample = _notification_summary(
        report,
        minimum_tier=minimum_tier,
        max_findings=max_findings,
    )
    generated_at = report.generated_at.strftime("%Y-%m-%d %H:%M UTC")
    detail_lines = [
        (
            f"- {status.finding.id} | {status.finding.severity.value.upper()} | "
            f"{status.finding.title} | "
            f"{abs(status.remaining_hours):.1f}h overdue"
            if status.remaining_hours < 0
            else f"- {status.finding.id} | {status.finding.severity.value.upper()} | "
            f"{status.finding.title} | {status.remaining_hours:.1f}h remaining"
        )
        for status in sample
    ]
    details = "\n".join(detail_lines) if detail_lines else "- No findings matched the selected tier."

    if normalized_channel == "slack":
        body = {
            "text": f"{repository_label}: {summary}",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"{repository_label} SLA alert"},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": summary},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Generated*\n{generated_at}"},
                        {"type": "mrkdwn", "text": f"*Compliance*\n{report.compliance_rate * 100:.0f}%"},
                        {"type": "mrkdwn", "text": f"*Threshold*\n{minimum_tier}+"},
                        {"type": "mrkdwn", "text": f"*Top findings*\n{len(sample)}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": details},
                },
            ],
        }
        return NotificationPayload(channel=normalized_channel, summary=summary, body=body)

    body = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "C43C35" if report.breach_count else "E0A100",
        "summary": f"{repository_label}: {summary}",
        "title": f"{repository_label} SLA alert",
        "sections": [
            {
                "activityTitle": summary,
                "activitySubtitle": generated_at,
                "facts": [
                    {"name": "Compliance", "value": f"{report.compliance_rate * 100:.0f}%"},
                    {"name": "Critical breach", "value": str(len(report.critical_breach))},
                    {"name": "Breached", "value": str(len(report.breached))},
                    {"name": "Warning", "value": str(len(report.warning))},
                    {"name": "Threshold", "value": minimum_tier},
                ],
                "text": details.replace("\n", "<br>"),
            }
        ],
    }
    return NotificationPayload(channel=normalized_channel, summary=summary, body=body)


def send_webhook_notification(
    webhook_url: str,
    payload: NotificationPayload,
    *,
    timeout: int = 10,
) -> int:
    """Send a JSON webhook payload and return the HTTP status code."""
    normalized_url = _validate_webhook_url(webhook_url)
    raw_body = json.dumps(payload.body).encode("utf-8")
    req = request.Request(
        normalized_url,
        data=raw_body,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout) as response:  # nosec: defensive webhook delivery
        return getattr(response, "status", response.getcode())
