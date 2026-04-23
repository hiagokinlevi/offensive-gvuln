from __future__ import annotations

import json
from typing import Any, Dict

import requests


def build_webhook_payload(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Build a normalized notification payload for Slack/Teams."""
    return {
        "id": finding.get("id"),
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "status": finding.get("status"),
        "owner": finding.get("owner"),
        "sla_due": finding.get("sla_due"),
    }


def send_webhook_notification(
    webhook_url: str,
    channel: str,
    finding: Dict[str, Any],
    timeout_seconds: int = 10,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """
    Send Slack/Teams webhook notification.

    When dry_run=True, prints exact payload + target metadata and skips network I/O.
    """
    payload = build_webhook_payload(finding)
    metadata = {
        "channel": channel,
        "webhook_url": webhook_url,
        "provider": "teams" if "office.com" in webhook_url or "teams" in webhook_url else "slack",
    }

    if dry_run:
        print(json.dumps({"dry_run": True, "target": metadata, "payload": payload}, sort_keys=True))
        return {"sent": False, "dry_run": True, "target": metadata, "payload": payload}

    response = requests.post(webhook_url, json=payload, timeout=timeout_seconds)
    response.raise_for_status()
    return {
        "sent": True,
        "dry_run": False,
        "status_code": response.status_code,
        "target": metadata,
        "payload": payload,
    }
