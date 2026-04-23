from vuln_management.notifications import send_webhook_notification


def test_webhook_dry_run_skips_http_call(monkeypatch, capsys):
    called = {"post": 0}

    def _fake_post(*args, **kwargs):
        called["post"] += 1
        raise AssertionError("requests.post should not be called in dry-run mode")

    monkeypatch.setattr("vuln_management.notifications.requests.post", _fake_post)

    finding = {
        "id": "F-001",
        "title": "SQL Injection",
        "severity": "High",
        "status": "open",
        "owner": "appsec",
        "sla_due": "2026-05-01T00:00:00Z",
    }

    result = send_webhook_notification(
        webhook_url="https://hooks.slack.com/services/T000/B000/XXX",
        channel="#security-alerts",
        finding=finding,
        dry_run=True,
    )

    assert called["post"] == 0
    assert result["dry_run"] is True
    assert result["sent"] is False

    out = capsys.readouterr().out
    assert '"dry_run": true' in out.lower()
    assert '"channel": "#security-alerts"' in out
    assert '"id": "F-001"' in out
