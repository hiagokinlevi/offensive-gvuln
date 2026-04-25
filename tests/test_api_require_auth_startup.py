from __future__ import annotations

from vuln_management import api


def test_require_auth_fails_without_secret(monkeypatch, capsys):
    monkeypatch.delenv(api.API_SECRET_ENV, raising=False)

    rc = api.main(["--require-auth"])

    assert rc == 1
    err = capsys.readouterr().err
    assert "--require-auth set but JWT auth is not effectively enabled" in err


def test_require_auth_starts_with_secret(monkeypatch):
    monkeypatch.setenv(api.API_SECRET_ENV, "super-secret")
    called = {}

    def fake_run(app, host, port):
        called["host"] = host
        called["port"] = port
        called["app"] = app

    monkeypatch.setattr(api.uvicorn, "run", fake_run)

    rc = api.main(["--require-auth", "--host", "0.0.0.0", "--port", "9000"])

    assert rc == 0
    assert called["host"] == "0.0.0.0"
    assert called["port"] == 9000
    assert called["app"] is api.app
