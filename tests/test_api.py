"""Tests for the optional REST API storage layer."""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vuln_management.api import FindingPatch, JsonFindingStore, create_app
from vuln_management.api_auth import JWTAuthConfig, JWTAuthError, verify_jwt_token
from vuln_management.models import Finding, FindingStatus, Severity


def _finding(
    finding_id: str = "finding-001",
    status: FindingStatus = FindingStatus.OPEN,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        id=finding_id,
        title="SQL Injection in login",
        severity=severity,
        status=status,
        description="Unsanitized input reaches a query builder.",
        affected_asset="app.example.com/login",
    )


def _jwt(claims: dict[str, object], secret: str = "unit-test-secret") -> str:
    header = {"alg": "HS256", "typ": "JWT"}

    def encode(data: dict[str, object]) -> str:
        raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    signing_input = f"{encode(header)}.{encode(claims)}"
    signature = hmac.new(secret.encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{signing_input}.{encoded_signature}"


def test_store_creates_and_persists_findings(tmp_path: Path) -> None:
    store_path = tmp_path / "findings.json"
    store = JsonFindingStore(store_path)

    created = store.create(_finding())

    assert created.id == "finding-001"
    persisted = json.loads(store_path.read_text(encoding="utf-8"))
    assert persisted[0]["id"] == "finding-001"
    assert JsonFindingStore(store_path).get("finding-001").title == "SQL Injection in login"


def test_store_filters_by_status_and_open_only(tmp_path: Path) -> None:
    store = JsonFindingStore(tmp_path / "findings.json")
    store.create(_finding("open-1", status=FindingStatus.OPEN, severity=Severity.CRITICAL))
    store.create(_finding("closed-1", status=FindingStatus.CLOSED, severity=Severity.LOW))
    store.create(_finding("triaged-1", status=FindingStatus.TRIAGED, severity=Severity.MEDIUM))

    assert [finding.id for finding in store.list(status=FindingStatus.TRIAGED)] == ["triaged-1"]
    assert [finding.id for finding in store.list(open_only=True)] == ["open-1", "triaged-1"]


def test_store_replaces_patches_and_deletes(tmp_path: Path) -> None:
    store = JsonFindingStore(tmp_path / "findings.json")
    store.create(_finding())

    replaced = _finding("finding-001", status=FindingStatus.TRIAGED)
    replaced.title = "Validated SQL injection"
    store.replace("finding-001", replaced)
    patched = store.patch("finding-001", FindingPatch(severity=Severity.CRITICAL, cve_id="CVE-2026-1111"))

    assert patched.title == "Validated SQL injection"
    assert patched.severity == Severity.CRITICAL
    assert patched.cve_id == "CVE-2026-1111"
    assert store.delete("finding-001").id == "finding-001"
    assert store.list() == []


def test_store_rejects_duplicate_and_mismatched_ids(tmp_path: Path) -> None:
    store = JsonFindingStore(tmp_path / "findings.json")
    store.create(_finding())

    with pytest.raises(ValueError, match="already exists"):
        store.create(_finding())

    with pytest.raises(ValueError, match="body id"):
        store.replace("finding-001", _finding("different-id"))


def test_store_rejects_non_array_json(tmp_path: Path) -> None:
    store_path = tmp_path / "findings.json"
    store_path.write_text('{"id": "not-a-list"}', encoding="utf-8")

    with pytest.raises(ValueError, match="JSON array"):
        JsonFindingStore(store_path)


def test_verify_hs256_jwt_accepts_valid_scoped_token() -> None:
    token = _jwt(
        {
            "sub": "api-client",
            "scope": "findings:write findings:read",
            "exp": 2_000_000_000,
        }
    )

    claims = verify_jwt_token(
        token,
        JWTAuthConfig(secret="unit-test-secret", required_scopes=("findings:write",)),
        now=datetime.fromtimestamp(1_800_000_000, tz=timezone.utc),
    )

    assert claims["sub"] == "api-client"


def test_verify_hs256_jwt_rejects_tampered_and_unscoped_tokens() -> None:
    token = _jwt({"sub": "api-client", "scope": "findings:write", "exp": 2_000_000_000})
    tampered = f"{token[:-1]}x"

    config = JWTAuthConfig(secret="unit-test-secret", required_scopes=("findings:write",))
    now = datetime.fromtimestamp(1_800_000_000, tz=timezone.utc)

    with pytest.raises(JWTAuthError, match="signature"):
        verify_jwt_token(tampered, config, now=now)

    with pytest.raises(JWTAuthError, match="required scopes"):
        verify_jwt_token(
            _jwt({"sub": "api-client", "scope": "findings:read", "exp": 2_000_000_000}),
            config,
            now=now,
        )


def test_verify_hs256_jwt_rejects_expired_token() -> None:
    token = _jwt({"sub": "api-client", "scope": "findings:write", "exp": 1_700_000_000})

    with pytest.raises(JWTAuthError, match="expired"):
        verify_jwt_token(
            token,
            JWTAuthConfig(secret="unit-test-secret", required_scopes=("findings:write",)),
            now=datetime.fromtimestamp(1_800_000_000, tz=timezone.utc),
        )


def test_verify_hs256_jwt_requires_expiration() -> None:
    token = _jwt({"sub": "api-client", "scope": "findings:write"})

    with pytest.raises(JWTAuthError, match="exp"):
        verify_jwt_token(
            token,
            JWTAuthConfig(secret="unit-test-secret", required_scopes=("findings:write",)),
            now=datetime.fromtimestamp(1_800_000_000, tz=timezone.utc),
        )


def test_create_app_requires_api_extra_when_fastapi_is_absent(tmp_path: Path) -> None:
    if importlib.util.find_spec("fastapi") is not None:
        app = create_app(tmp_path / "findings.json")
        assert app.title == "Offensive GVuln API"
        return

    with pytest.raises(RuntimeError, match="optional api extra"):
        create_app(tmp_path / "findings.json")


def test_findings_routes_require_jwt_when_secret_is_configured(tmp_path: Path) -> None:
    if importlib.util.find_spec("fastapi") is None:
        pytest.skip("FastAPI extra is not installed")

    from fastapi.testclient import TestClient

    app = create_app(tmp_path / "findings.json", jwt_secret="unit-test-secret")
    client = TestClient(app)

    assert client.get("/health").status_code == 200
    assert client.get("/findings").status_code == 401

    token = _jwt(
        {
            "sub": "api-client",
            "scope": "findings:write",
            "exp": 2_000_000_000,
        }
    )
    response = client.get("/findings", headers={"Authorization": f"bearer {token}"})

    assert response.status_code == 200
    assert response.json() == []
