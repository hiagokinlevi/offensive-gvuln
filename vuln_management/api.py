"""Optional FastAPI REST adapter for vulnerability findings CRUD."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from vuln_management.api_auth import JWTAuthConfig, JWTAuthError, verify_jwt_token
from vuln_management.models import Finding, FindingStatus, Severity


class FindingPatch(BaseModel):
    """Partial update payload for finding records."""

    title: str | None = None
    severity: Severity | None = None
    status: FindingStatus | None = None
    description: str | None = None
    affected_asset: str | None = None
    cvss_score: float | None = None
    cve_id: str | None = None

    def updates(self) -> dict[str, Any]:
        """Return only fields explicitly set by the caller."""
        return self.model_dump(exclude_unset=True)


class JsonFindingStore:
    """Small JSON-backed finding store used by the REST adapter and tests."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._findings: dict[str, Finding] = {}
        self.reload()

    def reload(self) -> None:
        """Reload findings from disk, treating a missing file as an empty store."""
        if not self.path.exists():
            self._findings = {}
            return

        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("Findings store must contain a JSON array")
        self._findings = {finding.id: finding for finding in (Finding(**item) for item in raw)}

    def save(self) -> None:
        """Persist all findings to disk in deterministic order."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [finding.model_dump(mode="json") for finding in self.list()]
        self.path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    def list(
        self,
        *,
        status: FindingStatus | None = None,
        open_only: bool = False,
    ) -> list[Finding]:
        """Return findings, optionally filtered by lifecycle status."""
        findings = sorted(self._findings.values(), key=lambda finding: finding.id)
        if status is not None:
            findings = [finding for finding in findings if finding.status == status]
        if open_only:
            findings = [finding for finding in findings if finding.is_open()]
        return findings

    def get(self, finding_id: str) -> Finding:
        """Return one finding or raise KeyError."""
        try:
            return self._findings[finding_id]
        except KeyError as exc:
            raise KeyError(f"Finding {finding_id!r} not found") from exc

    def create(self, finding: Finding) -> Finding:
        """Create a finding, rejecting accidental ID collisions."""
        if finding.id in self._findings:
            raise ValueError(f"Finding {finding.id!r} already exists")
        self._findings[finding.id] = finding
        self.save()
        return finding

    def replace(self, finding_id: str, finding: Finding) -> Finding:
        """Replace a finding while preserving URL/body ID consistency."""
        self.get(finding_id)
        if finding.id != finding_id:
            raise ValueError("Finding body id must match the route id")
        self._findings[finding_id] = finding
        self.save()
        return finding

    def patch(self, finding_id: str, patch: FindingPatch) -> Finding:
        """Partially update a finding."""
        finding = self.get(finding_id)
        updated = finding.model_copy(update=patch.updates())
        self._findings[finding_id] = updated
        self.save()
        return updated

    def delete(self, finding_id: str) -> Finding:
        """Delete and return a finding."""
        finding = self.get(finding_id)
        del self._findings[finding_id]
        self.save()
        return finding


def create_app(
    storage_path: str | Path = "findings-api.json",
    *,
    jwt_secret: str | None = None,
):
    """Create the FastAPI application for findings CRUD."""
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException, Query
    except ModuleNotFoundError as exc:  # pragma: no cover - depends on optional extra
        raise RuntimeError(
            "FastAPI support requires the optional api extra: "
            "pip install -e '.[api]'"
        ) from exc

    app = FastAPI(
        title="Offensive GVuln API",
        version="0.1.0",
        description="Defensive vulnerability findings CRUD API.",
    )
    store = JsonFindingStore(storage_path)
    resolved_jwt_secret = (jwt_secret or os.getenv("GVULN_API_JWT_SECRET", "")).strip()
    auth_config = JWTAuthConfig(
        secret=resolved_jwt_secret,
        required_scopes=("findings:write",),
    )

    def _not_found(exc: KeyError) -> HTTPException:
        return HTTPException(status_code=404, detail=str(exc))

    def _require_auth(authorization: str | None = Header(default=None)) -> dict[str, Any] | None:
        if not resolved_jwt_secret:
            return None
        if not authorization or not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Bearer JWT required")
        token = authorization.split(" ", 1)[1].strip()
        try:
            return verify_jwt_token(token, auth_config)
        except JWTAuthError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "storage_path": str(store.path)}

    @app.get("/findings", response_model=list[Finding])
    def list_findings(
        status: FindingStatus | None = Query(default=None),
        open_only: bool = Query(default=False),
        _claims: dict[str, Any] | None = Depends(_require_auth),
    ) -> list[Finding]:
        return store.list(status=status, open_only=open_only)

    @app.post("/findings", response_model=Finding, status_code=201)
    def create_finding(
        finding: Finding,
        _claims: dict[str, Any] | None = Depends(_require_auth),
    ) -> Finding:
        try:
            return store.create(finding)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/findings/{finding_id}", response_model=Finding)
    def get_finding(
        finding_id: str,
        _claims: dict[str, Any] | None = Depends(_require_auth),
    ) -> Finding:
        try:
            return store.get(finding_id)
        except KeyError as exc:
            raise _not_found(exc) from exc

    @app.put("/findings/{finding_id}", response_model=Finding)
    def replace_finding(
        finding_id: str,
        finding: Finding,
        _claims: dict[str, Any] | None = Depends(_require_auth),
    ) -> Finding:
        try:
            return store.replace(finding_id, finding)
        except KeyError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.patch("/findings/{finding_id}", response_model=Finding)
    def patch_finding(
        finding_id: str,
        patch: FindingPatch,
        _claims: dict[str, Any] | None = Depends(_require_auth),
    ) -> Finding:
        try:
            return store.patch(finding_id, patch)
        except KeyError as exc:
            raise _not_found(exc) from exc

    @app.delete("/findings/{finding_id}", status_code=204)
    def delete_finding(
        finding_id: str,
        _claims: dict[str, Any] | None = Depends(_require_auth),
    ) -> None:
        try:
            store.delete(finding_id)
        except KeyError as exc:
            raise _not_found(exc) from exc

    return app
