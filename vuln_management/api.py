"""Optional FastAPI REST and WebSocket adapter for vulnerability findings."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from vuln_management.api_auth import JWTAuthConfig, JWTAuthError, verify_jwt_token
from vuln_management.models import Finding, FindingStatus, Severity
from vuln_management.sla_report import FindingSLAStatus, SLAReport, build_sla_report


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


def _serialize_sla_status(status: FindingSLAStatus) -> dict[str, Any]:
    """Return a JSON-safe SLA status for WebSocket alert payloads."""
    return {
        "finding": status.finding.model_dump(mode="json"),
        "has_sla": status.has_sla,
        "elapsed_hours": status.elapsed_hours,
        "window_hours": status.window_hours,
        "deadline": status.deadline.isoformat() if status.deadline else None,
        "remaining_hours": status.remaining_hours,
        "elapsed_pct": status.elapsed_pct,
        "escalation": status.escalation,
    }


def build_sla_alert_payload(findings: list[Finding]) -> dict[str, Any]:
    """Build a deterministic SLA alert snapshot for WebSocket clients."""
    report: SLAReport = build_sla_report(findings)
    return {
        "type": "sla_alert_snapshot",
        "generated_at": report.generated_at.isoformat(),
        "total_open": report.total_open,
        "breach_count": report.breach_count,
        "compliance_rate": report.compliance_rate,
        "critical_breach": [_serialize_sla_status(status) for status in report.critical_breach],
        "breached": [_serialize_sla_status(status) for status in report.breached],
        "warning": [_serialize_sla_status(status) for status in report.warning],
    }


class SLAAlertHub:
    """Track connected WebSocket clients and publish SLA snapshots."""

    def __init__(self) -> None:
        self._clients: set[Any] = set()

    async def connect(self, websocket: Any) -> None:
        await websocket.accept()
        self._clients.add(websocket)

    def disconnect(self, websocket: Any) -> None:
        self._clients.discard(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        for websocket in list(self._clients):
            try:
                await websocket.send_json(payload)
            except Exception:
                self.disconnect(websocket)


def create_app(
    storage_path: str | Path = "findings-api.json",
    *,
    jwt_secret: str | None = None,
):
    """Create the FastAPI application for findings CRUD."""
    try:
        from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
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
    alert_hub = SLAAlertHub()
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

    def _require_websocket_auth(websocket: WebSocket) -> bool:
        if not resolved_jwt_secret:
            return True
        token = websocket.query_params.get("token", "").strip()
        header = websocket.headers.get("authorization", "")
        if not token and header.lower().startswith("bearer "):
            token = header.split(" ", 1)[1].strip()
        if not token:
            return False
        try:
            verify_jwt_token(token, auth_config)
        except JWTAuthError:
            return False
        return True

    def _sla_payload() -> dict[str, Any]:
        return build_sla_alert_payload(store.list(open_only=True))

    async def _broadcast_sla_alerts() -> None:
        await alert_hub.broadcast(_sla_payload())

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
    async def create_finding(
        finding: Finding,
        _claims: dict[str, Any] | None = Depends(_require_auth),
    ) -> Finding:
        try:
            created = store.create(finding)
            await _broadcast_sla_alerts()
            return created
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
    async def replace_finding(
        finding_id: str,
        finding: Finding,
        _claims: dict[str, Any] | None = Depends(_require_auth),
    ) -> Finding:
        try:
            replaced = store.replace(finding_id, finding)
            await _broadcast_sla_alerts()
            return replaced
        except KeyError as exc:
            raise _not_found(exc) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.patch("/findings/{finding_id}", response_model=Finding)
    async def patch_finding(
        finding_id: str,
        patch: FindingPatch,
        _claims: dict[str, Any] | None = Depends(_require_auth),
    ) -> Finding:
        try:
            patched = store.patch(finding_id, patch)
            await _broadcast_sla_alerts()
            return patched
        except KeyError as exc:
            raise _not_found(exc) from exc

    @app.delete("/findings/{finding_id}", status_code=204)
    async def delete_finding(
        finding_id: str,
        _claims: dict[str, Any] | None = Depends(_require_auth),
    ) -> None:
        try:
            store.delete(finding_id)
            await _broadcast_sla_alerts()
        except KeyError as exc:
            raise _not_found(exc) from exc

    @app.websocket("/sla/alerts")
    async def sla_alerts(websocket: WebSocket) -> None:
        if not _require_websocket_auth(websocket):
            await websocket.close(code=1008)
            return

        await alert_hub.connect(websocket)
        try:
            await websocket.send_json(_sla_payload())
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            alert_hub.disconnect(websocket)

    return app
