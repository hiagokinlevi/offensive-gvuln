from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from typing import Any

import jwt
from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
import uvicorn


API_SECRET_ENV = "OFFENSIVE_GVULN_API_SECRET"


class Finding(BaseModel):
    finding_id: str
    title: str
    severity: str
    status: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


app = FastAPI(title="offensive-gvuln findings api")
_FINDINGS: dict[str, Finding] = {}
_WS_CLIENTS: set[WebSocket] = set()


def _jwt_secret() -> str | None:
    secret = os.getenv(API_SECRET_ENV)
    return secret if secret and secret.strip() else None


def _auth_effectively_enabled() -> bool:
    return _jwt_secret() is not None


def _require_bearer_auth(authorization: str | None = Header(default=None)) -> None:
    secret = _jwt_secret()
    if not secret:
        return
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    try:
        jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/findings", dependencies=[Depends(_require_bearer_auth)])
def list_findings() -> list[dict[str, Any]]:
    return [f.model_dump(mode="json") for f in _FINDINGS.values()]


@app.post("/findings", dependencies=[Depends(_require_bearer_auth)])
def create_finding(finding: Finding) -> dict[str, Any]:
    _FINDINGS[finding.finding_id] = finding
    return finding.model_dump(mode="json")


@app.websocket("/ws/sla")
async def ws_sla(websocket: WebSocket) -> None:
    await websocket.accept()
    _WS_CLIENTS.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _WS_CLIENTS.discard(websocket)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run offensive-gvuln findings API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    parser.add_argument("--require-auth", action="store_true", help=f"Refuse startup unless JWT auth is enabled via {API_SECRET_ENV}")
    return parser.parse_args(argv)


def _validate_startup(require_auth: bool) -> None:
    if require_auth and not _auth_effectively_enabled():
        raise RuntimeError(
            f"--require-auth set but JWT auth is not effectively enabled: set non-empty {API_SECRET_ENV}."
        )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        _validate_startup(args.require_auth)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
