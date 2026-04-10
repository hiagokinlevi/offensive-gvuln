"""Dependency-light JWT verification for the optional findings API."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class JWTAuthError(ValueError):
    """Raised when a JWT cannot be trusted for API access."""


@dataclass(frozen=True)
class JWTAuthConfig:
    """Authentication policy for HS256 bearer tokens."""

    secret: str
    audience: str | None = None
    issuer: str | None = None
    required_scopes: tuple[str, ...] = ()
    clock_skew_seconds: int = 60


def _decode_json_segment(segment: str) -> dict[str, Any]:
    padded = f"{segment}{'=' * (-len(segment) % 4)}"
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        decoded = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise JWTAuthError("JWT segment is not valid base64url JSON") from exc
    if not isinstance(decoded, dict):
        raise JWTAuthError("JWT segment must decode to an object")
    return decoded


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _claim_as_timestamp(claims: dict[str, Any], name: str) -> int | None:
    value = claims.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise JWTAuthError(f"JWT {name} claim must be a numeric timestamp")
    return int(value)


def _claim_scopes(claims: dict[str, Any]) -> set[str]:
    raw = claims.get("scope", claims.get("scp", ""))
    if isinstance(raw, str):
        return {scope for scope in raw.split() if scope}
    if isinstance(raw, list):
        return {str(scope) for scope in raw if str(scope)}
    raise JWTAuthError("JWT scope claim must be a string or list")


def verify_jwt_token(
    token: str,
    config: JWTAuthConfig,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify an HS256 bearer token and return its claims."""
    if not config.secret:
        raise JWTAuthError("JWT auth secret is not configured")

    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        raise JWTAuthError("JWT must contain header, payload, and signature")

    header = _decode_json_segment(parts[0])
    claims = _decode_json_segment(parts[1])
    if header.get("alg") != "HS256":
        raise JWTAuthError("Only HS256 JWTs are accepted")
    if header.get("typ") not in (None, "JWT"):
        raise JWTAuthError("JWT typ header must be JWT when present")

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    expected = _b64url(hmac.new(config.secret.encode("utf-8"), signing_input, hashlib.sha256).digest())
    if not hmac.compare_digest(expected, parts[2]):
        raise JWTAuthError("JWT signature verification failed")

    reference = int((now or datetime.now(timezone.utc)).timestamp())
    skew = config.clock_skew_seconds
    exp = _claim_as_timestamp(claims, "exp")
    if exp is None:
        raise JWTAuthError("JWT exp claim is required")
    if exp <= reference - skew:
        raise JWTAuthError("JWT has expired")

    nbf = _claim_as_timestamp(claims, "nbf")
    if nbf is not None and nbf > reference + skew:
        raise JWTAuthError("JWT is not valid yet")

    iat = _claim_as_timestamp(claims, "iat")
    if iat is not None and iat > reference + skew:
        raise JWTAuthError("JWT iat claim is in the future")

    if config.issuer is not None and claims.get("iss") != config.issuer:
        raise JWTAuthError("JWT issuer is not trusted")

    if config.audience is not None:
        audience = claims.get("aud")
        if isinstance(audience, str):
            audiences = {audience}
        elif isinstance(audience, list):
            audiences = {str(item) for item in audience}
        else:
            raise JWTAuthError("JWT audience claim is required")
        if config.audience not in audiences:
            raise JWTAuthError("JWT audience is not trusted")

    missing_scopes = set(config.required_scopes) - _claim_scopes(claims)
    if missing_scopes:
        raise JWTAuthError(f"JWT missing required scopes: {', '.join(sorted(missing_scopes))}")

    return claims
