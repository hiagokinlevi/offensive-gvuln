"""Fluxo defensivo de aceitação de risco com assinatura de aprovador.

Este módulo implementa:
- modelo auditável de aceitação de risco;
- assinatura determinística baseada em hash para integridade do registro;
- verificação de assinatura e validade temporal;
- aplicação controlada da aceitação no lifecycle de um finding.

Observação:
Este mecanismo é voltado a governança e rastreabilidade em laboratório/produção
autorizada. Não substitui assinatura criptográfica corporativa formal.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import hashlib
import hmac
import json
from typing import Iterable
import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

from vuln_management.lifecycle import transition
from vuln_management.models import Finding, FindingStatus


def _now_utc() -> datetime:
    """Retorna o horário atual em UTC com timezone explícito."""
    return datetime.now(timezone.utc)


def _normalize_datetime(value: datetime) -> datetime:
    """Normaliza datetimes para UTC, preservando precisão."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _canonical_payload(data: dict[str, object]) -> str:
    """Gera payload canônico para assinatura estável."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


class RiskAcceptanceRecord(BaseModel):
    """Representa uma aprovação formal de aceitação de risco."""

    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    finding_id: str
    requested_by: str
    approved_by: str
    reason: str
    compensating_controls: list[str] = Field(default_factory=list)
    policy_reference: str | None = None
    approved_at: datetime = Field(default_factory=_now_utc)
    expires_at: datetime
    signature: str

    @field_validator("finding_id", "requested_by", "approved_by", "reason")
    @classmethod
    def _non_empty_required(cls, value: str) -> str:
        """Impede campos textuais obrigatórios vazios."""
        normalized = value.strip()
        if not normalized:
            raise ValueError("required field must not be empty")
        return normalized

    @field_validator("compensating_controls")
    @classmethod
    def _strip_controls(cls, values: list[str]) -> list[str]:
        """Normaliza controles compensatórios removendo itens vazios."""
        return [item.strip() for item in values if item.strip()]

    @model_validator(mode="after")
    def _validate_governance_constraints(self) -> "RiskAcceptanceRecord":
        """Valida regras de governança da aceitação de risco."""
        self.approved_at = _normalize_datetime(self.approved_at)
        self.expires_at = _normalize_datetime(self.expires_at)

        if self.requested_by == self.approved_by:
            raise ValueError("requested_by and approved_by must be different")
        if self.expires_at <= self.approved_at:
            raise ValueError("expires_at must be later than approved_at")
        if not self.signature.strip():
            raise ValueError("signature must not be empty")
        return self

    def is_expired(self, reference_time: datetime | None = None) -> bool:
        """Indica se o registro já expirou na referência informada."""
        reference = _normalize_datetime(reference_time or _now_utc())
        return self.expires_at <= reference

    def expires_within(self, days: int, reference_time: datetime | None = None) -> bool:
        """Retorna True quando expira dentro da janela de dias."""
        if days < 0:
            raise ValueError("days must be >= 0")
        reference = _normalize_datetime(reference_time or _now_utc())
        window_end = reference + timedelta(days=days)
        return reference <= self.expires_at <= window_end

    def signature_payload(self) -> dict[str, object]:
        """Retorna o payload usado para cálculo de assinatura."""
        return {
            "record_id": self.record_id,
            "finding_id": self.finding_id,
            "requested_by": self.requested_by,
            "approved_by": self.approved_by,
            "reason": self.reason,
            "compensating_controls": self.compensating_controls,
            "policy_reference": self.policy_reference,
            "approved_at": self.approved_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }


def build_signature(payload: dict[str, object], signing_key: str) -> str:
    """Calcula assinatura determinística HMAC-SHA256 do payload canônico."""
    if not signing_key.strip():
        raise ValueError("signing_key must not be empty")
    canonical = _canonical_payload(payload).encode("utf-8")
    secret = signing_key.encode("utf-8")
    return hmac.new(secret, canonical, hashlib.sha256).hexdigest()


def create_risk_acceptance_record(
    *,
    finding_id: str,
    requested_by: str,
    approved_by: str,
    reason: str,
    expires_at: datetime,
    signing_key: str,
    compensating_controls: Iterable[str] | None = None,
    policy_reference: str | None = None,
    approved_at: datetime | None = None,
) -> RiskAcceptanceRecord:
    """Cria um registro assinado de aceitação de risco."""
    record_fields = {
        "record_id": str(uuid.uuid4()),
        "finding_id": finding_id.strip(),
        "requested_by": requested_by.strip(),
        "approved_by": approved_by.strip(),
        "reason": reason.strip(),
        "compensating_controls": [item.strip() for item in (compensating_controls or []) if item.strip()],
        "policy_reference": policy_reference.strip() if policy_reference else None,
        "approved_at": _normalize_datetime(approved_at or _now_utc()),
        "expires_at": _normalize_datetime(expires_at),
    }
    signature = build_signature(
        {
            **record_fields,
            "approved_at": record_fields["approved_at"].isoformat(),
            "expires_at": record_fields["expires_at"].isoformat(),
        },
        signing_key=signing_key,
    )
    return RiskAcceptanceRecord(**record_fields, signature=signature)


def verify_risk_acceptance_signature(record: RiskAcceptanceRecord, signing_key: str) -> bool:
    """Verifica a integridade do registro via assinatura."""
    expected = build_signature(record.signature_payload(), signing_key=signing_key)
    return hmac.compare_digest(expected, record.signature)


def verify_risk_acceptance_record(
    record: RiskAcceptanceRecord,
    *,
    signing_key: str,
    reference_time: datetime | None = None,
) -> tuple[bool, str]:
    """Valida assinatura e expiração de um registro de aceitação."""
    if not verify_risk_acceptance_signature(record, signing_key=signing_key):
        return False, "invalid_signature"
    if record.is_expired(reference_time=reference_time):
        return False, "expired"
    return True, "valid"


def find_expiring_records(
    records: Iterable[RiskAcceptanceRecord],
    *,
    days: int,
    reference_time: datetime | None = None,
) -> list[RiskAcceptanceRecord]:
    """Filtra registros que expiram dentro da janela configurada."""
    return [r for r in records if r.expires_within(days=days, reference_time=reference_time)]


def apply_risk_acceptance_to_finding(
    finding: Finding,
    *,
    record: RiskAcceptanceRecord,
    signing_key: str,
    actor: str,
    note: str = "",
    reference_time: datetime | None = None,
) -> str:
    """Aplica aceitação de risco no finding após validar o registro assinado."""
    if record.finding_id != finding.id:
        raise ValueError(
            f"record.finding_id ({record.finding_id}) does not match finding.id ({finding.id})"
        )
    is_valid, reason = verify_risk_acceptance_record(
        record,
        signing_key=signing_key,
        reference_time=reference_time,
    )
    if not is_valid:
        raise ValueError(f"risk acceptance record is not valid: {reason}")

    audit_note = (
        note.strip()
        or f"Risk accepted by {record.approved_by} until {record.expires_at.isoformat()} "
        f"(record_id={record.record_id})"
    )
    return transition(
        finding,
        FindingStatus.RISK_ACCEPTED,
        actor=actor,
        note=audit_note,
    )
