"""Pydantic models for vulnerability findings and remediation records."""
from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    IN_REMEDIATION = "in_remediation"
    REMEDIATED = "remediated"
    RETEST_SCHEDULED = "retest_scheduled"
    CLOSED = "closed"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


class RemediationRecord(BaseModel):
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    from_status: FindingStatus
    to_status: FindingStatus
    actor: str
    note: str = ""


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    severity: Severity
    status: FindingStatus = FindingStatus.OPEN
    description: str
    affected_asset: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    remediation_records: list[RemediationRecord] = Field(default_factory=list)

    def is_open(self) -> bool:
        """Return True if finding requires active attention."""
        return self.status not in {
            FindingStatus.CLOSED,
            FindingStatus.RISK_ACCEPTED,
            FindingStatus.FALSE_POSITIVE,
        }
