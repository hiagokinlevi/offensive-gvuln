"""Tests for the optional REST API storage layer."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from vuln_management.api import FindingPatch, JsonFindingStore, create_app
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


def test_create_app_requires_api_extra_when_fastapi_is_absent(tmp_path: Path) -> None:
    if importlib.util.find_spec("fastapi") is not None:
        app = create_app(tmp_path / "findings.json")
        assert app.title == "Offensive GVuln API"
        return

    with pytest.raises(RuntimeError, match="optional api extra"):
        create_app(tmp_path / "findings.json")
