"""
Tests for vuln_management/lifecycle.py and the lifecycle CLI commands.

Validates:
  - Valid transitions succeed and record history
  - Invalid transitions raise InvalidTransitionError
  - can_transition() returns correct bool without mutating state
  - valid_transitions_from() returns correct targets
  - lifecycle_path() reconstructs the path from remediation records
  - Empty actor raises ValueError
  - Full workflow: OPEN → TRIAGED → IN_REMEDIATION → REMEDIATED → CLOSED
  - Reopen workflow: CLOSED → TRIAGED
  - lifecycle CLI commands: show, transitions, move
"""
from __future__ import annotations

import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

sys.path.insert(0, str(Path(__file__).parent.parent))

from vuln_management.lifecycle import (
    ALLOWED_TRANSITIONS,
    InvalidTransitionError,
    can_transition,
    lifecycle_path,
    transition,
    valid_transitions_from,
)
from vuln_management.models import Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding(status: FindingStatus = FindingStatus.OPEN) -> Finding:
    return Finding(
        title="SQL Injection in login form",
        severity=Severity.HIGH,
        status=status,
        description="Classic SQL injection in username field.",
        affected_asset="app.example.com/login",
        discovered_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )


def _findings_file(findings: list[Finding], tmpdir: str) -> Path:
    """Write findings to a temp JSON file and return its path."""
    path = Path(tmpdir) / "findings.json"
    data = [f.model_dump(mode="json") for f in findings]
    path.write_text(json.dumps(data, indent=2, default=str))
    return path


# ---------------------------------------------------------------------------
# can_transition
# ---------------------------------------------------------------------------

class TestCanTransition:

    def test_valid_transition_returns_true(self):
        f = _finding(FindingStatus.OPEN)
        assert can_transition(f, FindingStatus.TRIAGED)

    def test_invalid_transition_returns_false(self):
        f = _finding(FindingStatus.OPEN)
        assert not can_transition(f, FindingStatus.CLOSED)

    def test_does_not_mutate_finding(self):
        f = _finding(FindingStatus.OPEN)
        can_transition(f, FindingStatus.TRIAGED)
        assert f.status == FindingStatus.OPEN

    def test_same_status_returns_false(self):
        f = _finding(FindingStatus.OPEN)
        assert not can_transition(f, FindingStatus.OPEN)

    def test_closed_to_triaged_valid(self):
        f = _finding(FindingStatus.CLOSED)
        assert can_transition(f, FindingStatus.TRIAGED)


# ---------------------------------------------------------------------------
# transition
# ---------------------------------------------------------------------------

class TestTransition:

    def test_valid_transition_updates_status(self):
        f = _finding(FindingStatus.OPEN)
        transition(f, FindingStatus.TRIAGED, actor="analyst@example.com")
        assert f.status == FindingStatus.TRIAGED

    def test_transition_appends_remediation_record(self):
        f = _finding(FindingStatus.OPEN)
        transition(f, FindingStatus.TRIAGED, actor="analyst@example.com", note="RCA done")
        assert len(f.remediation_records) == 1
        record = f.remediation_records[0]
        assert record.from_status == FindingStatus.OPEN
        assert record.to_status == FindingStatus.TRIAGED
        assert record.actor == "analyst@example.com"
        assert record.note == "RCA done"

    def test_transition_returns_transition_name(self):
        f = _finding(FindingStatus.OPEN)
        name = transition(f, FindingStatus.TRIAGED, actor="a@b.com")
        assert name == "triage"

    def test_invalid_transition_raises(self):
        f = _finding(FindingStatus.OPEN)
        with pytest.raises(InvalidTransitionError):
            transition(f, FindingStatus.CLOSED, actor="a@b.com")

    def test_empty_actor_raises(self):
        f = _finding(FindingStatus.OPEN)
        with pytest.raises(ValueError, match="actor"):
            transition(f, FindingStatus.TRIAGED, actor="")

    def test_whitespace_actor_raises(self):
        f = _finding(FindingStatus.OPEN)
        with pytest.raises(ValueError, match="actor"):
            transition(f, FindingStatus.TRIAGED, actor="   ")

    def test_multiple_transitions_accumulate_records(self):
        f = _finding(FindingStatus.OPEN)
        transition(f, FindingStatus.TRIAGED, actor="a@b.com")
        transition(f, FindingStatus.IN_REMEDIATION, actor="dev@b.com")
        assert len(f.remediation_records) == 2

    def test_invalid_transition_does_not_mutate_status(self):
        f = _finding(FindingStatus.OPEN)
        try:
            transition(f, FindingStatus.CLOSED, actor="a@b.com")
        except InvalidTransitionError:
            pass
        assert f.status == FindingStatus.OPEN

    def test_invalid_transition_does_not_append_record(self):
        f = _finding(FindingStatus.OPEN)
        try:
            transition(f, FindingStatus.CLOSED, actor="a@b.com")
        except InvalidTransitionError:
            pass
        assert len(f.remediation_records) == 0


# ---------------------------------------------------------------------------
# valid_transitions_from
# ---------------------------------------------------------------------------

class TestValidTransitionsFrom:

    def test_open_has_valid_targets(self):
        targets = valid_transitions_from(FindingStatus.OPEN)
        assert FindingStatus.TRIAGED in targets

    def test_triaged_has_multiple_targets(self):
        targets = valid_transitions_from(FindingStatus.TRIAGED)
        assert len(targets) >= 2

    def test_closed_to_triaged_only(self):
        targets = valid_transitions_from(FindingStatus.CLOSED)
        assert FindingStatus.TRIAGED in targets

    def test_returns_list(self):
        result = valid_transitions_from(FindingStatus.OPEN)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# InvalidTransitionError
# ---------------------------------------------------------------------------

class TestInvalidTransitionError:

    def test_message_contains_from_and_to(self):
        err = InvalidTransitionError(FindingStatus.OPEN, FindingStatus.CLOSED)
        assert "open" in str(err).lower()
        assert "closed" in str(err).lower()

    def test_message_contains_valid_targets(self):
        err = InvalidTransitionError(FindingStatus.OPEN, FindingStatus.CLOSED)
        assert "triaged" in str(err).lower()

    def test_error_stores_statuses(self):
        err = InvalidTransitionError(FindingStatus.OPEN, FindingStatus.CLOSED, "abc-123")
        assert err.from_status == FindingStatus.OPEN
        assert err.to_status == FindingStatus.CLOSED


# ---------------------------------------------------------------------------
# lifecycle_path
# ---------------------------------------------------------------------------

class TestLifecyclePath:

    def test_no_records_returns_current_status(self):
        f = _finding(FindingStatus.OPEN)
        path = lifecycle_path(f)
        assert path == ["open"]

    def test_single_transition_path(self):
        f = _finding(FindingStatus.OPEN)
        transition(f, FindingStatus.TRIAGED, actor="a@b.com")
        path = lifecycle_path(f)
        assert path == ["open", "triaged"]

    def test_full_workflow_path(self):
        f = _finding(FindingStatus.OPEN)
        transition(f, FindingStatus.TRIAGED,        actor="a@b.com")
        transition(f, FindingStatus.IN_REMEDIATION, actor="dev@b.com")
        transition(f, FindingStatus.REMEDIATED,     actor="dev@b.com")
        transition(f, FindingStatus.CLOSED,         actor="qa@b.com", note="verified")
        path = lifecycle_path(f)
        assert path == ["open", "triaged", "in_remediation", "remediated", "closed"]


# ---------------------------------------------------------------------------
# Full workflow integration
# ---------------------------------------------------------------------------

class TestFullWorkflows:

    def test_standard_remediation_workflow(self):
        f = _finding()
        assert transition(f, FindingStatus.TRIAGED,        actor="a") == "triage"
        assert transition(f, FindingStatus.IN_REMEDIATION, actor="b") == "start_remediation"
        assert transition(f, FindingStatus.REMEDIATED,     actor="c") == "mark_remediated"
        assert transition(f, FindingStatus.CLOSED,         actor="d") == "close_without_retest"
        assert f.status == FindingStatus.CLOSED

    def test_retest_workflow(self):
        f = _finding()
        transition(f, FindingStatus.TRIAGED,           actor="a")
        transition(f, FindingStatus.IN_REMEDIATION,    actor="b")
        transition(f, FindingStatus.REMEDIATED,        actor="c")
        transition(f, FindingStatus.RETEST_SCHEDULED,  actor="d")
        assert transition(f, FindingStatus.CLOSED,     actor="e") == "close_verified"
        assert f.status == FindingStatus.CLOSED

    def test_retest_failure_workflow(self):
        f = _finding()
        transition(f, FindingStatus.TRIAGED,           actor="a")
        transition(f, FindingStatus.IN_REMEDIATION,    actor="b")
        transition(f, FindingStatus.REMEDIATED,        actor="c")
        transition(f, FindingStatus.RETEST_SCHEDULED,  actor="d")
        assert transition(f, FindingStatus.TRIAGED,    actor="e") == "retest_failed"
        assert f.status == FindingStatus.TRIAGED

    def test_risk_acceptance_workflow(self):
        f = _finding()
        transition(f, FindingStatus.TRIAGED,       actor="a")
        assert transition(f, FindingStatus.RISK_ACCEPTED, actor="b") == "accept_risk"
        assert f.status == FindingStatus.RISK_ACCEPTED

    def test_reopen_workflow(self):
        f = _finding()
        transition(f, FindingStatus.TRIAGED,       actor="a")
        transition(f, FindingStatus.IN_REMEDIATION, actor="b")
        transition(f, FindingStatus.REMEDIATED,    actor="c")
        transition(f, FindingStatus.CLOSED,        actor="d")
        assert transition(f, FindingStatus.TRIAGED, actor="e") == "reopen"

    def test_false_positive_workflow(self):
        f = _finding()
        transition(f, FindingStatus.TRIAGED, actor="a")
        assert transition(f, FindingStatus.FALSE_POSITIVE, actor="b") == "mark_false_positive"


# ---------------------------------------------------------------------------
# Lifecycle CLI commands
# ---------------------------------------------------------------------------

class TestLifecycleCli:

    def test_lifecycle_show(self):
        from cli.main import cli as main_cli
        runner = CliRunner()
        with runner.isolated_filesystem():
            f = _finding()
            transition(f, FindingStatus.TRIAGED, actor="analyst@example.com")
            ffile = _findings_file([f], ".")

            result = runner.invoke(main_cli, ["lifecycle", "show", str(ffile)])
            assert result.exit_code == 0, result.output
            assert "open" in result.output
            assert "triaged" in result.output

    def test_lifecycle_transitions(self):
        from cli.main import cli as main_cli
        runner = CliRunner()
        result = runner.invoke(main_cli, ["lifecycle", "transitions", "open"])
        assert result.exit_code == 0
        assert "triaged" in result.output

    def test_lifecycle_transitions_unknown_status(self):
        from cli.main import cli as main_cli
        runner = CliRunner()
        result = runner.invoke(main_cli, ["lifecycle", "transitions", "nonexistent"])
        assert result.exit_code != 0

    def test_lifecycle_move_valid(self):
        from cli.main import cli as main_cli
        runner = CliRunner()
        with runner.isolated_filesystem():
            f = _finding()
            ffile = _findings_file([f], ".")

            result = runner.invoke(main_cli, [
                "lifecycle", "move", str(ffile),
                "--id", f.id[:8],
                "--to", "triaged",
                "--actor", "analyst@example.com",
                "--note", "Confirmed issue",
            ])
            assert result.exit_code == 0, result.output
            assert "triage" in result.output.lower()

    def test_lifecycle_move_invalid_transition_exits_1(self):
        from cli.main import cli as main_cli
        runner = CliRunner()
        with runner.isolated_filesystem():
            f = _finding(FindingStatus.OPEN)
            ffile = _findings_file([f], ".")

            result = runner.invoke(main_cli, [
                "lifecycle", "move", str(ffile),
                "--id", f.id[:8],
                "--to", "closed",
                "--actor", "analyst@example.com",
            ])
            assert result.exit_code == 1

    def test_lifecycle_move_save_persists_to_file(self):
        from cli.main import cli as main_cli
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            f = _finding()
            ffile = _findings_file([f], tmpdir)

            result = runner.invoke(main_cli, [
                "lifecycle", "move", str(ffile),
                "--id", f.id[:8],
                "--to", "triaged",
                "--actor", "analyst@example.com",
                "--save",
            ])
            assert result.exit_code == 0

            # Verify file was updated
            saved = json.loads(ffile.read_text())
            assert saved[0]["status"] == "triaged"

    def test_lifecycle_move_ambiguous_id_exits_2(self):
        from cli.main import cli as main_cli
        runner = CliRunner()
        with runner.isolated_filesystem():
            # Two findings with different IDs but same short prefix possible — use ""
            f1, f2 = _finding(), _finding()
            ffile = _findings_file([f1, f2], ".")

            result = runner.invoke(main_cli, [
                "lifecycle", "move", str(ffile),
                "--id", "",  # matches all → ambiguous
                "--to", "triaged",
                "--actor", "a@b.com",
            ])
            assert result.exit_code != 0
