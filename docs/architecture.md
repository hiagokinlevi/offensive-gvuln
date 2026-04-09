# Architecture

## Core Components

### Vulnerability State Machine

The `VulnerabilityTracker` enforces a directed acyclic graph of valid status transitions. Each transition appends a `RemediationRecord` with actor, timestamp, and notes — creating an immutable audit trail.

```
OPEN ──────────────────────────────────► FALSE_POSITIVE
  │
  ▼
TRIAGED ─────────────────────────────► RISK_ACCEPTED
  │
  ▼
IN_REMEDIATION
  │
  ▼
REMEDIATED
  │
  ▼
RETEST_SCHEDULED ◄─────────────────── (regression found)
  │
  ▼
CLOSED
```

### SLA Engine

`sla_engine.py` computes deadline and remaining time from `Finding.discovered_at`. `find_breached()` returns only open findings past their deadline — closed/risk-accepted findings are excluded from SLA monitoring.

### Signed Risk Acceptance Workflow

`risk_acceptance.py` introduces a governance-focused workflow for risk acceptance with:

- deterministic HMAC-SHA256 signatures for integrity validation;
- approver/requester separation enforcement;
- expiration windows and expiring-record checks;
- lifecycle integration that applies validated records directly to `RISK_ACCEPTED`.

This provides auditable approvals and reduces the chance of ad-hoc, non-traceable risk acceptance decisions.

### Retest Planning And Diff Reporting

`retest.py` adds a verification layer after remediation:

- `schedule_retest()` attaches a structured `RetestPlan` to a finding, records the lifecycle transition into `RETEST_SCHEDULED`, and forces teams to capture the target environment plus verification scope.
- `generate_retest_diff_report()` compares baseline and candidate finding snapshots so teams can separate fixed findings, regressions, new exposure, and still-open debt before closing a remediation sprint.

This closes the gap between "fix claimed" and "fix verified" while keeping the workflow JSON-native and easy to automate.

### Pentest Governance

- **ScopeValidator**: Validates targets against exact hostnames, CIDR ranges, and wildcard patterns before assessment begins.
- **RoEConfig + render_roe()**: Produces a Jinja2-rendered RoE document for sign-off.
- **EvidenceCollector**: Copies files to a case directory and produces a SHA-256 manifest for chain-of-custody.

## Design Decisions

- **Pydantic v2** for all models: runtime validation, `model_dump(mode="json")` for serialization.
- **State enforcement in tracker, not models**: keeps the model pure; transition logic is centralized.
- **No database**: JSON files for portability — a v0.2 REST API can layer persistence on top.
