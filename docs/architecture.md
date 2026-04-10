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

### Evidence Bundle Integrity

`evidence_bundle.py` now produces delivery bundles with an embedded SHA-256 integrity inventory:

- `generate_bundle()` writes the usual manifest, summary, per-finding JSON, and SLA status files, then appends an `integrity.files[]` block with hash and byte-size metadata for every delivered artifact in the bundle except the manifest itself.
- `verify_bundle()` replays those checks at handoff or intake time and flags missing, modified, or unexpected files before evidence is trusted.

This makes the bundle itself tamper-evident, not just the individual raw artifacts collected during the engagement.

### Issue Sync Adapters

`issue_sync.py` exports tracker-native remediation payloads without requiring live API credentials during triage:

- `build_github_issue_payload()` maps findings into GitHub-friendly titles, labels, assignees, and a Markdown body that preserves SLA and asset context.
- `build_jira_issue_payload()` maps severity into JIRA priorities, carries due dates from the SLA engine, and preserves component metadata for queue routing.
- `redact_sensitive_text()` removes common credential material from exported descriptions and affected assets, including password or token assignments, bearer/basic auth values, AWS access key IDs, and private key blocks.
- `export_issue_sync_payloads()` sorts findings by urgency, filters closed work by default, and emits a deterministic JSON bundle that another automation layer can POST later.

This keeps the repository offline-safe while still closing the handoff gap between discovery and ticketed remediation.

### Optional REST API

`api.py` provides a FastAPI application factory for teams that want a small service boundary around the same JSON-native finding model:

- `JsonFindingStore` persists `Finding` records to a deterministic JSON array so the service can run without a database.
- `create_app()` exposes health, list, create, get, replace, patch, and delete routes under `/findings`.
- FastAPI and Uvicorn live behind the `api` optional dependency group, keeping the default offline CLI install lean.

This closes the first v0.2 REST service gap while preserving the repository's local-first workflow.

### SLA Notification Payloads

`sla_notifications.py` converts the structured `SLAReport` output into webhook-safe Slack and Microsoft Teams payloads:

- `build_notification_payload()` reuses the existing warning, breached, and critical-breach tiers so alerts stay consistent with local CLI and file-based reporting.
- `send_webhook_notification()` uses standard-library HTTP delivery so teams can post the payload without introducing a `requests` dependency or breaking offline editable installs.
- The `gvuln notify-sla` CLI supports `--dry-run` payload export, which lets teams review the exact JSON that will be sent before they attach a real webhook URL.

This closes the operational gap between "we can calculate overdue findings" and "we can route the alert into the chat system that the remediation team already watches."

## Design Decisions

- **Pydantic v2** for all models: runtime validation, `model_dump(mode="json")` for serialization.
- **State enforcement in tracker, not models**: keeps the model pure; transition logic is centralized.
- **No database**: JSON files for portability — a v0.2 REST API can layer persistence on top.
