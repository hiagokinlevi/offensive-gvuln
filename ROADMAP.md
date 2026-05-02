# Roadmap

## v0.1 — Core (current)
- [x] Vulnerability finding model (Pydantic v2)
- [x] State machine tracker with enforced transitions
- [x] SLA engine (Critical=24h, High=7d, Medium=30d, Low=90d)
- [x] Report generator (JSON, CSV, Markdown)
- [x] Pentest scope validator (exact, CIDR, wildcard)
- [x] Rules of Engagement template renderer
- [x] Evidence collector with SHA-256 manifest
- [x] Tamper-evident evidence bundle verification for delivery handoff

## v0.2 — REST API
- [x] FastAPI REST service for findings CRUD
- [x] JWT authentication
- [x] WebSocket live SLA breach alerts

## v0.3 — Integrations
- [x] JIRA issue sync adapter
- [x] GitHub Issues sync adapter
- [x] Secret redaction for offline remediation issue exports
- [x] Slack/Teams SLA breach notifications

## v0.4 — Risk Scoring
- [x] CVSS v3.1 base score calculator (complete formula, roundup, severity ratings, vector string parser)
- [x] Risk acceptance workflow with approver signatures
- [x] Retest scheduling and diff reporting

## Automated Completions
- [x] Define Vulnerability Lifecycle Specification (cycle 1)
- [x] Create Standardized Vulnerability Record Schema (cycle 2)
- [x] Create Remediation Tracking Workflow (cycle 18)
- [x] Build Pentest Evidence Collection Guidelines (cycle 19)
- [x] Implement Vulnerability Disclosure Policy (cycle 20)
- [x] Create Pentest Reporting Framework (cycle 21)
- [x] Add Retest and Verification Procedures (cycle 22)
- [x] Implement Repository Directory Architecture (cycle 23)
- [x] Generate and Publish Findings JSON Schema (cycle 24)
- [x] Add JSONL (NDJSON) Export Format to Report Generator (cycle 25)
- [x] Add CLI command to verify finding state transition before apply (cycle 26)
- [x] Add deterministic evidence manifest sort + timestamp normalization (cycle 27)
-
- [x] Add `--max-findings` limit to report generation CLI (cycle 45)
