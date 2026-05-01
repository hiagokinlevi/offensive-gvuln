# offensive-gvuln

Vulnerability management workflows, authorized pentest governance, evidence templates, and remediation tracking for security teams and authorized assessors.

## Objective

Provide a structured, auditable framework for managing the full vulnerability lifecycle — from discovery through remediation verification — along with governance controls and templates for authorized penetration testing engagements.

## Problem Solved

Security teams often lack standardized processes for tracking vulnerability remediation SLAs, managing pentest scopes, and producing audit-ready evidence. This toolkit provides ready-to-use workflows, schemas, and templates that enforce accountability without requiring expensive commercial tools.

## Use Cases

- Track open vulnerabilities with severity-based SLA deadlines
- Validate pentest scope before engagement begins
- Generate Rules of Engagement documents for authorized assessments
- Collect and hash evidence for audit trails
- Generate tamper-evident evidence bundles and verify them before handoff
- Produce executive and technical vulnerability reports
- Monitor overdue remediations by severity tier
- Send Slack or Microsoft Teams webhook notifications for SLA breaches
- Operate signed risk acceptance workflows with approver traceability
- Schedule verification retests and generate before/after diff reports
- Export normalized GitHub and JIRA issue payloads for remediation tracking
- Redact common credential material from offline remediation issue exports
- Run an optional FastAPI findings CRUD service backed by the same JSON models
- Require HS256 Bearer JWTs on the optional findings REST API when an API secret is configured
- Stream live WebSocket SLA breach snapshots from the optional findings API

## Structure

```text
offensive-gvuln/
├── vuln_management/      # Vulnerability lifecycle tracking and SLA enforcement
├── pentest_governance/   # Scope validation, RoE generation, evidence collection
├── templates/            # Document templates for reports and governance
└── scripts/              # CLI tools for report generation and SLA checks
```

## How to Run

```bash
pip install -e ".[dev]"

# Check overdue findings (default: detailed per-finding output + summary)
python scripts/check_sla.py --findings findings.json

# Check overdue findings with concise aggregate output only (cron/CI friendly)
python scripts/check_sla.py --findings findings.json --summary-only

# Export filtered SLA results to CSV for SOC/SIEM ingestion
python scripts/check_sla.py --findings findings.json --csv sla_results.csv

# Optional scope filter with summary-only out
```