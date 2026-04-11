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

```
offensive-gvuln/
├── vuln_management/      # Vulnerability lifecycle tracking and SLA enforcement
├── pentest_governance/   # Scope validation, RoE generation, evidence collection
├── templates/            # Document templates for reports and governance
└── scripts/              # CLI tools for report generation and SLA checks
```

## How to Run

```bash
pip install -e ".[dev]"

# Check overdue findings
python scripts/check_sla.py --findings findings.json

# Generate a vulnerability report
python scripts/generate_report.py --findings findings.json --format markdown --output report.md

# Create and verify a signed risk acceptance record
python -m cli.main risk-acceptance create \
  --finding-id <finding-id> \
  --requested-by analyst@example.com \
  --approved-by manager@example.com \
  --reason "Temporary business acceptance with compensating controls" \
  --expires-at 2026-12-31T23:59:59Z \
  --output risk-acceptance.json \
  --signing-key "$GVULN_APPROVER_SIGNING_KEY"

python -m cli.main risk-acceptance verify risk-acceptance.json \
  --signing-key "$GVULN_APPROVER_SIGNING_KEY"

# Schedule a retest after remediation and compare verification snapshots
python -m cli.main retest schedule findings.json \
  --id <finding-id-prefix> \
  --due-at 2026-12-31T23:59:59Z \
  --actor qa@example.com \
  --environment staging \
  --scope "Re-run authenticated and unauthenticated validation steps" \
  --save

python -m cli.main retest diff findings-before.json findings-after.json

# Generate and verify a tamper-evident evidence bundle
gvuln evidence-bundle generate findings.json \
  --engagement-id PENTEST-2026-001 \
  --output-dir ./evidence \
  --client-name "Example Corp"

gvuln evidence-bundle verify ./evidence/PENTEST-2026-001

# Export open findings as GitHub or JIRA issue payloads
gvuln issue-sync export findings.json \
  --target github \
  --repo example-org/security-remediation \
  --assignee appsec-owner

gvuln issue-sync export findings.json \
  --target jira \
  --project-key SEC \
  --component appsec \
  --output jira-issues.json

# Issue export bodies redact common secrets before handoff
# including password/token assignments, auth headers, AWS access keys,
# and private key blocks copied into descriptions or affected assets.

# Build a Slack or Teams SLA notification payload for offline review
gvuln notify-sla findings.json \
  --channel slack \
  --minimum-tier breached \
  --dry-run \
  --output slack-payload.json

# Send a live webhook notification once the payload looks correct
# Live delivery only accepts public HTTPS webhook endpoints and rejects
# localhost, non-public IP literals, and embedded URL credentials.
gvuln notify-sla findings.json \
  --channel teams \
  --minimum-tier warning \
  --webhook-url "$GVULN_TEAMS_WEBHOOK_URL"

# Run the optional findings CRUD REST API
pip install -e ".[api]"
export GVULN_API_JWT_SECRET="$(openssl rand -hex 32)"
uvicorn "vuln_management.api:create_app" --factory --reload

# Subscribe to SLA alert snapshots and mutation updates
# Connect with a Bearer token header, or pass ?token=<jwt> from browser clients.
# The endpoint emits total open findings, warning counts, breached findings,
# and critical breach findings as JSON.
wscat -c "ws://127.0.0.1:8000/sla/alerts?token=<jwt>"
```

When `GVULN_API_JWT_SECRET` is set, `/findings` endpoints require an `Authorization: Bearer <jwt>` token signed with HS256 and a `findings:write` scope. `/sla/alerts` accepts the same token through the `Authorization` header or a `token` query parameter for WebSocket clients. `/health` stays unauthenticated for liveness checks.

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- v0.1: Core vulnerability models, SLA engine, scope validator
- v0.2: FastAPI findings CRUD service
- v0.2: HS256 JWT authentication for the FastAPI findings API
- v0.2: WebSocket live SLA breach alerts
- v0.2: CVSS scoring integration, JIRA/GitHub Issues export
- v0.3: Automated evidence packaging, PDF report generation
- v0.3: Tamper-evident evidence bundle verification
- v0.3: Offline-safe GitHub/JIRA remediation issue export
- v0.3: Slack/Teams SLA breach notifications
- v0.4: Integration with Nuclei, Burp Suite, Nessus output formats
- v0.5: Retest scheduling and outcome diff reporting

## License

CC BY 4.0 — see [LICENSE](LICENSE).

## Ethical Disclaimer

This toolkit is designed exclusively for authorized security assessments. Never use these tools or techniques against systems you do not have explicit written permission to test. Unauthorized access to computer systems is illegal and unethical. Always obtain proper authorization before any security testing activity.
