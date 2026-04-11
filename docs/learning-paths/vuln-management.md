# Learning Path — Vulnerability Management

## Beginner
1. Read `training/01-vulnerability-lifecycle.md`
2. Run `check-sla` against a sample findings file
3. Generate a Markdown report and review the output

## Intermediate
1. Read `training/02-pentest-governance.md`
2. Write a ScopeValidator for a fictional engagement
3. Render a RoE document and review its structure
4. Collect and hash evidence files with EvidenceCollector
5. Build a `gvuln notify-sla --dry-run` payload and review which findings would page the remediation team

## Advanced
1. Extend the state machine with a custom transition (e.g., REMEDIATED → VERIFIED)
2. Run the optional FastAPI findings API with `GVULN_API_JWT_SECRET` set, optionally pin `GVULN_API_JWT_ISSUER` and `GVULN_API_JWT_AUDIENCE`, and call it with an HS256 Bearer JWT that has the `findings:write` scope
3. Subscribe to `/sla/alerts` with the same JWT and confirm that creating an overdue finding emits a fresh SLA breach snapshot
4. Integrate with a JIRA project via the REST API
5. Wire `gvuln notify-sla` into a scheduled workflow that posts only warning-or-higher findings
