# Remediation Tracking Workflow

## Purpose

This workflow standardizes how confirmed vulnerabilities move from validation to verified closure. It enforces accountability through explicit status states, owner assignments, SLA-driven deadlines, and verification checkpoints.

## Scope

Applies to all confirmed findings tracked in this repository's vulnerability lifecycle process, including findings originating from:
- Internal security testing
- Authorized penetration tests
- Bug bounty/third-party reports (after triage confirmation)
- Continuous scanning with manual confirmation

## Core Roles

- **Security Analyst (SA):** Confirms vulnerability, sets severity, tracks SLA, validates evidence.
- **Remediation Owner (RO):** System/service owner responsible for remediation execution.
- **Engineering Implementer (EI):** Engineer assigned to apply the fix (can be same as RO).
- **QA/Validator (QV):** Performs functional/regression validation after patch deployment.
- **Security Verifier (SV):** Performs retest and closure decision.
- **Risk Approver (RA):** Approves exceptions/risk acceptance when deadlines cannot be met.

## Required Tracking Fields

Each remediation task should include at minimum:
- `finding_id`
- `title`
- `severity` (Critical/High/Medium/Low)
- `status`
- `remediation_owner`
- `engineering_implementer`
- `security_analyst`
- `date_confirmed`
- `sla_due_date`
- `target_fix_date`
- `patch_deployed_at` (nullable)
- `retest_due_date`
- `verified_at` (nullable)
- `verification_result` (Pass/Fail/Partial)
- `exception_requested` (bool)
- `exception_approved_by` (nullable)
- `evidence_links` (tickets, commits, deployment logs, test output)

## Status State Machine

1. **Confirmed**
   - Entry criteria: Vulnerability validity established and severity assigned.
   - Owner: Security Analyst.
   - Exit criteria: Remediation owner assigned and remediation task created.

2. **Assigned**
   - Entry criteria: RO and EI identified; fix plan drafted.
   - Owner: Remediation Owner.
   - Exit criteria: Target fix date committed.

3. **In Remediation**
   - Entry criteria: Active engineering work started.
   - Owner: Engineering Implementer.
   - Exit criteria: Code/config fix completed and peer-reviewed.

4. **Pending Deployment**
   - Entry criteria: Fix approved and waiting for release window/change control.
   - Owner: Remediation Owner.
   - Exit criteria: Patch/config deployed to affected environment(s).

5. **Deployed - Awaiting Validation**
   - Entry criteria: Deployment completed and evidence attached.
   - Owner: QA/Validator.
   - Exit criteria: Validation checkpoint passed; ready for security retest.

6. **Retest Scheduled**
   - Entry criteria: Security retest date/time committed.
   - Owner: Security Verifier.
   - Exit criteria: Retest executed.

7. **Verification Failed**
   - Entry criteria: Retest indicates vulnerability persists or partial fix.
   - Owner: Engineering Implementer.
   - Exit criteria: New remediation plan accepted; returns to **In Remediation**.

8. **Verified Remediated**
   - Entry criteria: Retest confirms vulnerability no longer exploitable.
   - Owner: Security Verifier.
   - Exit criteria: Evidence bundle finalized and closure approved.

9. **Closed**
   - Entry criteria: Final sign-off complete; audit evidence immutable.
   - Owner: Security Analyst.
   - Exit criteria: None.

10. **Risk Accepted (Exception Path)**
   - Entry criteria: Formal exception approved before SLA breach or with documented violation acceptance.
   - Owner: Risk Approver.
   - Exit criteria: Expiration reached, compensating controls changed, or remediation resumed.

## Transition Rules

- `Confirmed -> Assigned` requires `remediation_owner` and `sla_due_date`.
- `Assigned -> In Remediation` requires `target_fix_date`.
- `In Remediation -> Pending Deployment` requires implementation evidence (PR/commit/change request).
- `Pending Deployment -> Deployed - Awaiting Validation` requires deployment evidence (ticket/log/version).
- `Deployed - Awaiting Validation -> Retest Scheduled` requires QA/functional validation pass.
- `Retest Scheduled -> Verified Remediated` requires retest proof-of-fix evidence.
- `Retest Scheduled -> Verification Failed` requires failure evidence and rollback/impact notes if applicable.
- `Verified Remediated -> Closed` requires final evidence completeness check.
- Any active state -> `Risk Accepted` requires signed approval and expiry date.

## Deadline Model

Use severity-driven SLA due dates as baseline:
- **Critical:** 24 hours
- **High:** 7 days
- **Medium:** 30 days
- **Low:** 90 days

### Operational Deadlines

For each finding:
1. `sla_due_date` = derived from severity and confirmation timestamp.
2. `target_fix_date` = engineering commitment date (must be <= `sla_due_date` unless exception process is active).
3. `retest_due_date` = within 1 business day of deployment for Critical/High, 3 business days for Medium/Low.

### Breach Handling

- If current time > `sla_due_date` and status not in (`Verified Remediated`, `Closed`, `Risk Accepted`), mark as **Overdue**.
- Overdue tasks require:
  - Escalation to remediation owner manager
  - Daily update notes
  - Security leadership visibility until closure/exception

## Verification Checkpoints

1. **Checkpoint A — Confirmation Quality Gate**
   - Repro steps documented
   - Affected asset/version identified
   - Severity and business impact validated

2. **Checkpoint B — Remediation Plan Gate**
   - Fix strategy documented (patch/config/compensating control)
   - Owner and ETA assigned
   - Rollback considerations recorded

3. **Checkpoint C — Implementation Gate**
   - Code/config diff linked
   - Peer review completed
   - Security impact of changes considered

4. **Checkpoint D — Deployment Gate**
   - Deployment evidence attached
   - Environment coverage confirmed (prod/non-prod as applicable)
   - Change record approved

5. **Checkpoint E — Validation Gate**
   - Functional/regression tests passed
   - No critical side effects introduced

6. **Checkpoint F — Security Retest Gate**
   - Original exploit path retested
   - Variant/adjacent checks performed as needed
   - Result recorded: Pass/Fail/Partial

7. **Checkpoint G — Closure Evidence Gate**
   - Before/after artifacts linked
   - Timeline complete and auditable
   - Final closure signer identified

## Minimal Workflow Example

1. SA confirms finding `F-2026-104`, severity High, sets SLA due in 7 days.
2. Task moves to **Assigned** with RO and EI.
3. EI implements fix and moves to **Pending Deployment** with PR + test evidence.
4. Patch deploys; task moves to **Deployed - Awaiting Validation**.
5. QV validates application health; SV schedules and executes retest.
6. If fixed, move to **Verified Remediated** then **Closed**.
7. If not fixed, move to **Verification Failed** and loop back to **In Remediation**.

## Audit Readiness Notes

- Preserve immutable timestamps for all status changes.
- Keep evidence pointers in a centralized record to support reporting and compliance reviews.
- Require explicit approver identity for exception/risk acceptance actions.
