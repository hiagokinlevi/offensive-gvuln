# Retest and Verification Procedures

## Purpose

This procedure defines how to verify that reported vulnerabilities are properly remediated, what evidence must be captured, and when a vulnerability record can be closed.

These steps are intended for authorized internal security teams and approved external assessors operating under project governance and Rules of Engagement.

---

## 1. Preconditions for Retest

A finding is eligible for retest when all of the following are true:

1. **Remediation owner update is complete**
   - Ticket/status moved to `Ready for Retest` (or equivalent state in local workflow).
   - Fix summary is provided (what changed, where, and when).
2. **Deployment confirmation exists**
   - Change is deployed to the in-scope environment(s) where the finding was originally observed.
   - Deployment/version identifier is available.
3. **Required artifacts are attached**
   - Links or attachments to code/config/infrastructure change records.
   - Any required approvals (e.g., CAB/change approval, risk acceptance when relevant).

If any precondition is missing, return the finding to remediation with a documented reason.

---

## 2. Retest Methodology

Retest must reproduce the original test path first, then verify compensating controls and adjacent exposure.

### 2.1 Reproduce Original Scenario

- Use the original finding metadata:
  - asset/host/service
  - endpoint/path/parameter
  - affected component and version
  - proof-of-concept steps
- Execute the same technique/tooling used during discovery where feasible.
- Confirm whether original exploitability still exists.

### 2.2 Verify Fix Effectiveness

- Validate expected secure behavior (e.g., access denied, input sanitized, vulnerable package removed, misconfiguration corrected).
- Confirm no bypass using common variants of the original exploit path.
- For patch-based fixes, verify target version/build is active in runtime, not only in source or ticket notes.

### 2.3 Check for Regression/Related Exposure

- Test directly related endpoints/components/control paths.
- Verify fix did not shift weakness to equivalent attack surface.
- If equivalent weakness appears elsewhere, create linked findings rather than reusing the original record.

### 2.4 Outcome Classification

Retest outcome must be one of:

- **Remediated**: Original vulnerability no longer reproducible; fix validated.
- **Partially Remediated**: Severity/impact reduced but weakness remains exploitable in some form.
- **Not Remediated**: Original vulnerability still reproducible.
- **Risk Accepted (Verified)**: Remediation not implemented; approved acceptance is active and valid.

---

## 3. Documentation Requirements

Each retest must produce auditable evidence. Minimum required fields:

1. **Retest metadata**
   - finding ID
   - retest date/time (UTC)
   - tester name/role
   - environment tested (prod/stage/etc.)
2. **Execution record**
   - exact steps performed
   - tools/commands/versions used
   - relevant request/response excerpts or logs
3. **Result evidence**
   - before/after comparison reference (diff report if available)
   - screenshots, terminal output, API traces, or scanner snippets
   - updated severity/impact rationale (if changed)
4. **Decision record**
   - final retest outcome classification
   - next action (close, reopen, continue remediation, risk acceptance)
   - reviewer/approver if required by governance

Evidence should be stored with tamper-evident handling (hash manifest/bundle process where implemented).

---

## 4. Criteria to Close a Vulnerability Record

A vulnerability record may be closed only when **all** are true:

1. Retest outcome is `Remediated` **or** `Risk Accepted (Verified)` with valid approval.
2. Required evidence/documentation is complete and attached/linked.
3. Any related tracking objects are synchronized (issue tracker, governance records, exceptions).
4. Closure rationale is explicit and references test evidence.

### 4.1 Closure Notes (Required)

Closure note should include:

- verification date and verifier
- concise statement of retest result
- artifact references (report, evidence bundle, ticket links)
- final state transition reason

---

## 5. Reopen Conditions

A closed finding must be reopened if:

- the same vulnerability is reproduced in the same scope,
- remediation is rolled back or becomes ineffective,
- material new evidence invalidates prior verification,
- accepted risk expires or approval is revoked without replacement.

When reopening, preserve full history and link new evidence to the original finding lineage.

---

## 6. SLA and Governance Considerations

- Retest should be scheduled and completed within policy-defined windows after remediation is marked ready.
- If retest fails, SLA breach logic continues or resumes based on organization policy.
- Exceptions and risk acceptance must follow signed approval workflows and expiry tracking.

---

## 7. Suggested Minimal Retest Checklist

- [ ] Preconditions verified
- [ ] Original exploit path retested
- [ ] Fix behavior validated
- [ ] Related attack surface spot-checked
- [ ] Evidence captured and stored
- [ ] Outcome classified
- [ ] Record closed/reopened with rationale

This checklist can be embedded into ticket templates, report appendices, or CLI/API workflow gates.
