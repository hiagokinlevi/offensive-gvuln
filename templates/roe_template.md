# Rules of Engagement — ACME Corp Web Application Assessment

**Date:** 2026-04-06
**Authorizing party:** Jane Smith, CISO — ACME Corp
**Lead tester:** Hiago Kin Levi

---

## Authorized Scope

- app.example.com
- api.example.com
- *.staging.example.com
- 10.0.1.0/24

## Exclusions

- prod-db.example.com (production database — out of scope)
- 10.0.0.1 (core network gateway)
- Any third-party SaaS integrations not owned by ACME Corp

## Testing Window

- **Start:** 2026-04-10 08:00 UTC
- **End:**   2026-04-17 18:00 UTC

## Emergency Contact

Security Team Hotline: +1-800-555-0199
Email: security-emergency@example.com
Slack: #incident-response (24/7 monitoring)

## Authorized Activities

- Unauthenticated and authenticated web application testing
- API endpoint enumeration and parameter fuzzing
- Business logic abuse testing
- Session management and authentication bypass testing
- Passive network traffic observation within authorized CIDR
- Manual source code review (where access is provided)

## Prohibited Activities

- Exploitation of vulnerabilities beyond proof-of-concept (no data exfiltration)
- Denial-of-service or load testing of any kind
- Social engineering of ACME Corp employees
- Physical access attempts
- Testing outside the authorized IP ranges and hostnames listed above
- Modification or deletion of any data in production systems
- Lateral movement to systems not explicitly listed in scope

---

## Sign-Off

| Role                | Name              | Signature | Date       |
|---------------------|-------------------|-----------|------------|
| Authorizing Party   | Jane Smith        |           | 2026-04-06 |
| Lead Tester         | Hiago Kin Levi    |           | 2026-04-06 |
| Legal Representative| (if required)     |           |            |

---

*This document must be signed by the authorizing party before any testing activities commence.
Retain a copy in the case evidence directory alongside the evidence manifest.*
