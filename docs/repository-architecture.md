# Repository Directory Architecture

This document defines the production-ready directory layout for scalable vulnerability lifecycle management across discovery, triage, remediation, verification, and governance workflows.

## Canonical Layout

```text
offensive-gvuln/
├── assets/                        # Static asset inventory and metadata
│   ├── inventories/
│   └── owners/
├── engagements/                   # Authorized engagement definitions and scope
│   ├── active/
│   ├── planned/
│   └── completed/
├── evidence/                      # Collected evidence and integrity manifests
│   ├── raw/
│   ├── processed/
│   └── manifests/
├── governance/                    # Governance docs, policies, and approvals
│   ├── policies/
│   ├── standards/
│   └── exceptions/
├── reports/                       # Generated executive/technical reports
│   ├── executive/
│   ├── technical/
│   └── exports/
├── schemas/                       # JSON/Pydantic-facing schema artifacts
│   ├── vulnerabilities/
│   ├── engagements/
│   └── evidence/
├── vulnerabilities/               # Vulnerability records and lifecycle state
│   ├── incoming/
│   ├── triaged/
│   ├── in_remediation/
│   ├── pending_retest/
│   └── closed/
├── vuln_management/               # Existing implementation modules
├── pentest_governance/            # Existing implementation modules
└── templates/                     # Existing document templates
```

## Notes

- Keep records immutable where possible; append state changes rather than destructive edits.
- Store sensitive artifacts in encrypted-at-rest storage when mirrored outside local development.
- Maintain hash manifests for `evidence/` artifacts to preserve chain-of-custody.
- Align `schemas/` with runtime validators used by `vuln_management` and API layers.
