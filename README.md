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
- Produce executive and technical vulnerability reports
- Monitor overdue remediations by severity tier

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
```

## How to Contribute

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

- v0.1: Core vulnerability models, SLA engine, scope validator
- v0.2: CVSS scoring integration, JIRA/GitHub Issues export
- v0.3: Automated evidence packaging, PDF report generation
- v0.4: Integration with Nuclei, Burp Suite, Nessus output formats

## License

CC BY 4.0 — see [LICENSE](LICENSE).

## Ethical Disclaimer

This toolkit is designed exclusively for authorized security assessments. Never use these tools or techniques against systems you do not have explicit written permission to test. Unauthorized access to computer systems is illegal and unethical. Always obtain proper authorization before any security testing activity.
