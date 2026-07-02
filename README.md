# SOC Use Cases & Playbooks

An open, practical library of SOC detection use cases, triage instructions, and incident response playbooks. The goal is to help analysts move from an alert name to a consistent investigation path, evidence record, decision tree, and escalation outcome.

## Why this exists

A SOC repository is only useful if an analyst can follow it during a real alert. This project is designed to make detection logic and response playbooks clear enough for junior analysts, reusable enough for security engineers, and traceable enough for audit and assurance reviews.

Use this repository to:

- Document detection logic in a consistent format.
- Capture required data sources, SIEM logic, tuning notes, and false positive guidance.
- Give analysts repeatable first-response triage steps.
- Map detections and playbooks to MITRE ATT&CK tactics and techniques.
- Maintain evidence-friendly response workflows for incident review and continuous improvement.

## Who this is for

- SOC analysts and shift leads
- Detection engineers
- Threat hunters
- Incident responders
- Security managers building a use-case library
- GRC teams that need traceability between monitoring controls and operational evidence

## Repository structure

```text
.
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── LICENSE
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── content-request.md
│   │   └── tuning-request.md
│   └── workflows/
│       └── validate-usecases.yml
├── docs/
│   ├── attack-navigator-layer.json      (generated)
│   ├── data-source-onboarding.md        (generated)
│   ├── detection-logic-documentation.md
│   ├── metrics-template.md              (register table generated)
│   ├── mitre-attack-coverage.md         (coverage tables generated)
│   ├── playbook-flowcharts.md
│   ├── threat-intel-integration.md
│   ├── triage-instructions.md
│   ├── use-case-lifecycle.md
│   └── use-case-template.md
├── scripts/
│   └── generate_registers.py
├── sigma/                               (generated Sigma exports)
│   ├── uc-cloud-001-impossible-travel.yml
│   ├── uc-email-001-phishing-credential-harvest.yml
│   ├── uc-endpoint-001-possible-lsass-credential-dump.yml
│   ├── uc-identity-001-mfa-fatigue-attack.yml
│   └── uc-identity-002-malicious-oauth-app-consent.yml
└── use-cases/
    ├── README.md                        (generated index)
    ├── UC-CLOUD-001-Impossible-Travel.md
    ├── UC-EMAIL-001-Phishing-Credential-Harvest.md
    ├── UC-ENDPOINT-001-Possible-LSASS-Credential-Dump.md
    ├── UC-IDENTITY-001-MFA-Fatigue-Attack.md
    └── UC-IDENTITY-002-Malicious-OAuth-App-Consent.md
```

Files marked generated are produced by `scripts/generate_registers.py` from the YAML front-matter in `use-cases/`. Edit the use cases, rerun the generator, and commit the result. CI fails if a generated file is out of date.

## Quick start

1. Read [`docs/detection-logic-documentation.md`](docs/detection-logic-documentation.md) to understand the required fields for every detection.
2. Use [`docs/use-case-template.md`](docs/use-case-template.md) when drafting a new detection or playbook.
3. Use [`docs/use-case-lifecycle.md`](docs/use-case-lifecycle.md) to understand draft, validated, operational, tuning-required, and retired status expectations.
4. Review the first populated use cases in [`use-cases/`](use-cases/).
5. Use [`docs/triage-instructions.md`](docs/triage-instructions.md) as the analyst first-response template.
6. Use [`docs/playbook-flowcharts.md`](docs/playbook-flowcharts.md) to follow Mermaid decision trees for each playbook.
7. Maintain ATT&CK mapping in [`docs/mitre-attack-coverage.md`](docs/mitre-attack-coverage.md).
8. Track detection quality with [`docs/metrics-template.md`](docs/metrics-template.md).
9. Use [`docs/threat-intel-integration.md`](docs/threat-intel-integration.md) to enrich detections with threat intelligence.
10. Update [`CHANGELOG.md`](CHANGELOG.md) whenever detection logic, playbook steps, escalation criteria, or severity guidance changes.

## Initial use cases

| Use case | Focus | Severity |
| --- | --- | --- |
| [`UC-IDENTITY-001-MFA-Fatigue-Attack`](use-cases/UC-IDENTITY-001-MFA-Fatigue-Attack.md) | Repeated MFA failures followed by success | High |
| [`UC-IDENTITY-002-Malicious-OAuth-App-Consent`](use-cases/UC-IDENTITY-002-Malicious-OAuth-App-Consent.md) | Risky third-party OAuth consent | High |
| [`UC-CLOUD-001-Impossible-Travel`](use-cases/UC-CLOUD-001-Impossible-Travel.md) | Implausible cloud account travel pattern | Medium, tunable to High |
| [`UC-EMAIL-001-Phishing-Credential-Harvest`](use-cases/UC-EMAIL-001-Phishing-Credential-Harvest.md) | Phishing email with allowed URL click | High |
| [`UC-ENDPOINT-001-Possible-LSASS-Credential-Dump`](use-cases/UC-ENDPOINT-001-Possible-LSASS-Credential-Dump.md) | Possible LSASS credential dumping | Critical |

## Minimum standard for each SOC use case

Each use case should include:

- Alert name
- Objective
- Threat scenario
- Required data sources
- Detection logic format, such as Sigma, KQL, SPL, YARA, or SIEM-native rule
- MITRE ATT&CK mapping
- Severity and priority guidance
- False positive scenarios
- Tuning notes
- Triage steps
- Escalation criteria
- Evidence to preserve
- Containment and recovery actions
- Lessons learned fields

## Example use-case naming convention

```text
UC-IDENTITY-001-Suspicious-MFA-Fatigue.md
UC-ENDPOINT-001-Possible-Credential-Dumping.md
UC-CLOUD-001-Impossible-Travel.md
UC-EMAIL-001-Phishing-With-Malicious-Link.md
```

## Validation

A GitHub Actions workflow validates every push and pull request:

1. Each Markdown file in `use-cases/` follows the naming convention and includes the required operational section headers.
2. The generated registers, index, Sigma exports, and Navigator layer match a fresh run of `scripts/generate_registers.py`, so the registers cannot drift from the use-case front-matter.
3. Every embedded KQL and YAML detection block parses via `scripts/validate_detections.py`.

Before submitting a change, run both scripts locally:

```bash
python3 scripts/generate_registers.py
python3 scripts/validate_detections.py
```

## Analyst operating principle

At 03:00, the analyst should be able to answer:

1. What triggered the alert?
2. What are the first three checks?
3. What evidence must be preserved?
4. When do I escalate?
5. What action is safe to take immediately?

## Audit and assurance value

This repository can support evidence for security monitoring and incident response controls by showing:

- Detection coverage.
- Data source dependencies.
- Alert triage process.
- Incident escalation decision logic.
- MITRE ATT&CK coverage.
- Playbook change history.
- Response evidence expectations.
- Metrics review and tuning cadence.
- Threat intelligence enrichment process.

## Contributing

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting new detections, playbooks, tuning recommendations, or ATT&CK mappings.

## License

This repository is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.

## Disclaimer

This repository contains practical security operations guidance. Test detection logic safely before production deployment, tune thresholds to your environment, and do not include real incident data, client information, credentials, or sensitive artefacts in contributions.
