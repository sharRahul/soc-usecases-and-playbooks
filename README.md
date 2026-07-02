# SOC Use Cases & Playbooks

An open, practical library of SOC detection use cases, analyst guidance, and operational playbooks. The goal is to help analysts move from an alert name to a consistent investigation path, evidence record, decision tree, and escalation outcome.

## Why this exists

A SOC repository is only useful if an analyst can follow it during a real alert. This project is designed to make detection logic and response guidance clear enough for junior analysts, reusable enough for security engineers, and traceable enough for audit and assurance reviews.

Use this repository to:

- Document detection logic in a consistent format.
- Capture required data sources, SIEM logic, tuning notes, and false positive guidance.
- Give analysts repeatable first-response triage steps.
- Map detections and playbooks to MITRE ATT&CK tactics and techniques.
- Maintain evidence-friendly operational workflows for review and continuous improvement.

## Who this is for

- SOC analysts and shift leads
- Detection engineers
- Threat hunters
- Incident responders
- Security managers building a use-case library
- GRC teams that need traceability between monitoring controls and operational evidence

## Documentation index

| Document | Read it for |
| --- | --- |
| [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) | What works today, what validation proves, and what remains backlog. |
| [`docs/detection-logic-documentation.md`](docs/detection-logic-documentation.md) | Required detection documentation fields and review expectations. |
| [`docs/use-case-template.md`](docs/use-case-template.md) | Copyable structure for a new use case. |
| [`docs/use-case-lifecycle.md`](docs/use-case-lifecycle.md) | Draft, validated, operational, tuning-required, and retired status expectations. |
| [`docs/data-source-onboarding.md`](docs/data-source-onboarding.md) | Generated table of required data sources by use case. |
| [`docs/data-source-setup-recipes.md`](docs/data-source-setup-recipes.md) | Practical onboarding and validation recipes for required telemetry. |
| [`docs/rule-deployment-guide.md`](docs/rule-deployment-guide.md) | How to adapt KQL, Sigma, and playbooks into SIEM-specific rules. |
| [`docs/safe-detection-testing.md`](docs/safe-detection-testing.md) | How to validate detections with lab, benign, or synthetic data. |
| [`docs/review-metadata-register.md`](docs/review-metadata-register.md) | Central review ownership, cadence, and test-evidence tracking. |
| [`docs/triage-instructions.md`](docs/triage-instructions.md) | Analyst first-response template. |
| [`docs/playbook-flowcharts.md`](docs/playbook-flowcharts.md) | Mermaid decision trees for each playbook. |
| [`docs/mitre-attack-coverage.md`](docs/mitre-attack-coverage.md) | Generated ATT&CK coverage and improvement backlog. |
| [`docs/metrics-template.md`](docs/metrics-template.md) | Metrics register and monthly/quarterly review guidance. |
| [`docs/threat-intel-integration.md`](docs/threat-intel-integration.md) | Enrichment process. |

## Repository structure

```text
.
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── LICENSE
├── .github/
├── docs/
├── scripts/
├── sigma/
└── use-cases/
```

Generated files are produced by `scripts/generate_registers.py` from YAML front matter in `use-cases/`. Edit the use cases, rerun the generator, and commit the result. CI fails if generated files are out of date.

## Quick start

1. Read [`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) to understand current capability and validation boundaries.
2. Read [`docs/detection-logic-documentation.md`](docs/detection-logic-documentation.md) to understand required fields for every detection.
3. Use [`docs/use-case-template.md`](docs/use-case-template.md) when drafting a new detection or playbook.
4. Use [`docs/use-case-lifecycle.md`](docs/use-case-lifecycle.md) to understand lifecycle status expectations.
5. Review the populated use cases in `use-cases/`.
6. Confirm required telemetry with [`docs/data-source-onboarding.md`](docs/data-source-onboarding.md) and [`docs/data-source-setup-recipes.md`](docs/data-source-setup-recipes.md).
7. Use [`docs/rule-deployment-guide.md`](docs/rule-deployment-guide.md) before adapting detections into a SIEM or analytics platform.
8. Use [`docs/safe-detection-testing.md`](docs/safe-detection-testing.md) before validating logic.
9. Use [`docs/triage-instructions.md`](docs/triage-instructions.md) as the analyst first-response template.
10. Track review ownership in [`docs/review-metadata-register.md`](docs/review-metadata-register.md).
11. Update [`CHANGELOG.md`](CHANGELOG.md) whenever detection logic, playbook steps, escalation criteria, severity guidance, data sources, or review ownership changes.

## Minimum standard for each SOC use case

Each use case should include:

- Alert name
- Objective
- Scenario summary
- Required data sources
- Detection logic format, such as Sigma, KQL, SPL, or SIEM-native rule
- MITRE ATT&CK mapping
- Severity and priority guidance
- False positive scenarios
- Tuning notes
- Triage steps
- Escalation criteria
- Evidence to preserve
- Response actions
- Lessons learned fields
- Review metadata in the use case or in [`docs/review-metadata-register.md`](docs/review-metadata-register.md)

## Validation

A GitHub Actions workflow validates every push and pull request:

1. Each Markdown file in `use-cases/` follows the naming convention and includes the required operational section headers.
2. Generated registers, indexes, Sigma exports, and Navigator layer match a fresh run of `scripts/generate_registers.py`.
3. Embedded KQL and YAML detection blocks parse via `scripts/validate_detections.py`.

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

This repository can support evidence for monitoring controls by showing detection coverage, data-source dependencies, alert triage process, escalation logic, MITRE ATT&CK coverage, playbook change history, response evidence expectations, metrics review, tuning cadence, enrichment process, and review ownership.

## Contributing

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting new detections, playbooks, tuning recommendations, or ATT&CK mappings.

## License

This repository is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.

## Disclaimer

This repository contains practical security operations guidance. Test detection logic safely before production deployment, tune thresholds to your environment, and do not include real case data, client information, credentials, or sensitive artefacts in contributions.