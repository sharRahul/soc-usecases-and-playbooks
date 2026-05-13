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
└── docs/
    ├── detection-logic-documentation.md
    ├── triage-instructions.md
    ├── playbook-flowcharts.md
    └── mitre-attack-coverage.md
```

## Quick start

1. Read [`docs/detection-logic-documentation.md`](docs/detection-logic-documentation.md) to understand the required fields for every detection.
2. Use [`docs/triage-instructions.md`](docs/triage-instructions.md) as the analyst first-response template.
3. Use [`docs/playbook-flowcharts.md`](docs/playbook-flowcharts.md) to create Mermaid decision trees for each playbook.
4. Maintain ATT&CK mapping in [`docs/mitre-attack-coverage.md`](docs/mitre-attack-coverage.md).
5. Update [`CHANGELOG.md`](CHANGELOG.md) whenever detection logic, playbook steps, escalation criteria, or severity guidance changes.

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

## Contributing

Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before submitting new detections, playbooks, tuning recommendations, or ATT&CK mappings.

## License

This repository is licensed under the MIT License. See [`LICENSE`](LICENSE) for details.

## Disclaimer

This repository contains practical security operations guidance. Test detection logic safely before production deployment, tune thresholds to your environment, and do not include real incident data, client information, credentials, or sensitive artefacts in contributions.
