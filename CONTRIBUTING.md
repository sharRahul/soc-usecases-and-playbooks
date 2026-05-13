# Contributing

Thank you for helping improve **SOC Use Cases & Playbooks**. Contributions should make detection and response work clearer, safer, and more repeatable for analysts.

## Contribution principles

All contributions should be:

- Actionable: an analyst should know exactly what to check next.
- Testable: detection logic should state required data sources and assumptions.
- Tunable: include false positives, known noisy conditions, and threshold guidance.
- Evidence-led: explain what evidence to preserve for incident review and audit.
- Safe: never include real credentials, tenant IDs, private incident data, client names, or personal data.

## Adding a detection use case

Each detection use case should include:

1. Use-case ID and alert name.
2. Threat objective.
3. Required log sources.
4. Detection logic in Sigma, KQL, SPL, YARA, or SIEM-native format.
5. MITRE ATT&CK tactic and technique mapping.
6. Severity and priority guidance.
7. False positive scenarios.
8. Tuning recommendations.
9. First three triage steps.
10. Evidence to preserve.
11. Escalation criteria.
12. Containment and recovery guidance.

## Adding or changing a playbook

Playbooks should include:

- Trigger condition.
- Decision tree or Mermaid flowchart.
- Analyst triage steps.
- Escalation path.
- Communication requirements.
- Containment options.
- Recovery and closure criteria.
- Post-incident improvement notes.

## Pull request checklist

Before opening a pull request, confirm that:

- [ ] No sensitive or real incident data is included.
- [ ] Detection logic has required data sources listed.
- [ ] False positive scenarios are documented.
- [ ] MITRE ATT&CK mapping is included where applicable.
- [ ] Triage instructions are clear enough for a junior analyst.
- [ ] Mermaid diagrams render correctly where used.
- [ ] The changelog is updated when detection logic or response steps change.

## Style guide

- Use clear analyst instructions, not vague security language.
- Start triage steps with verbs: Review, Confirm, Query, Check, Preserve, Escalate.
- Avoid irreversible containment actions unless the required approval path is stated.
- Make severity guidance conditional and environment-aware.
- Document assumptions, especially data source gaps and logging limitations.

## Security and privacy

Do not submit real alerts, real incident timelines, customer evidence, usernames, IP addresses, tenant IDs, access tokens, passwords, or screenshots containing sensitive information. Use synthetic examples and placeholders.
