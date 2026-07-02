# Pull request

## Summary

Describe what this change adds or improves and why an analyst or detection engineer benefits.

## Type of change

- [ ] New use case
- [ ] Detection logic change
- [ ] Playbook or triage guidance change
- [ ] Register, template, or documentation change
- [ ] Tooling or CI change

## Checklist

- [ ] I ran `python3 scripts/generate_registers.py` and committed the regenerated registers, index, Sigma exports, and Navigator layer.
- [ ] I ran `python3 scripts/validate_detections.py` and it passed.
- [ ] New or changed use cases have complete YAML front-matter matching `docs/use-case-template.md`.
- [ ] No real alerts, incident timelines, customer evidence, usernames, IP addresses, tenant IDs, or tokens are included. Synthetic examples and placeholders only.
- [ ] False positive scenarios and tuning notes are documented for detection changes.
- [ ] `CHANGELOG.md` is updated if detection behaviour, severity, escalation criteria, or containment guidance changed.
