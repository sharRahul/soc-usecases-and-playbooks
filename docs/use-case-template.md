# SOC Use-Case Template

Copy this template into `use-cases/` and rename it using the format `UC-[CATEGORY]-[NNN]-[Description].md`.

## Front-matter

Every use case starts with a YAML front-matter block. The registers in `docs/`, the use-case index, the Sigma exports, and the ATT&CK Navigator layer are all generated from this block by `scripts/generate_registers.py`, so it must be complete and accurate. Run the generator after editing front-matter and commit the regenerated files.

```yaml
---
id: UC-CATEGORY-NNN
title: Short Descriptive Title
domain: identity
severity: high
severity_note: Optional qualifier, for example Tunable to High
attack_focus: One line describing the behaviour the detection targets
lifecycle_status: draft
mitre_tactics:
  - Tactic Name
mitre_techniques:
  - T0000
mitre_mapping:
  - tactic: Tactic Name
    technique_id: T0000
    technique_name: Technique Name
    detection_source: Log sources that support this mapping
data_sources:
  - Log source name
---
```

Field rules:

| Field | Rules |
| --- | --- |
| `id` | Must match the filename prefix, format `UC-[CATEGORY]-[NNN]`. |
| `title` | Human-readable title, matching the filename description. |
| `domain` | One of `cloud`, `email`, `endpoint`, `identity`, `network`. |
| `severity` | One of `low`, `medium`, `high`, `critical`. |
| `severity_note` | Optional. Short qualifier shown next to the severity in generated tables. |
| `attack_focus` | One line summarising the behaviour, used in the coverage register. |
| `lifecycle_status` | One of `draft`, `validated`, `operational`, `tuning-required`, `retired`, matching `docs/use-case-lifecycle.md`. |
| `mitre_tactics` | Every tactic that appears in `mitre_mapping`, no duplicates. |
| `mitre_techniques` | Every technique ID that appears in `mitre_mapping`, no duplicates. |
| `mitre_mapping` | One entry per tactic and technique pair, with the technique name and supporting detection source. |
| `data_sources` | Every log source from the Required data sources table, using consistent names across use cases. |

## Alert name

`<clear analyst-facing alert title>`

## Objective

Explain the behaviour the detection is intended to identify and the operational outcome it supports.

## Threat scenario

Describe the scenario, policy concern, or operational risk this alert is expected to represent.

## Required data sources

| Source | Purpose | Minimum fields |
| --- | --- | --- |
| `<log-source>` | `<why it is required>` | `<fields required for detection and triage>` |

## Detection logic

Document the detection in the native format used by the target platform. Include assumptions, lookback window, thresholds, joins, and entity mappings.

## MITRE ATT&CK

| Tactic | Technique ID | Technique name | Rationale |
| --- | --- | --- | --- |
| `<tactic>` | `<technique-id>` | `<technique-name>` | `<why this mapping is appropriate>` |

## Severity

State the default severity and the conditions that raise or lower it.

## False positive scenarios

- `<benign scenario>`
- `<environment-specific condition>`

## Tuning notes

- `<threshold guidance>`
- `<safe suppression or allowlist logic>`
- `<risk of over-tuning>`

## Triage steps

1. Confirm what triggered the alert using raw event fields.
2. Review related activity for the affected user, device, mailbox, application, or workload.
3. Assess business impact and whether the entity is privileged, sensitive, or production-critical.
4. Preserve evidence before containment or closure.
5. Decide whether escalation criteria are met.

## Escalation criteria

Escalate when any of the following are true:

- `<confirmed security concern or strong suspicious signal>`
- `<privileged or high-value entity involved>`
- `<multiple affected users/devices/workloads>`
- `<data access, persistence, lateral movement, or destructive activity observed>`

## Evidence to preserve

- `<source event rows>`
- `<alert or incident ID>`
- `<user/device/application identifiers>`
- `<screenshots or exports where appropriate>`
- `<containment and analyst decision notes>`

## Containment and recovery

- `<safe immediate action>`
- `<containment action requiring approval>`
- `<recovery action>`
- `<monitoring or follow-up action>`

## Lessons learned fields

| Field | Notes |
| --- | --- |
| Root cause | `<cause or investigation summary>` |
| Detection quality | `<whether the detection fired correctly>` |
| Response quality | `<whether the playbook was clear and timely>` |
| Tuning action | `<changes required>` |
| Control improvement | `<preventive or detective control improvement>` |

## Review metadata

| Field | Value |
| --- | --- |
| Status | `<Draft / Validated / Operational / Retired>` |
| Owner | `<detection owner>` |
| Last reviewed | `<yyyy-mm-dd>` |
| Reviewer | `<name or role>` |
| Test evidence | `<link or reference>` |
