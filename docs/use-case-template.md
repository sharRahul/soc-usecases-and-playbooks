# SOC Use-Case Template

Copy this template into `use-cases/` and rename it using the format `UC-[CATEGORY]-[NNN]-[Description].md`.

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
