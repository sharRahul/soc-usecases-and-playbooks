# MITRE ATT&CK Coverage

This document tracks which MITRE ATT&CK tactics and techniques are covered by the SOC detection and playbook library.

The coverage matrix, heatmap summary, and use-case coverage tables below are generated from the YAML front-matter in `use-cases/` by `scripts/generate_registers.py`. Do not edit the generated tables by hand. Update the front-matter and rerun the generator.

## Coverage model

| Coverage status | Meaning |
| --- | --- |
| Detect | Detection logic exists and is documented, but may require local validation and tuning. |
| Alert | Detection logic, severity guidance, triage, escalation, evidence, and containment guidance are documented. |
| No Coverage | No documented detection or playbook currently exists in this repository. |

Coverage status is derived from `lifecycle_status`: `operational` and `validated` map to Alert, `draft` and `tuning-required` map to Detect, and `retired` use cases are excluded. The gap rating counts covered techniques per tactic: two or more is Low, one is Medium, none is High.

## ATT&CK coverage matrix

<!-- BEGIN GENERATED: attack-matrix -->
| Tactic | Technique ID | Technique Name | Use Case ID | Detection Source | Coverage Status |
| --- | --- | --- | --- | --- | --- |
| Reconnaissance | T1598 | Phishing for Information | UC-EMAIL-001-Phishing-Credential-Harvest | Defender for Office 365 EmailEvents, UrlClickEvents, Entra ID SigninLogs | Alert |
| Initial Access | T1078 | Valid Accounts | UC-CLOUD-001-Impossible-Travel | Entra ID SigninLogs, AADNonInteractiveUserSignInLogs | Alert |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | UC-CLOUD-001-Impossible-Travel | Entra ID SigninLogs, AADNonInteractiveUserSignInLogs | Alert |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | UC-EMAIL-001-Phishing-Credential-Harvest | Defender for Office 365 EmailEvents, UrlClickEvents | Alert |
| Persistence | T1098.002 | Account Manipulation: Additional Email Delegate Permissions | UC-IDENTITY-002-Malicious-OAuth-App-Consent | Entra ID AuditLogs, M365 audit logs | Alert |
| Defence Evasion | T1550.001 | Use Alternate Authentication Material: Application Access Token | UC-IDENTITY-002-Malicious-OAuth-App-Consent | Entra ID AuditLogs, application and service principal inventory | Alert |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | UC-ENDPOINT-001-Possible-LSASS-Credential-Dump | MDE DeviceProcessEvents, DeviceEvents, DeviceAlertEvents | Alert |
| Credential Access | T1621 | Multi-Factor Authentication Request Generation | UC-IDENTITY-001-MFA-Fatigue-Attack | Entra ID SigninLogs, Microsoft Authenticator logs | Alert |
<!-- END GENERATED: attack-matrix -->

## Heatmap summary

<!-- BEGIN GENERATED: heatmap -->
| Tactic | Detect | Alert | No Coverage | Gap rating |
| --- | ---: | ---: | ---: | --- |
| Reconnaissance | 0 | 1 | 0 | Medium |
| Initial Access | 0 | 3 | 0 | Low |
| Persistence | 0 | 1 | 0 | Medium |
| Defence Evasion | 0 | 1 | 0 | Medium |
| Credential Access | 0 | 2 | 0 | Low |
<!-- END GENERATED: heatmap -->

## Current use-case coverage

<!-- BEGIN GENERATED: use-case-coverage -->
| Use Case ID | Primary severity | Primary data sources | ATT&CK focus |
| --- | --- | --- | --- |
| UC-CLOUD-001-Impossible-Travel | Medium (Tunable to High) | Entra ID SigninLogs, AADNonInteractiveUserSignInLogs, VPN and proxy logs, Entra ID risk signals | Valid cloud account use from implausible locations |
| UC-EMAIL-001-Phishing-Credential-Harvest | High | Defender for Office 365 EmailEvents, Defender for Office 365 UrlClickEvents, Entra ID SigninLogs, Email investigation artefacts | Phishing link and credential harvesting exposure |
| UC-ENDPOINT-001-Possible-LSASS-Credential-Dump | Critical | MDE DeviceProcessEvents, MDE DeviceEvents, MDE DeviceAlertEvents, Identity and network logs | LSASS credential dumping |
| UC-IDENTITY-001-MFA-Fatigue-Attack | High | Entra ID SigninLogs, Microsoft Authenticator logs, Entra ID user and device context | MFA request generation |
| UC-IDENTITY-002-Malicious-OAuth-App-Consent | High | Entra ID AuditLogs, Entra ID application and service principal inventory, M365 audit logs | OAuth consent abuse and persistent application access |
<!-- END GENERATED: use-case-coverage -->

## Mapping standard

When adding a detection, include:

- Tactic name.
- Technique ID.
- Technique name.
- Sub-technique ID if applicable.
- Why the mapping is appropriate.
- Data source that supports the mapping.
- Confidence level: Low, Medium, or High.
- Coverage status: Detect, Alert, or No Coverage.

## Review process

Review ATT&CK mapping when:

- Detection logic changes.
- Required data sources change.
- MITRE ATT&CK updates technique names or structure.
- False positive tuning materially changes what behaviour is detected.
- A detection is promoted from draft to operational.

## Coverage improvement backlog

| Priority | Gap | Suggested next action |
| --- | --- | --- |
| High | Execution coverage | Add suspicious PowerShell, LOLBin, and script interpreter detections. |
| High | Defence evasion coverage | Add EDR disabled, tamper protection disabled, and audit log disabled detections. |
| High | Lateral movement coverage | Add RDP, SMB, WinRM, and admin share use cases. |
| Medium | Email collection | Add mailbox forwarding, inbox rule, and eDiscovery export detections. |
| Medium | Cloud persistence | Add service principal credential and privileged role assignment detections. |
