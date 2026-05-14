# MITRE ATT&CK Coverage

This document tracks which MITRE ATT&CK tactics and techniques are covered by the SOC detection and playbook library.

## Coverage model

| Coverage status | Meaning |
| --- | --- |
| Detect | Detection logic exists and is documented, but may require local validation and tuning. |
| Alert | Detection logic, severity guidance, triage, escalation, evidence, and containment guidance are documented. |
| No Coverage | No documented detection or playbook currently exists in this repository. |

## ATT&CK coverage matrix

| Tactic | Technique ID | Technique Name | Use Case ID | Detection Source | Coverage Status |
| --- | --- | --- | --- | --- | --- |
| Credential Access | T1621 | Multi-Factor Authentication Request Generation | UC-IDENTITY-001-MFA-Fatigue-Attack | Entra ID SigninLogs, Microsoft Authenticator logs | Alert |
| Defence Evasion | T1550.001 | Use Alternate Authentication Material: Application Access Token | UC-IDENTITY-002-Malicious-OAuth-App-Consent | Entra ID AuditLogs, application/service principal inventory | Alert |
| Persistence | T1098.002 | Account Manipulation: Additional Email Delegate Permissions | UC-IDENTITY-002-Malicious-OAuth-App-Consent | Entra ID AuditLogs, M365 audit logs | Alert |
| Initial Access | T1078 | Valid Accounts | UC-CLOUD-001-Impossible-Travel | Entra ID SigninLogs, AADNonInteractiveUserSignInLogs | Alert |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | UC-CLOUD-001-Impossible-Travel | Entra ID SigninLogs, AADNonInteractiveUserSignInLogs | Alert |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | UC-EMAIL-001-Phishing-Credential-Harvest | Defender for Office 365 EmailEvents, UrlClickEvents | Alert |
| Reconnaissance | T1598 | Phishing for Information | UC-EMAIL-001-Phishing-Credential-Harvest | Defender for Office 365 EmailEvents, UrlClickEvents, Entra ID SigninLogs | Alert |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory | UC-ENDPOINT-001-Possible-LSASS-Credential-Dump | MDE DeviceProcessEvents, DeviceEvents, DeviceAlertEvents | Alert |

## Heatmap summary

| Tactic | Detect | Alert | No Coverage | Gap rating |
| --- | ---: | ---: | ---: | --- |
| Reconnaissance | 0 | 1 | 0 | Low |
| Initial Access | 0 | 3 | 0 | Low |
| Defence Evasion | 0 | 1 | 0 | Medium |
| Persistence | 0 | 1 | 0 | Medium |
| Credential Access | 0 | 2 | 0 | Low |

## Current use-case coverage

| Use Case ID | Primary severity | Primary data sources | ATT&CK focus |
| --- | --- | --- | --- |
| UC-IDENTITY-001-MFA-Fatigue-Attack | High | Entra ID SigninLogs, Microsoft Authenticator logs | MFA request generation |
| UC-IDENTITY-002-Malicious-OAuth-App-Consent | High | Entra ID AuditLogs | OAuth consent abuse and persistent application access |
| UC-CLOUD-001-Impossible-Travel | Medium, tunable to High | Entra ID SigninLogs, AADNonInteractiveUserSignInLogs | Valid cloud account use from implausible locations |
| UC-EMAIL-001-Phishing-Credential-Harvest | High | Defender for Office 365, Entra ID SigninLogs | Phishing link and credential harvesting exposure |
| UC-ENDPOINT-001-Possible-LSASS-Credential-Dump | Critical | Microsoft Defender for Endpoint | LSASS credential dumping |

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
