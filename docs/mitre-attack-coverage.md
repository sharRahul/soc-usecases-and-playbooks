# MITRE ATT&CK Coverage

This document tracks which MITRE ATT&CK tactics and techniques are covered by the SOC detection and playbook library.

## Coverage model

| Coverage level | Meaning |
| --- | --- |
| Planned | A use case is planned but not written. |
| Detection Drafted | Detection logic exists but is not validated. |
| Detection Validated | Detection logic has been tested with sample or lab telemetry. |
| Playbook Drafted | Response steps exist but have not been exercised. |
| Operational | Detection and playbook are approved for use. |
| Needs Review | Content may be stale, noisy, or missing required data sources. |

## ATT&CK coverage matrix

| Tactic | Technique ID | Technique name | Example use case | Required data sources | Coverage level | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Initial Access | T1566 | Phishing | UC-EMAIL-001 Phishing With Malicious Link | Email security logs, message trace, URL click logs | Planned | Add campaign hunting query |
| Initial Access | T1078 | Valid Accounts | UC-IDENTITY-002 Suspicious Valid Account Use | Entra ID sign-in logs, audit logs | Planned | Link to impossible travel and risky sign-in detections |
| Execution | T1059 | Command and Scripting Interpreter | UC-ENDPOINT-002 Suspicious PowerShell | EDR, Sysmon, PowerShell logs | Planned | Include encoded command logic |
| Persistence | T1098 | Account Manipulation | UC-IDENTITY-003 Suspicious MFA or Auth Method Change | Entra ID audit logs | Planned | High severity for privileged users |
| Persistence | T1136 | Create Account | UC-CLOUD-002 Unauthorised Account Creation | Entra ID audit logs, admin audit logs | Planned | Require approval validation |
| Privilege Escalation | T1068 | Exploitation for Privilege Escalation | UC-ENDPOINT-003 Privilege Escalation Indicators | EDR, vulnerability context | Planned | Requires endpoint telemetry |
| Defence Evasion | T1562 | Impair Defences | UC-ENDPOINT-004 Security Tool Disabled | EDR, Defender alerts, Windows event logs | Planned | Critical if AV/EDR disabled |
| Credential Access | T1110 | Brute Force | UC-IDENTITY-001 Multiple Failed Sign-ins | Entra ID sign-in logs | Detection Drafted | Tune by user, IP, time window |
| Credential Access | T1003 | OS Credential Dumping | UC-ENDPOINT-001 Possible Credential Dumping | EDR, Sysmon, Windows security logs | Planned | Escalate immediately if confirmed |
| Discovery | T1087 | Account Discovery | UC-ENDPOINT-005 Suspicious Account Enumeration | EDR, Sysmon, command line telemetry | Planned | May be noisy for admin tools |
| Lateral Movement | T1021 | Remote Services | UC-ENDPOINT-006 Suspicious Remote Service Use | Windows logs, EDR, network logs | Planned | Needs admin baseline |
| Collection | T1114 | Email Collection | UC-EMAIL-002 Suspicious Mailbox Access | M365 audit logs, mailbox audit logs | Planned | Link to compromised mailbox playbook |
| Command and Control | T1071 | Application Layer Protocol | UC-NETWORK-001 Suspicious C2 Over Web Protocols | Proxy, DNS, firewall, EDR network telemetry | Planned | Requires threat intel enrichment |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | UC-NETWORK-002 Suspicious Outbound Data Transfer | Proxy, firewall, EDR, DLP logs | Planned | Needs baseline thresholds |
| Impact | T1486 | Data Encrypted for Impact | UC-ENDPOINT-007 Ransomware Behaviour | EDR, file activity, backup alerts | Planned | Immediate containment path required |

## Heatmap summary

| Tactic | Planned | Drafted | Validated | Operational | Gap rating |
| --- | ---: | ---: | ---: | ---: | --- |
| Initial Access | 2 | 0 | 0 | 0 | Medium |
| Execution | 1 | 0 | 0 | 0 | High |
| Persistence | 2 | 0 | 0 | 0 | Medium |
| Privilege Escalation | 1 | 0 | 0 | 0 | High |
| Defence Evasion | 1 | 0 | 0 | 0 | High |
| Credential Access | 1 | 1 | 0 | 0 | Medium |
| Discovery | 1 | 0 | 0 | 0 | High |
| Lateral Movement | 1 | 0 | 0 | 0 | High |
| Collection | 1 | 0 | 0 | 0 | Medium |
| Command and Control | 1 | 0 | 0 | 0 | High |
| Exfiltration | 1 | 0 | 0 | 0 | High |
| Impact | 1 | 0 | 0 | 0 | High |

## Mapping standard

When adding a detection, include:

- Tactic name.
- Technique ID.
- Technique name.
- Sub-technique ID if applicable.
- Why the mapping is appropriate.
- Data source that supports the mapping.
- Confidence level: Low, Medium, or High.

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
| High | Execution coverage | Add suspicious PowerShell and LOLBin detections. |
| High | Defence evasion coverage | Add EDR disabled, tamper protection disabled, and audit log disabled detections. |
| High | Lateral movement coverage | Add RDP, SMB, WinRM, and admin share use cases. |
| Medium | Email collection | Add mailbox forwarding, inbox rule, and eDiscovery export detections. |
| Medium | Cloud persistence | Add OAuth consent and service principal credential detections. |
