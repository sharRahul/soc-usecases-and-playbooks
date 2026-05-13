# Detection Logic Documentation

Every detection use case should be documented in a consistent way so analysts, detection engineers, and auditors understand what the rule does, what it depends on, and how it should be handled.

## Detection record template

| Field | Guidance |
| --- | --- |
| Use-case ID | Unique ID such as `UC-IDENTITY-001`. |
| Alert name | Human-readable alert title. |
| Objective | What behaviour the detection is intended to identify. |
| Threat scenario | Short description of the attacker behaviour or operational risk. |
| Severity | Informational, Low, Medium, High, or Critical. Explain the conditions that change severity. |
| Required data sources | Logs and telemetry required for the detection to work. |
| Detection logic | Sigma, KQL, SPL, YARA, EDR query, or SIEM-native logic. |
| MITRE ATT&CK mapping | Tactic, technique ID, technique name, and sub-technique where applicable. |
| False positives | Legitimate events that may trigger the detection. |
| Tuning guidance | Safe exclusions, thresholds, allowlists, and suppression logic. |
| Triage steps | First analyst checks before escalation. |
| Evidence to preserve | Logs, alerts, endpoint details, email headers, identity events, files, or memory where applicable. |
| Escalation criteria | Conditions that require incident declaration, senior analyst review, or immediate containment. |
| Response playbook | Link to relevant playbook. |
| Last reviewed | Date and reviewer. |

## Data source matrix

| Source | Example events | Detection value | Common gap |
| --- | --- | --- | --- |
| Microsoft Entra ID sign-in logs | Interactive and non-interactive sign-ins, risk events | Identity compromise, impossible travel, MFA fatigue | Logs not retained long enough or not ingested into SIEM |
| Microsoft 365 audit logs | Mailbox, SharePoint, Teams, admin actions | Email compromise, data access, admin misuse | Audit logging not enabled or advanced events unavailable |
| Microsoft Defender for Endpoint | Process, network, file, alert, device timeline | Malware, credential dumping, lateral movement | Devices not onboarded or excluded from EDR |
| Sysmon | Process creation, network connection, image load, registry events | Endpoint behaviour detection | Inconsistent config or high noise |
| Firewall and proxy logs | Source, destination, URL, action, category | C2, exfiltration, suspicious web access | NAT or proxy identity not mapped to user/device |
| DNS logs | Query, response, client, domain | DGA, tunnelling, malicious domains | No endpoint-to-query attribution |
| Email security logs | Sender, recipient, URL, attachment, verdict | Phishing, malware delivery, spoofing | Logs not correlated with user click activity |

## False positive documentation

For each detection, document likely false positives using this structure:

| Scenario | Why it triggers | How to validate | Tuning option | Risk of tuning |
| --- | --- | --- | --- | --- |
| New admin tool deployment | Unusual process or script activity | Confirm approved change ticket | Allowlist signed deployment path | Could hide abuse of the same tool |
| User travelling | Impossible travel or unfamiliar sign-in | Confirm travel and MFA success | Conditional suppression for confirmed travel period | Could mask account compromise during travel |
| Security testing | Attack simulation tools | Confirm authorised test window | Suppress by test host and time window | Could hide real attacker activity if too broad |

## Severity model

| Severity | Use when | Example response |
| --- | --- | --- |
| Informational | Useful context but no immediate action required | Record and trend. |
| Low | Suspicious but weak signal and no asset/user sensitivity | Review during normal queue handling. |
| Medium | Suspicious activity with credible telemetry or repeated activity | Triage and escalate if confirmed. |
| High | Strong evidence of compromise or activity on sensitive asset/user | Escalate to incident response. |
| Critical | Active compromise, destructive activity, widespread impact, or privileged account abuse | Immediate incident declaration and containment. |

## Example KQL detection documentation

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)
| where FailedAttempts >= 10
```

### Example metadata

| Field | Value |
| --- | --- |
| Use-case ID | UC-IDENTITY-001 |
| Alert name | Multiple failed sign-ins from same IP |
| Required data source | Microsoft Entra ID SigninLogs |
| False positives | Password changes, expired credentials, user typo, automation using stale password |
| First three checks | Check user risk, check successful sign-in after failures, check IP reputation and geolocation |
| Escalation | Escalate if followed by successful login, privileged user, impossible travel, or MFA reset |
| MITRE ATT&CK | T1110 Brute Force, TA0006 Credential Access |

## Review cadence

| Item | Recommended cadence |
| --- | --- |
| High/Critical detections | Monthly |
| Medium detections | Quarterly |
| Low/Informational detections | Semi-annual |
| Data source health | Weekly or automated |
| ATT&CK mapping | Quarterly or after material logic changes |
| False positive tuning | After each repeated noisy alert pattern |

## Change control expectations

Detection changes should record:

- What changed.
- Why it changed.
- Expected impact on alert volume.
- Test evidence.
- Rollback approach.
- Reviewer approval.

Update `CHANGELOG.md` whenever detection logic, severity, escalation criteria, or data source requirements change.
