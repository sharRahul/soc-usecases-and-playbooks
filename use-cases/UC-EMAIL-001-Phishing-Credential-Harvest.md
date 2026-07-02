---
id: UC-EMAIL-001
title: Phishing Credential Harvest
domain: email
severity: high
attack_focus: Phishing link and credential harvesting exposure
lifecycle_status: operational
mitre_tactics:
  - Initial Access
  - Reconnaissance
mitre_techniques:
  - T1566.002
  - T1598
mitre_mapping:
  - tactic: Initial Access
    technique_id: T1566.002
    technique_name: 'Phishing: Spearphishing Link'
    detection_source: Defender for Office 365 EmailEvents, UrlClickEvents
  - tactic: Reconnaissance
    technique_id: T1598
    technique_name: Phishing for Information
    detection_source: Defender for Office 365 EmailEvents, UrlClickEvents, Entra ID SigninLogs
data_sources:
  - Defender for Office 365 EmailEvents
  - Defender for Office 365 UrlClickEvents
  - Entra ID SigninLogs
  - Email investigation artefacts
---

# UC-EMAIL-001 Phishing Credential Harvest

## Alert name

Phishing credential harvest email with allowed URL click.

## Objective

Detect phishing messages where a user received a suspected credential harvesting email and clicked a URL that was allowed. The use case helps analysts confirm exposure, assess credential compromise risk, and contain malicious email campaigns.

## Threat scenario

An attacker sends a phishing email containing a link to a credential harvesting page. The message is detected as phishing, but the user clicks the link before block, detonation, or manual response prevents access.

## Required data sources

| Source | Purpose | Minimum fields |
| --- | --- | --- |
| Defender for Office 365 EmailEvents | Identify phishing messages and delivery context | Timestamp, NetworkMessageId, RecipientEmailAddress, SenderFromAddress, SenderFromDomain, ThreatTypes, DeliveryAction |
| Defender for Office 365 UrlClickEvents | Identify user clicks and allowed actions | Timestamp, NetworkMessageId, AccountUpn, Url, ActionType, IPAddress |
| Entra ID SigninLogs | Check post-click sign-in anomalies | TimeGenerated, UserPrincipalName, IPAddress, LocationDetails, ResultType, AppDisplayName, RiskLevelAggregated |
| Email investigation artefacts | Support forensics and campaign scoping | Message headers, URLs, attachments, sender infrastructure |

## Detection logic

### Microsoft Sentinel KQL

```kql
let lookback = 7d;
let phishingEmails = EmailEvents
| where Timestamp >= ago(lookback)
| where ThreatTypes has "Phish"
| project EmailTime=Timestamp, NetworkMessageId, RecipientEmailAddress, SenderFromAddress, SenderFromDomain, Subject, ThreatTypes, DeliveryAction;
let allowedClicks = UrlClickEvents
| where Timestamp >= ago(lookback)
| where ActionType == "ClickAllowed"
| project ClickTime=Timestamp, NetworkMessageId, AccountUpn, Url, ClickAction=ActionType, ClickIPAddress=IPAddress;
phishingEmails
| join kind=inner allowedClicks on NetworkMessageId
| extend ClickDelayMinutes = datetime_diff('minute', ClickTime, EmailTime)
| project AlertTime=ClickTime, RecipientEmailAddress, AccountUpn, SenderFromAddress, SenderFromDomain, Subject, ThreatTypes, DeliveryAction, Url, ClickAction, ClickIPAddress, ClickDelayMinutes, NetworkMessageId
```

### Defender Advanced Hunting query

```kql
let lookback = 7d;
EmailEvents
| where Timestamp >= ago(lookback)
| where ThreatTypes has "Phish"
| join kind=inner (
    UrlClickEvents
    | where Timestamp >= ago(lookback)
    | where ActionType == "ClickAllowed"
    | project ClickTime=Timestamp, NetworkMessageId, AccountUpn, Url, ActionType, IPAddress
) on NetworkMessageId
| project ClickTime, RecipientEmailAddress, AccountUpn, SenderFromAddress, SenderFromDomain, Subject, Url, ActionType, IPAddress, ThreatTypes, DeliveryAction, NetworkMessageId
```

### Sigma rule

```yaml
title: M365 Phishing Email With Allowed URL Click
id: 8329a1ab-07f1-4e41-a6a1-55d802c3e8a9
status: experimental
description: Detects phishing email telemetry correlated with an allowed user URL click.
author: SOC Use Cases and Playbooks
logsource:
  product: m365
  service: defender.email
detection:
  selection_email:
    ThreatTypes|contains: Phish
  selection_click:
    ActionType: ClickAllowed
  condition: selection_email and selection_click
  timeframe: 7d
  aggregation:
    - correlate by NetworkMessageId
fields:
  - Timestamp
  - NetworkMessageId
  - RecipientEmailAddress
  - SenderFromAddress
  - SenderFromDomain
  - Url
  - ActionType
falsepositives:
  - Security awareness test emails.
  - Newsletter unsubscribe links misclassified as phishing.
level: high
tags:
  - attack.initial_access
  - attack.reconnaissance
  - attack.t1566.002
  - attack.t1598
```

## MITRE ATT&CK

| Tactic | Technique ID | Technique name | Rationale |
| --- | --- | --- | --- |
| Initial Access | T1566.002 | Phishing: Spearphishing Link | The alert identifies a phishing email containing a clicked URL. |
| Reconnaissance | T1598 | Phishing for Information | Credential harvesting attempts collect authentication material or sensitive user data. |

## Severity

High.

Raise to Critical when credentials were entered, the user is privileged, the clicked URL remains live, multiple users clicked, or post-click sign-in anomalies are present.

## False positive scenarios

- Approved security awareness test emails and simulated phishing exercises.
- Benign newsletter unsubscribe or account management links misclassified as phishing.
- Sandboxing or automated detonation activity attributed to a user.
- User clicked a rewritten safe link after the destination was already blocked.

## Tuning notes

- Suppress authorised phishing simulation sender domains and campaign identifiers.
- Use Safe Links verdict, URL detonation result, sender reputation, and user click context to reduce noise.
- Increase severity for credential-related URL paths, newly registered domains, and lookalike domains.
- Correlate with Entra ID sign-ins from new geographies, failed MFA, OAuth consent, and mailbox rule creation after the click.

## Triage steps

1. Confirm the alert trigger: phishing verdict, recipient, sender, subject, URL, click action, and click time.
2. Extract and safely analyse the URL using approved tooling such as VirusTotal, URLScan, sandbox, proxy, or TI platform.
3. Determine whether the user clicked only, submitted credentials, downloaded files, or granted OAuth consent.
4. Check Entra ID sign-in logs for post-click anomalies from new IPs, countries, devices, or applications.
5. Scope the campaign by sender, subject, URL, domain, NetworkMessageId, and recipient list.

## Escalation criteria

Escalate to incident response when any of the following are true:

- The user entered credentials, approved MFA, or granted OAuth consent after the click.
- The user is privileged, VIP, finance-related, or has access to sensitive systems.
- Multiple users received or clicked the same malicious URL.
- Post-click sign-in anomalies, mailbox rule changes, file access, or outbound phishing are observed.
- The URL is confirmed malicious and remained accessible during user interaction.

## Evidence to preserve

- Original message headers, subject, sender, recipient, NetworkMessageId, and delivery details.
- URL, click time, click action, source IP, and any Safe Links verdict.
- Screenshots or sandbox reports of the phishing page where safe and policy-approved.
- Entra ID sign-in logs after the click.
- User interview notes confirming whether credentials or MFA were entered.
- Campaign scope results and remediation actions.

## Containment and recovery

- Soft-delete or quarantine the message from affected mailboxes.
- Block sender, sender domain, URL, and related indicators where appropriate.
- Reset the user's password and revoke sessions if credentials were entered or compromise is suspected.
- Review and remove malicious inbox rules, forwarding, delegates, and OAuth grants.
- Notify affected users with clear reporting and credential guidance.
- Monitor for follow-on mailbox access, outbound phishing, and cloud data access.

## Lessons learned fields

| Field | Notes |
| --- | --- |
| Root cause | Did the email bypass controls, arrive before verdict, or exploit user trust? |
| Detection quality | Did the alert include enough click, URL, and message context? |
| Response quality | Were mail removal, URL blocking, and account controls applied quickly? |
| User awareness | Does the campaign indicate a training or reporting gap? |
| Control improvement | Review Safe Links, anti-phishing policy, simulation allowlists, and TI enrichment. |
