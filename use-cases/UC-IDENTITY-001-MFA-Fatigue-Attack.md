# UC-IDENTITY-001 MFA Fatigue Attack

## Alert name

MFA fatigue attack: repeated failed MFA prompts followed by successful authentication.

## Objective

Detect repeated failed or denied MFA prompts for a user followed by a successful sign-in within a short period. The use case helps analysts identify push fatigue, MFA bombing, and social engineering attempts against Entra ID accounts.

## Threat scenario

An attacker has valid primary credentials and repeatedly triggers Microsoft Authenticator push requests. The attacker relies on user fatigue, confusion, or social pressure to obtain one approval and complete sign-in.

## Required data sources

| Source | Purpose | Minimum fields |
| --- | --- | --- |
| Entra ID SigninLogs | Identify failed MFA attempts and later successful sign-in | TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType, Status, AuthenticationRequirement, ConditionalAccessStatus |
| Microsoft Authenticator logs | Confirm denied, timed-out, or approved push requests where available | User, request time, result, device, location |
| Entra ID user and device context | Assess impact and trust posture | User role, device compliance, risk level, MFA methods |

## Detection logic

### Microsoft Sentinel KQL

```kql
let lookback = 1d;
let window = 15m;
let threshold = 5;
let mfaFailures = SigninLogs
| where TimeGenerated >= ago(lookback)
| where AuthenticationRequirement =~ "multiFactorAuthentication"
| where ResultType != 0
| where tostring(Status.failureReason) has_any ("MFA", "multi-factor", "denied", "timeout", "declined")
| summarize FailureCount = count(), FirstFailure=min(TimeGenerated), LastFailure=max(TimeGenerated), FailureIPs=make_set(IPAddress, 10), FailureLocations=make_set(tostring(LocationDetails.countryOrRegion), 10) by UserPrincipalName, bin(TimeGenerated, window)
| where FailureCount > threshold;
let successes = SigninLogs
| where TimeGenerated >= ago(lookback)
| where AuthenticationRequirement =~ "multiFactorAuthentication"
| where ResultType == 0
| project SuccessTime=TimeGenerated, UserPrincipalName, SuccessIP=IPAddress, SuccessLocation=tostring(LocationDetails.countryOrRegion), AppDisplayName, ConditionalAccessStatus, DeviceDetail, CorrelationId;
mfaFailures
| join kind=inner successes on UserPrincipalName
| where SuccessTime between (LastFailure .. LastFailure + window)
| project AlertTime=SuccessTime, UserPrincipalName, FailureCount, FirstFailure, LastFailure, SuccessTime, FailureIPs, FailureLocations, SuccessIP, SuccessLocation, AppDisplayName, ConditionalAccessStatus, DeviceDetail, CorrelationId
```

### Sigma rule

```yaml
title: Entra ID MFA Fatigue Pattern Followed By Success
id: 2d2cfbb1-0c41-4e1e-8c10-ucidentity001
status: experimental
description: Detects repeated failed MFA prompts followed by a successful authentication for the same user.
author: SOC Use Cases and Playbooks
logsource:
  product: azure
  service: aad
  category: SigninLogs
detection:
  selection_mfa_failure:
    AuthenticationRequirement|contains: multiFactorAuthentication
    ResultType|neq: 0
    Status.failureReason|contains:
      - MFA
      - multi-factor
      - denied
      - timeout
      - declined
  selection_mfa_success:
    AuthenticationRequirement|contains: multiFactorAuthentication
    ResultType: 0
  condition: selection_mfa_failure and selection_mfa_success
  timeframe: 15m
  aggregation:
    - count(selection_mfa_failure) by UserPrincipalName > 5
fields:
  - TimeGenerated
  - UserPrincipalName
  - IPAddress
  - LocationDetails.countryOrRegion
  - AppDisplayName
  - ConditionalAccessStatus
falsepositives:
  - User connectivity issues causing repeated MFA prompt failures.
  - Legitimate sign-in after travel or network change.
level: high
tags:
  - attack.credential_access
  - attack.t1621
```

## MITRE ATT&CK

| Tactic | Technique ID | Technique name | Rationale |
| --- | --- | --- | --- |
| Credential Access | T1621 | Multi-Factor Authentication Request Generation | The detection identifies repeated MFA push requests used to obtain user approval. |

## Severity

High.

Raise to Critical when the user is privileged, the successful sign-in is from an unfamiliar geography, the sign-in bypasses expected Conditional Access controls, or post-authentication activity is observed.

## False positive scenarios

- User has poor mobile data or Wi-Fi connectivity and receives delayed or repeated prompts.
- A legitimate user travels and completes MFA from a new location.
- A device restore, browser reset, or application re-authentication causes repeated prompts.
- A user accidentally denies several legitimate prompts before approving one.

## Tuning notes

- Start with more than 5 failures within 15 minutes and tune by business baseline.
- Suppress known helpdesk-assisted enrolment windows where documented.
- Increase severity for privileged roles, break-glass accounts, finance users, and service owners.
- Correlate with impossible travel, risky sign-ins, password spray, and suspicious inbox rule activity.

## Triage steps

1. Confirm the trigger: identify the failed MFA prompts, the later successful sign-in, source IPs, application, and geography.
2. Check whether the user confirms the approval and whether they recognise the device, time, and application.
3. Review Conditional Access result, device compliance, Entra ID risk score, and any recent password failures.
4. Check for post-authentication activity: mailbox access, OAuth consent, file downloads, privileged actions, and endpoint alerts.
5. Review recent MFA method changes and authentication method registration events.

## Escalation criteria

Escalate to incident response when any of the following are true:

- The user denies approving the prompt or cannot be contacted promptly.
- The account is privileged, VIP, finance-related, or has access to sensitive systems.
- The successful sign-in is from a suspicious IP, unfamiliar country, anonymising service, or unmanaged device.
- There is evidence of mailbox access, data access, OAuth consent, lateral movement, or additional account compromise.
- Multiple users show similar MFA fatigue patterns from the same infrastructure.

## Evidence to preserve

- SigninLogs rows for the failed and successful authentications.
- CorrelationId, IP address, location, UserPrincipalName, AppDisplayName, device detail, and Conditional Access result.
- Microsoft Authenticator request records where available.
- User confirmation notes, contact time, and response.
- Post-authentication activity logs for mailbox, files, app consent, and privileged actions.
- Incident ticket timeline and containment decisions.

## Containment and recovery

- Disable the affected account if compromise is likely or the user cannot validate the sign-in.
- Revoke active sessions and refresh tokens.
- Force password reset and MFA re-registration using trusted recovery procedures.
- Remove suspicious authentication methods and review recent MFA method changes.
- Apply Conditional Access step-up or sign-in risk controls as appropriate.
- Monitor the user for at least 24 to 72 hours for recurrence and related activity.

## Lessons learned fields

| Field | Notes |
| --- | --- |
| Root cause | Was the account password compromised, phished, reused, or guessed? |
| Detection quality | Did the threshold fire at the right time and severity? |
| Response quality | Were sessions revoked and MFA re-registered quickly enough? |
| User education | Does the user need guidance on number matching and reporting unexpected prompts? |
| Control improvement | Is stronger Conditional Access, phishing-resistant MFA, or risk-based access required? |
