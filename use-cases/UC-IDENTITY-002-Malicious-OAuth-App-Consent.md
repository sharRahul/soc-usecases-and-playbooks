# UC-IDENTITY-002 Malicious OAuth App Consent

## Alert name

Malicious OAuth app consent with high-risk permissions.

## Objective

Detect user or administrator consent to third-party OAuth applications requesting permissions that could expose mail, files, directory data, or other sensitive cloud resources.

## Threat scenario

An attacker uses a phishing lure or fake productivity application to trick a user into granting OAuth consent. Once consent is granted, the attacker can access cloud data without needing the user's password or active session.

## Required data sources

| Source | Purpose | Minimum fields |
| --- | --- | --- |
| Entra ID AuditLogs | Identify application consent events | TimeGenerated, OperationName, Category, TargetResources, InitiatedBy, Result |
| Entra ID application and service principal inventory | Validate app ownership and publisher | AppId, PublisherName, VerifiedPublisher, ServicePrincipalId |
| M365 audit logs | Confirm downstream access where available | Mailbox access, file access, consent changes |

## Detection logic

### Microsoft Sentinel KQL

```kql
let lookback = 7d;
let riskyPermissions = dynamic(["Mail.Read", "Files.ReadWrite.All", "User.Read.All"]);
AuditLogs
| where TimeGenerated >= ago(lookback)
| where Category =~ "ApplicationManagement"
| where OperationName has_any ("Consent to application", "Add delegated permission grant", "Add app role assignment to service principal")
| extend InitiatingUser = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatingApp = tostring(InitiatedBy.app.displayName)
| extend TargetApp = tostring(TargetResources[0].displayName)
| extend TargetAppId = tostring(TargetResources[0].id)
| extend ModifiedProperties = tostring(TargetResources[0].modifiedProperties)
| where ModifiedProperties has_any (riskyPermissions)
| project AlertTime=TimeGenerated, OperationName, Result, InitiatingUser, InitiatingApp, TargetApp, TargetAppId, ModifiedProperties, CorrelationId
```

### Sigma rule

```yaml
title: Entra ID OAuth Consent With High-Risk Permissions
id: 1660bfb0-4185-4c6b-8f5e-cdd285ef4c21
status: experimental
description: Detects OAuth application consent events that include high-risk Microsoft Graph permissions.
author: SOC Use Cases and Playbooks
logsource:
  product: azure
  service: aad
  category: AuditLogs
detection:
  selection_operation:
    Category: ApplicationManagement
    OperationName|contains:
      - Consent to application
      - Add delegated permission grant
      - Add app role assignment to service principal
  selection_permissions:
    TargetResources.modifiedProperties|contains:
      - Mail.Read
      - Files.ReadWrite.All
      - User.Read.All
  condition: selection_operation and selection_permissions
fields:
  - TimeGenerated
  - OperationName
  - InitiatedBy.user.userPrincipalName
  - TargetResources.displayName
  - TargetResources.modifiedProperties
falsepositives:
  - Sanctioned SaaS onboarding.
  - IT-approved integration or automation deployment.
level: high
tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1550.001
  - attack.t1098.002
```

## MITRE ATT&CK

| Tactic | Technique ID | Technique name | Rationale |
| --- | --- | --- | --- |
| Defence Evasion | T1550.001 | Use Alternate Authentication Material: Application Access Token | OAuth grants can allow access through tokens rather than direct password use. |
| Persistence | T1098.002 | Account Manipulation: Additional Email Delegate Permissions | Consent grants may create persistent application access to user data. |

## Severity

High.

Raise to Critical when the app has tenant-wide admin consent, accesses mail or files at scale, uses an unverified publisher, or affects a privileged user.

## False positive scenarios

- Sanctioned SaaS onboarding by IT or the application owner.
- Approved integration with collaboration, backup, eDiscovery, or security tooling.
- Administrator consent granted during a documented change window.
- Permissions appear broad but are required and risk-accepted by the business.

## Tuning notes

- Maintain an allowlist of approved AppIds, verified publishers, and approved permission sets.
- Alert on consent to unverified publishers, newly registered applications, or apps with low user counts.
- Increase severity for admin consent, high-privilege users, and permissions that allow offline access.
- Review whether user consent is disabled or restricted to verified publishers.

## Triage steps

1. Confirm the consent event, initiating user, target application, AppId, publisher, and requested permissions.
2. Determine whether the application is approved by IT, procurement, security, or the data owner.
3. Review the app publisher, reply URLs, service principal creation time, verified publisher status, and tenant prevalence.
4. Check the user's role, recent sign-ins, phishing exposure, mailbox activity, and file access after the consent event.
5. Identify whether admin consent or tenant-wide access was granted.

## Escalation criteria

Escalate to incident response when any of the following are true:

- Consent was granted to an unapproved or suspicious application.
- The app requests Mail.Read, Files.ReadWrite.All, User.Read.All, offline_access, or similarly sensitive permissions without approval.
- The initiating user reports they did not intend to grant consent.
- The user is privileged, VIP, or has access to sensitive data.
- Evidence shows mailbox, file, or directory access after the consent event.

## Evidence to preserve

- AuditLogs consent event with CorrelationId and TargetResources.
- AppId, ServicePrincipalId, publisher, reply URLs, requested scopes, and consent type.
- Screenshots or exports of enterprise application permissions before revocation where possible.
- Sign-in and user activity for the initiating account.
- Mailbox, SharePoint, OneDrive, and Graph activity related to the app.
- Approval records or change tickets if the activity is authorised.

## Containment and recovery

- Revoke the OAuth consent grant and remove the service principal if unauthorised.
- Block the application AppId and publisher where appropriate.
- Revoke the affected user's sessions and reset credentials if phishing or account compromise is suspected.
- Audit data accessed by the app, including mail, files, and directory reads.
- Review tenant consent settings and restrict user consent where business appropriate.
- Monitor for repeated consent attempts and related phishing messages.

## Lessons learned fields

| Field | Notes |
| --- | --- |
| Root cause | Was consent caused by phishing, shadow IT, or an approved process gap? |
| Detection quality | Did the rule identify the risky permission and app context clearly? |
| Response quality | Was consent revoked and impact assessed quickly? |
| Governance improvement | Are app consent approval, user consent, and publisher controls sufficient? |
| Follow-up actions | Add approved apps to allowlist and document denied apps or publishers. |
