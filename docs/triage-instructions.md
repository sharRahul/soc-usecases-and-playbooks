# Triage Instructions

This document provides a standard first-response structure for SOC alerts. It is designed for analysts who need a repeatable investigation path before escalating, containing, or closing an alert.

## Triage objectives

During initial triage, the analyst must determine:

1. What triggered the alert?
2. Which user, asset, mailbox, workload, or application is affected?
3. Is there evidence of compromise, policy violation, or benign activity?
4. What evidence must be preserved?
5. Does the alert meet escalation criteria?

## Universal first three checks

For every alert, start with:

1. **Validate the alert context**: confirm time, source, affected entity, severity, rule name, and raw event fields.
2. **Check related activity**: search for related sign-ins, process activity, mailbox actions, network connections, or alerts within a relevant time window.
3. **Assess business impact**: determine whether the affected user or system is privileged, VIP, externally exposed, production-critical, or sensitive.

## Triage record template

| Field | Value |
| --- | --- |
| Alert ID | `<alert-id>` |
| Alert name | `<alert-name>` |
| Detection ID | `<use-case-id>` |
| Analyst | `<analyst-name>` |
| Start time | `<yyyy-mm-dd hh:mm>` |
| Affected entity | `<user/device/mailbox/app/ip>` |
| Severity at triage start | `<severity>` |
| Severity after review | `<severity>` |
| Evidence preserved | `<links or references>` |
| Decision | `<close/escalate/contain/monitor>` |
| Escalation ticket | `<ticket-ref>` |
| Closure reason | `<reason>` |

## Identity alert triage

Use for alerts such as impossible travel, suspicious MFA prompts, password spraying, risky sign-in, or privileged role changes.

### First three checks

1. Review sign-in timeline for the user across the last 24 hours.
2. Check MFA details, device compliance, location, IP reputation, and conditional access result.
3. Confirm whether the user is privileged, VIP, or has access to sensitive systems.

### Preserve evidence

- Sign-in logs.
- Risky user or risky sign-in detail.
- Conditional Access result.
- MFA registration or reset events.
- Privileged role assignment changes.
- Related mailbox, endpoint, or cloud activity.

### Escalate when

- A successful sign-in follows multiple failures from suspicious infrastructure.
- MFA method registration changed shortly before suspicious sign-in.
- Privileged account is involved.
- Impossible travel includes a successful session.
- User denies the activity.

## Endpoint alert triage

Use for malware, suspicious process execution, credential dumping, persistence, defence evasion, or lateral movement alerts.

### First three checks

1. Review the device timeline around the alert time.
2. Identify parent process, child process, command line, file hash, user context, and network connections.
3. Check whether the device has other alerts, vulnerability exposure, or recent software changes.

### Preserve evidence

- Process tree.
- Command line arguments.
- File hash and file path.
- Network connections.
- Logged-on user.
- Defender or EDR alert details.
- Isolation or containment actions.

### Escalate when

- Credential dumping, ransomware behaviour, suspicious PowerShell, or persistence is observed.
- The alert affects a server, privileged user, or high-value asset.
- The same indicator appears on multiple devices.
- The file is unknown, unsigned, or confirmed malicious.

## Email and phishing alert triage

Use for suspicious email, malicious attachment, malicious link, user-reported phishing, or mailbox compromise alerts.

### First three checks

1. Review sender, recipient, subject, URLs, attachment hashes, authentication results, and message trace.
2. Check whether the user clicked, opened, replied, downloaded, or entered credentials.
3. Search for similar emails across the tenant.

### Preserve evidence

- Original message or message ID.
- Email headers.
- URL and attachment details.
- Click events.
- Mailbox rules and forwarding settings.
- Message trace and delivery status.

### Escalate when

- Credentials may have been submitted.
- Malware was delivered or executed.
- Similar emails reached multiple users.
- VIP, finance, HR, or privileged user is targeted.
- Mailbox rules, forwarding, or suspicious OAuth consent is discovered.

## Cloud and SaaS alert triage

Use for suspicious admin activity, data exfiltration, mass downloads, risky OAuth consent, or cloud configuration changes.

### First three checks

1. Identify the principal, application, workload, action, source IP, and target resource.
2. Validate whether the action aligns with an approved change or expected business activity.
3. Check for related authentication, privilege change, data access, and outbound sharing events.

### Preserve evidence

- Audit log entries.
- Admin role assignments.
- App consent details.
- Data access or sharing logs.
- Change ticket or approval record.
- Affected object list.

### Escalate when

- Privileged activity is unauthorised.
- Data was shared externally or downloaded in bulk.
- OAuth consent grants high-risk permissions.
- The account shows suspicious sign-in activity.
- A security control was disabled or weakened.

## Closure categories

| Category | Use when | Required note |
| --- | --- | --- |
| True Positive - Incident | Confirmed malicious activity or policy-impacting compromise | Incident ticket and containment record |
| True Positive - Benign | Detection worked, activity was expected or authorised | Business justification and evidence |
| False Positive | Detection fired on non-relevant activity | Tuning recommendation |
| Duplicate | Same activity already handled under another alert or incident | Reference to parent ticket |
| Insufficient Evidence | Required logs are unavailable or inconclusive | Data source gap and improvement action |

## Analyst safety rules

- Do not delete evidence before escalation.
- Do not contact a suspected compromised user from the same potentially compromised channel.
- Do not perform destructive containment without approval unless the playbook explicitly allows it.
- Do not add broad allowlists without detection engineering review.
- Do not close alerts involving privileged users without a second review.

## Escalation template

```text
Summary:
Affected entity:
Alert name:
Detection ID:
Why this matters:
Evidence reviewed:
Initial findings:
Recommended action:
Containment already performed:
Outstanding questions:
```
