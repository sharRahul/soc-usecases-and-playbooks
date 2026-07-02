# Data Source Setup Recipes

`docs/data-source-onboarding.md` lists the data sources required by the use cases. This companion guide explains what each source normally represents, how to onboard it, and what to verify before relying on a detection.

## General onboarding checklist

For every data source:

1. Confirm the source is legally and contractually approved for monitoring.
2. Confirm the data source is available in the tenant, SIEM, EDR, or log platform.
3. Confirm retention meets investigation and audit needs.
4. Confirm the fields used by the detection exist in your schema.
5. Confirm timestamps are normalised to a consistent timezone.
6. Confirm user, device, IP, and application identifiers can be correlated.
7. Test with benign or synthetic data before operational use.
8. Document gaps and compensating controls.

## Microsoft Sentinel / Log Analytics examples

| Source | Typical Sentinel table | Key checks |
| --- | --- | --- |
| Entra ID SigninLogs | `SigninLogs` | Interactive sign-ins are present, location fields populate, Conditional Access status is available. |
| AADNonInteractiveUserSignInLogs | `AADNonInteractiveUserSignInLogs` | Non-interactive sign-ins are ingested and user/app fields are populated. |
| Entra ID AuditLogs | `AuditLogs` | App consent, role changes, policy changes, and authentication changes are present. |
| Microsoft 365 audit logs | `OfficeActivity` or product-specific tables | Workload, operation, user, client IP, and object ID fields are present. |
| Defender for Office 365 EmailEvents | `EmailEvents` | Sender, recipient, delivery action, threat type, and network message ID are populated. |
| Defender for Office 365 UrlClickEvents | `UrlClickEvents` | Click time, URL, user, action, and threat category are populated. |
| MDE DeviceProcessEvents | `DeviceProcessEvents` | Process name, command line, account, SHA256, parent process, and device fields are populated. |
| MDE DeviceEvents | `DeviceEvents` | Action type, device, user, and additional fields support triage. |
| MDE DeviceAlertEvents | `DeviceAlertEvents` | Alert title, severity, device, evidence, and investigation status are present. |
| VPN and proxy logs | Custom table or network vendor table | User/device mapping, public IP, destination, action, and geo fields are reliable. |

## Entra ID SigninLogs

Required by:

- UC-IDENTITY-001 MFA Fatigue Attack
- UC-CLOUD-001 Impossible Travel
- UC-EMAIL-001 Phishing Credential Harvest

Minimum useful fields:

- `TimeGenerated`
- `UserPrincipalName`
- `IPAddress`
- `LocationDetails`
- `AppDisplayName`
- `ResultType`
- `Status`
- `AuthenticationRequirement`
- `ConditionalAccessStatus`
- `DeviceDetail`
- `CorrelationId`

Validation query:

```kql
SigninLogs
| summarize Count=count(), First=min(TimeGenerated), Last=max(TimeGenerated) by AppDisplayName
| order by Count desc
```

Common gaps:

- Logs retained for too short a period.
- Location data missing or inaccurate.
- Conditional Access status unavailable for older or incomplete events.
- Non-interactive activity not collected where needed.

## Entra ID AuditLogs

Required by:

- UC-IDENTITY-002 Malicious OAuth App Consent

Minimum useful fields:

- `TimeGenerated`
- `OperationName`
- `InitiatedBy`
- `TargetResources`
- `Result`
- `CorrelationId`

Validation query:

```kql
AuditLogs
| summarize Count=count() by OperationName
| order by Count desc
```

Common gaps:

- Application consent events are not retained long enough.
- Service principal changes are not correlated with sign-ins.
- Analyst cannot resolve app IDs to owner and publisher details.

## Defender for Office 365 email telemetry

Required by:

- UC-EMAIL-001 Phishing Credential Harvest

Minimum useful fields:

- Email sender and recipient
- Network message ID
- Delivery action and threat verdict
- URL click action
- URL and domain
- User and timestamp

Validation query:

```kql
EmailEvents
| summarize Count=count() by DeliveryAction, ThreatTypes
| order by Count desc
```

Common gaps:

- Safe Links click telemetry not licensed or not enabled.
- Email event and URL click tables cannot be joined because message identifiers are missing.
- Phishing investigation artefacts are kept in a portal but not exported for evidence.

## Microsoft Defender for Endpoint telemetry

Required by:

- UC-ENDPOINT-001 Possible LSASS Credential Dump

Minimum useful fields:

- `Timestamp` or `TimeGenerated`
- `DeviceName`
- `AccountName`
- `FileName`
- `ProcessCommandLine`
- `InitiatingProcessFileName`
- `InitiatingProcessCommandLine`
- `SHA256`
- Alert or action type fields

Validation query:

```kql
DeviceProcessEvents
| summarize Count=count() by DeviceName
| order by Count desc
```

Common gaps:

- Test devices are not onboarded to Defender for Endpoint.
- Command-line collection is disabled or incomplete.
- Analyst cannot access device timeline evidence.
- EDR exclusions hide relevant process activity.

## VPN, proxy, DNS, and network logs

Required by:

- UC-CLOUD-001 Impossible Travel
- Some future lateral movement, command-and-control, and exfiltration use cases

Minimum useful fields:

- User or device identifier
- Source IP
- Destination IP or URL
- Action
- Timestamp
- Geo or egress location
- Authentication result where applicable

Common gaps:

- NAT or proxy egress hides user attribution.
- Logs are not normalised to the same time format as identity events.
- Corporate VPN locations trigger false impossible-travel patterns.
- IP reputation or geo enrichment is unavailable.

## Data-source evidence to preserve

For each onboarded source, keep:

| Evidence | Purpose |
| --- | --- |
| Connector status screenshot/export | Proves the source is connected. |
| Sample event query output | Proves data is arriving. |
| Retention setting | Proves events remain available long enough for investigation. |
| Field validation query | Proves required fields are present. |
| Known limitation note | Prevents over-claiming coverage. |

## Adoption decision

Do not enable a use case operationally until:

1. Every required data source is available or the missing source is documented.
2. The detection query has been tested against local schema.
3. False positives have been reviewed.
4. Severity and escalation guidance match local risk.
5. The responsible team can access the evidence required by the playbook.