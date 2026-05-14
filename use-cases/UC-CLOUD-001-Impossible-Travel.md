# UC-CLOUD-001 Impossible Travel

## Alert name

Impossible travel: account sign-ins from distant locations within an implausible time window.

## Objective

Detect accounts accessed from two geographically distant locations where the time between sign-ins would require unrealistic travel speed. The use case helps identify compromised cloud accounts, token replay, anonymising infrastructure, and unmanaged access paths.

## Threat scenario

An attacker uses valid credentials or session material from one geography while the legitimate user continues to authenticate from another. The account appears to move between countries or regions faster than physically possible.

## Required data sources

| Source | Purpose | Minimum fields |
| --- | --- | --- |
| Entra ID SigninLogs | Interactive sign-in source and result | TimeGenerated, UserPrincipalName, IPAddress, ResultType, LocationDetails, ConditionalAccessStatus, AppDisplayName |
| AADNonInteractiveUserSignInLogs | Non-interactive token activity | TimeGenerated, UserPrincipalName, IPAddress, ResultType, LocationDetails, AppDisplayName |
| VPN/proxy logs | Explain legitimate network egress | User, IP address, egress country, connection time |
| Entra ID risk signals | Support prioritisation | RiskLevelAggregated, RiskState, RiskDetail |

## Detection logic

### Microsoft Sentinel KQL

```kql
let lookback = 1d;
let minDistanceKm = 500;
let maxSpeedKmh = 900;
let signins = union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(lookback)
| where ResultType == 0
| extend Latitude = todouble(LocationDetails.geoCoordinates.latitude), Longitude = todouble(LocationDetails.geoCoordinates.longitude)
| where isnotempty(UserPrincipalName) and isnotempty(IPAddress) and isnotnull(Latitude) and isnotnull(Longitude)
| project TimeGenerated, UserPrincipalName, IPAddress, Country=tostring(LocationDetails.countryOrRegion), City=tostring(LocationDetails.city), Latitude, Longitude, AppDisplayName, ConditionalAccessStatus, RiskLevelAggregated;
signins
| sort by UserPrincipalName asc, TimeGenerated asc
| serialize
| extend PreviousUser = prev(UserPrincipalName), PreviousTime = prev(TimeGenerated), PreviousIP = prev(IPAddress), PreviousCountry = prev(Country), PreviousCity = prev(City), PreviousLatitude = prev(Latitude), PreviousLongitude = prev(Longitude)
| where UserPrincipalName == PreviousUser
| extend DeltaHours = datetime_diff('second', TimeGenerated, PreviousTime) / 3600.0
| where DeltaHours > 0 and DeltaHours <= 12
| extend DistanceKm = geo_distance_2points(Longitude, Latitude, PreviousLongitude, PreviousLatitude) / 1000.0
| extend RequiredSpeedKmh = DistanceKm / DeltaHours
| where DistanceKm >= minDistanceKm and RequiredSpeedKmh > maxSpeedKmh
| project AlertTime=TimeGenerated, UserPrincipalName, PreviousTime, CurrentTime=TimeGenerated, PreviousIP, CurrentIP=IPAddress, PreviousLocation=strcat(PreviousCity, ", ", PreviousCountry), CurrentLocation=strcat(City, ", ", Country), DistanceKm, DeltaHours, RequiredSpeedKmh, AppDisplayName, ConditionalAccessStatus, RiskLevelAggregated
```

### Sigma rule

```yaml
title: Entra ID Impossible Travel Sign-In Pattern
id: 0bdc2cd5-7950-4cb2-92cc-4c9672e2f8ea
status: experimental
description: Detects successful Entra ID sign-ins from geographically distant locations within an implausible time period.
author: SOC Use Cases and Playbooks
logsource:
  product: azure
  service: aad
  category: SigninLogs
detection:
  selection_success:
    ResultType: 0
  condition: selection_success
  timeframe: 12h
correlation:
  type: temporal
  group-by:
    - UserPrincipalName
  condition: distance_between(LocationDetails.geoCoordinates) > 500km and required_speed > 900kmh
fields:
  - TimeGenerated
  - UserPrincipalName
  - IPAddress
  - LocationDetails.countryOrRegion
  - LocationDetails.city
  - AppDisplayName
  - RiskLevelAggregated
falsepositives:
  - VPN or secure web gateway egress changes.
  - Split-tunnelling or satellite office traffic.
  - Recently relocated employees.
level: medium
tags:
  - attack.initial_access
  - attack.t1078
  - attack.t1078.004
```

## MITRE ATT&CK

| Tactic | Technique ID | Technique name | Rationale |
| --- | --- | --- | --- |
| Initial Access | T1078 | Valid Accounts | The detection identifies successful use of valid credentials from inconsistent locations. |
| Initial Access | T1078.004 | Valid Accounts: Cloud Accounts | The activity concerns Entra ID cloud account authentication. |

## Severity

Medium by default.

Raise to High for privileged users, unmanaged devices, high Entra ID risk, unfamiliar locations, failed MFA before success, or post-sign-in sensitive activity.

## False positive scenarios

- VPN, secure web gateway, or proxy egress from different countries.
- Split-tunnelling where some traffic exits locally and some through corporate infrastructure.
- Satellite offices and regional data centres sharing egress addresses.
- Recently relocated employees or business travel not reflected in HR records.
- Mobile carrier IP geolocation errors.

## Tuning notes

- Maintain allowlists for corporate VPN, secure web gateway, and known travel-support networks.
- Suppress impossible travel between known paired corporate egress points when validated.
- Use higher severity for privileged accounts and sensitive applications.
- Correlate with MFA fatigue, risky sign-ins, unfamiliar device, and token replay indicators.

## Triage steps

1. Confirm both successful sign-ins, time delta, IP addresses, applications, and calculated locations.
2. Verify whether either IP belongs to a corporate VPN, secure web gateway, proxy, or known third-party service.
3. Contact the user to confirm travel, location, device, and application usage.
4. Review Entra ID risk score, Conditional Access result, device compliance, and MFA result.
5. Check for post-sign-in activity such as mailbox access, file downloads, OAuth consent, privilege changes, or endpoint alerts.

## Escalation criteria

Escalate to incident response when any of the following are true:

- The user cannot validate one or both sign-ins.
- The account is privileged, VIP, finance-related, or has access to sensitive systems.
- One sign-in originates from anonymising infrastructure, TOR, hosting, or a high-risk ASN.
- Entra ID risk is medium or high, or Conditional Access did not enforce expected controls.
- There is evidence of data access, persistence, privilege changes, or additional suspicious account activity.

## Evidence to preserve

- SigninLogs and AADNonInteractiveUserSignInLogs records for both sign-ins.
- IP addresses, resolved geographies, applications, device detail, risk signals, and Conditional Access result.
- VPN/proxy logs that support benign explanation or show no matching user session.
- User confirmation notes and contact timeline.
- Post-authentication mailbox, file, OAuth, and admin activity.

## Containment and recovery

- Revoke sessions and require MFA step-up if suspicious but not yet confirmed as compromise.
- Disable the account if the user denies activity or cannot be contacted and risk is high.
- Force password reset and review MFA methods if credential compromise is suspected.
- Apply Conditional Access restrictions for risky sign-ins and unmanaged devices.
- Review affected applications and audit any data accessed after suspicious sign-in.

## Lessons learned fields

| Field | Notes |
| --- | --- |
| Root cause | Was the trigger caused by compromise, VPN routing, travel, or geolocation error? |
| Detection quality | Did distance, speed, and allowlist thresholds behave correctly? |
| Response quality | Were session revocation and user validation completed quickly? |
| Data source quality | Were location fields reliable and complete? |
| Tuning action | Add legitimate egress points or increase severity rules for sensitive users. |
