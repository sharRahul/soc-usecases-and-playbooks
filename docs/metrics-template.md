# SOC Metrics Tracking Template

Use this template to track detection performance, response quality, and tuning priorities for each SOC use case. Metrics should be reviewed with analysts, detection engineers, and SOC leadership so noisy detections are improved rather than ignored.

## Detection metrics table

| Use_Case_ID | Alert_Volume_This_Period | True_Positive_Count | False_Positive_Count | FP_Rate_Percent | MTTD_Minutes | MTTR_Hours | Escalation_Rate_Percent | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| UC-IDENTITY-001-MFA-Fatigue-Attack |  |  |  |  |  |  |  |  |
| UC-IDENTITY-002-Malicious-OAuth-App-Consent |  |  |  |  |  |  |  |  |
| UC-CLOUD-001-Impossible-Travel |  |  |  |  |  |  |  |  |
| UC-EMAIL-001-Phishing-Credential-Harvest |  |  |  |  |  |  |  |  |
| UC-ENDPOINT-001-Possible-LSASS-Credential-Dump |  |  |  |  |  |  |  |  |

## Field definitions

| Field | Definition |
| --- | --- |
| Use_Case_ID | The unique use-case identifier from the `use-cases/` folder. |
| Alert_Volume_This_Period | Total number of alerts generated during the reporting period. |
| True_Positive_Count | Alerts confirmed as malicious, suspicious, policy-violating, or requiring security action. |
| False_Positive_Count | Alerts confirmed as benign, authorised, expected, or caused by known telemetry issues. |
| FP_Rate_Percent | False positive rate for the period. |
| MTTD_Minutes | Mean time to detect. Measures elapsed time from event occurrence to alert generation. |
| MTTR_Hours | Mean time to respond. Measures elapsed time from alert creation to containment, closure, or formal incident handover. |
| Escalation_Rate_Percent | Percentage of alerts escalated to senior analyst, incident response, or security engineering. |

## Calculating false positive rate

```text
FP_Rate_Percent = (False_Positive_Count / Alert_Volume_This_Period) * 100
```

When alert volume is zero, record the FP rate as `0` and add a note that the use case did not fire during the period.

## Calculating MTTD from SIEM timestamps

Mean time to detect should use consistent timestamps from the SIEM or detection platform.

Recommended timestamp fields:

| Timestamp | Meaning |
| --- | --- |
| EventTime | Time the underlying activity occurred, for example sign-in time, email click time, or process execution time. |
| AlertGeneratedTime | Time the SIEM analytics rule or detection created the alert. |

Formula:

```text
MTTD_Minutes = average(AlertGeneratedTime - EventTime in minutes)
```

Example KQL pattern:

```kql
SecurityIncident
| where CreatedTime between (startofday(ago(30d)) .. now())
| extend MTTD_Minutes = datetime_diff('minute', CreatedTime, FirstActivityTime)
| summarize Avg_MTTD_Minutes = avg(MTTD_Minutes) by Title
```

If `FirstActivityTime` is unavailable, use the earliest correlated source event timestamp from the detection query.

## Calculating MTTR from SIEM timestamps

Mean time to respond should reflect how long it takes the SOC to complete the defined response outcome.

Recommended timestamp fields:

| Timestamp | Meaning |
| --- | --- |
| AlertGeneratedTime | Time the alert or incident was created. |
| ResponseCompletedTime | Time containment, closure, or formal escalation was completed. |

Formula:

```text
MTTR_Hours = average(ResponseCompletedTime - AlertGeneratedTime in hours)
```

Example KQL pattern:

```kql
SecurityIncident
| where CreatedTime between (startofday(ago(30d)) .. now())
| where Status in ("Closed")
| extend MTTR_Hours = datetime_diff('minute', ClosedTime, CreatedTime) / 60.0
| summarize Avg_MTTR_Hours = avg(MTTR_Hours) by Title, Classification
```

If the incident is handed to a separate incident response team, record the handover time and measure SOC MTTR to handover separately from full incident recovery time.

## Tuning guidance

| Metric condition | Recommended action |
| --- | --- |
| FP rate greater than 20% | Review thresholds, allowlists, entity grouping, enrichment, and suppression logic. |
| Alert volume increases by more than 50% month on month | Validate whether the increase is attack activity, telemetry change, rule regression, or business change. |
| MTTD is increasing | Review analytics rule frequency, ingestion delay, connector health, and query performance. |
| MTTR is increasing | Review triage clarity, escalation criteria, automation, evidence access, and analyst workload. |
| Escalation rate is very low | Confirm that analysts are not under-escalating and that escalation criteria are clear. |
| Escalation rate is very high | Review severity, routing, enrichment, and whether Tier 1 can safely close more benign cases. |

## Monthly review cadence

Run a monthly review for all active use cases.

Minimum agenda:

1. Review alert volume, true positives, false positives, FP rate, MTTD, MTTR, and escalation rate.
2. Identify the top three noisy detections and assign tuning actions.
3. Identify the top three high-value detections and confirm response lessons learned.
4. Check whether data source changes affected detection quality.
5. Record any updates needed in use-case files, playbooks, or ATT&CK coverage.

## Quarterly review cadence

Run a deeper quarterly review with SOC leadership, detection engineering, threat intelligence, and incident response.

Minimum agenda:

1. Confirm whether each use case remains aligned to current threat priorities.
2. Review ATT&CK coverage and identify material gaps.
3. Validate whether severity and escalation guidance still match business risk.
4. Review automation opportunities for evidence collection and safe containment.
5. Retire stale detections or move them to backlog with a clear owner and reason.
6. Update audit evidence showing that monitoring content is reviewed and improved regularly.

## Reporting notes

- Do not publish raw incident data, personal data, credentials, or customer-specific evidence in this repository.
- Keep metric extracts in an access-controlled reporting location.
- Include enough context for tuning decisions to be repeatable and auditable.
- When a detection is tuned, update the relevant use-case file and changelog entry.
