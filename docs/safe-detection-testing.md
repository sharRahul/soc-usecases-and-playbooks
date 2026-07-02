# Safe Detection Testing

This guide explains how to validate SOC use cases without using real incident records or sensitive evidence.

## Principles

1. Use a lab tenant, test workspace, or synthetic data wherever possible.
2. Use clearly labelled test accounts and test devices.
3. Get approval before testing in any shared or production environment.
4. Keep test data separate from real alert and incident data.
5. Record expected results, actual results, and tuning decisions.
6. Redact personal, client, tenant, and internal identifiers before sharing evidence.

## Test record template

| Field | Value |
| --- | --- |
| Use case ID |  |
| Test date |  |
| Tester |  |
| Environment | Lab / dev / approved production change |
| Data source |  |
| Test method | Synthetic event / benign activity / sample query / table validation |
| Expected result |  |
| Actual result |  |
| Tuning required |  |
| Evidence location |  |
| Approved by |  |

## Safe test patterns

| Domain | Safe pattern |
| --- | --- |
| Identity | Use test accounts and review sign-in log output. |
| Email | Use benign test messages and mail trace evidence. |
| Endpoint | Use approved sample telemetry or harmless lab activity. |
| Cloud | Use test resources in a lab subscription or tenant. |
| Network | Use approved connectivity checks or synthetic log rows. |

## Synthetic data approach

Synthetic events are useful when a real test would be inappropriate.

Minimum synthetic event qualities:

- Field names match the target platform schema.
- Timestamps are realistic.
- User, device, IP, URL, and process values are clearly fake.
- The test case includes both matching and non-matching examples.
- The synthetic record is not mixed with real incident data.

Example fake identity values:

```text
user: pilot.user1@contoso.example
device: LAB-WIN11-001
ip: 203.0.113.10
country: GB
app: OfficeHome
```

## KQL dry-run pattern

Before enabling an analytics rule, run a safe dry-run:

```kql
let lookback = 7d;
SigninLogs
| where TimeGenerated >= ago(lookback)
| summarize Count=count() by UserPrincipalName, AppDisplayName, ResultType
| order by Count desc
```

Then run the candidate detection over a short lookback and inspect result volume before creating an alert.

## Result review

Before routing alerts to analysts, record:

| Question | Why it matters |
| --- | --- |
| How many results appear over 24 hours, 7 days, and 30 days? | Helps estimate analyst workload. |
| Which entities trigger repeatedly? | Identifies service accounts, scheduled jobs, scanners, or automation. |
| Are results tied to approved business activity? | Prevents noisy alerts. |
| Would suppressing this activity hide suspicious behaviour? | Prevents risky allowlisting. |
| Does severity match the observed risk? | Prevents over- or under-escalation. |

## Evidence to preserve from testing

- Query used.
- Time range.
- Test account or synthetic entity.
- Result count.
- Example alert or incident.
- Tuning decisions.
- Approval or change reference where required.
- Screenshots or exports with sensitive values redacted.

## When testing is not possible

If a use case cannot be tested safely:

1. Record why testing is not possible.
2. Validate data-source availability instead.
3. Review the query with a detection engineer.
4. Mark lifecycle status as `draft` or `tuning-required` until testing is possible.
5. Do not claim the use case is operational without test evidence or a documented review decision.