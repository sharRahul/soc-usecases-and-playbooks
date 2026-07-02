# Rule Deployment Guide

This repository documents detections and playbooks; it does not automatically deploy rules into a production SIEM. Use this guide to adapt the documented KQL, Sigma, and playbook content safely.

## Deployment principles

1. Treat every use case as a starting point, not a drop-in production rule.
2. Validate required data sources before deploying.
3. Test detection logic with benign or synthetic events first.
4. Tune thresholds and allowlists to local baseline behaviour.
5. Deploy in a non-production or disabled state where your SIEM supports it.
6. Record rule owner, severity, data sources, query version, and rollback plan.
7. Review alert volume and false positives before routing to analysts.

## Microsoft Sentinel deployment checklist

| Step | Action | Evidence |
| --- | --- | --- |
| 1 | Confirm data tables exist and contain current events. | Query output screenshot or export. |
| 2 | Paste the KQL into Logs and run over a safe lookback period. | Query result and error-free execution. |
| 3 | Adjust table names, field names, thresholds, and entity mapping. | Change notes in rule record. |
| 4 | Create a scheduled analytics rule in disabled mode if supported, or with limited scope and clear owner. | Rule screenshot/export. |
| 5 | Set severity, tactics, techniques, and entity mapping. | Rule metadata export. |
| 6 | Define incident creation, grouping, suppression, and automation behaviour. | Rule configuration evidence. |
| 7 | Run safe test scenario or sample-data replay. | Test result and analyst notes. |
| 8 | Move to operational routing only after false positives are understood. | Approval or change ticket. |

## Sentinel KQL adaptation notes

Use case queries are written for readability. Before deployment:

- Confirm table names match your workspace.
- Confirm fields exist and have the expected type.
- Reduce lookback while testing to control query cost.
- Add `where` filters for pilot users, test devices, or safe test periods.
- Use `project` to keep analyst-relevant fields.
- Add entity mapping for account, host, IP, URL, mailbox, or application where supported.
- Document any local allowlist or suppression logic.

Example validation query:

```kql
SigninLogs
| getschema
```

Example pilot filter:

```kql
SigninLogs
| where UserPrincipalName in~ ("pilot.user1@contoso.com", "pilot.user2@contoso.com")
```

## Sigma deployment checklist

The generated Sigma files in `sigma/` are exports from the embedded Sigma blocks in `use-cases/`. They are useful for portability but still need backend-specific conversion and review.

| Step | Action |
| --- | --- |
| 1 | Confirm the Sigma rule parses with your chosen Sigma toolchain. |
| 2 | Confirm the logsource maps to your telemetry backend. |
| 3 | Convert to the target backend such as Sentinel, Splunk, Elastic, or QRadar. |
| 4 | Review field mappings and unsupported operators. |
| 5 | Run converted logic against test or sample data. |
| 6 | Record conversion notes in the rule documentation. |

Common Sigma portability gaps:

- Field names differ between products.
- Aggregation or correlation logic may not convert cleanly.
- Time windows may require backend-specific syntax.
- Backend pipelines may use different event normalisation.
- The rule may need extra enrichment to match the playbook.

## Splunk adaptation pattern

When adapting KQL or Sigma to Splunk SPL:

1. Identify the index and sourcetype for the relevant logs.
2. Map identity, host, IP, process, email, and URL fields to your Common Information Model where available.
3. Convert time-window logic to `bin`, `stats`, `transaction`, or `streamstats` patterns.
4. Add asset and identity enrichment through lookups.
5. Test in search before creating a correlation search.

## Elastic adaptation pattern

When adapting to Elastic:

1. Confirm Elastic Common Schema field mappings.
2. Convert logic to EQL, KQL, ES|QL, or detection-rule syntax.
3. Map MITRE tactics and techniques into rule metadata.
4. Validate event category, dataset, and integration names.
5. Test with non-production index patterns first.

## QRadar adaptation pattern

When adapting to QRadar:

1. Confirm DSM parsing and custom property extraction.
2. Map event names and low-level categories to the detection behaviour.
3. Build rules using AQL searches, custom properties, reference sets, and rule tests.
4. Tune by log source group and asset/user context.
5. Record CRE rule IDs and response actions.

## Rule record template

Use this minimum record when deploying a rule:

| Field | Value |
| --- | --- |
| Use case ID | `UC-...` |
| Rule name |  |
| Platform | Sentinel / Splunk / Elastic / QRadar / Other |
| Owner |  |
| Severity |  |
| Data sources |  |
| Query version |  |
| Test evidence |  |
| Known limitations |  |
| False-positive handling |  |
| Escalation route |  |
| Rollback method |  |
| Last reviewed |  |

## Do not deploy when

- Required logs are missing or stale.
- The query does not run cleanly in the target environment.
- Analysts do not have access to required evidence.
- Severity and escalation are not approved.
- False positives are unknown for high-volume detections.
- Containment actions are unsafe or unauthorised.
- The rule cannot be disabled or rolled back quickly.

## Change-control expectations

Material deployment changes should be recorded in `CHANGELOG.md` when they alter repository content. Local SIEM deployment changes should be recorded in the user's change or detection engineering system, not committed back to this public repository unless they are generic and sanitised.