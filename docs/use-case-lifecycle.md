# SOC Use-Case Lifecycle

Use this lifecycle to separate draft ideas from operational detections and to make review expectations clear for community contributors.

## Status model

| Status | Meaning | Promotion criteria |
| --- | --- | --- |
| Draft | Initial idea, incomplete logic, or untested triage guidance. | Required sections completed and owner assigned. |
| Validated | Detection logic and analyst steps have been reviewed against realistic sample data or a lab scenario. | Query works, false positives are documented, and escalation criteria are clear. |
| Operational | Content is ready to adapt into a SOC process or SIEM rule after local tuning. | Use case appears in metrics and MITRE coverage registers. |
| Tuning Required | Detection is useful but too noisy, incomplete, or dependent on missing telemetry. | Tuning action and owner are documented. |
| Retired | Use case is no longer relevant, has been replaced, or depends on obsolete telemetry. | Replacement or retirement reason is recorded in the changelog. |

## Minimum promotion checklist

Before a use case moves beyond Draft, confirm that:

- The filename follows `UC-[CATEGORY]-[NNN]-[Description].md`.
- All required section headers are present.
- Required data sources and minimum fields are documented.
- Detection assumptions, thresholds, and tuning notes are clear.
- MITRE ATT&CK mapping is included and reflected in `docs/mitre-attack-coverage.md`.
- A row exists in `docs/metrics-template.md`.
- Escalation criteria and evidence preservation steps are specific enough for a junior analyst.
- Unsafe or irreversible containment actions include an approval expectation.

## Review cadence

| Content type | Suggested cadence |
| --- | --- |
| High or Critical use cases | Monthly or after major false-positive trends. |
| Medium use cases | Quarterly. |
| Low or informational use cases | Semi-annually. |
| Data source assumptions | Whenever logging, SIEM ingestion, or product schema changes. |
| MITRE ATT&CK mapping | Quarterly or after material logic changes. |

## Change-control expectations

Record material changes in `CHANGELOG.md` when they alter detection behaviour, severity, escalation criteria, containment guidance, required data sources, or ATT&CK mapping.

For larger updates, include a short note explaining:

1. What changed.
2. Why it changed.
3. Expected impact on alert volume or triage behaviour.
4. How the change was reviewed.
5. Whether rollback or retirement is required.
