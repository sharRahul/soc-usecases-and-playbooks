# Review Metadata Register

Use this register to track review ownership and maintenance evidence for the current SOC use cases. Individual use-case files may also include a `## Review metadata` section, but this central register gives maintainers one place to review coverage across the library.

Do not add real analyst names, customer names, live case IDs, or sensitive evidence links to the public repository. Use role-based owners and synthetic references here. Store real review evidence in an internal system of record.

## Current review register

| Use Case ID | Status | Owner Role | Suggested Review Cadence | Last Reviewed | Reviewer | Test Evidence Reference | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| UC-IDENTITY-001 | Operational | Detection Engineering / Identity Security | Monthly | 2026-07-02 | Security Engineering Reviewer | Synthetic lab validation required before adoption | Validate identity log fields and local thresholds before use. |
| UC-IDENTITY-002 | Operational | Detection Engineering / Identity Security | Monthly | 2026-07-02 | Security Engineering Reviewer | Synthetic lab validation required before adoption | Validate app and audit log fields before use. |
| UC-CLOUD-001 | Operational | Detection Engineering / Cloud Security | Quarterly | 2026-07-02 | Security Engineering Reviewer | Synthetic lab validation required before adoption | Tune for approved VPN, proxy, and travel patterns. |
| UC-EMAIL-001 | Operational | Detection Engineering / Email Security | Monthly | 2026-07-02 | Security Engineering Reviewer | Synthetic lab validation required before adoption | Validate email and URL click telemetry before use. |
| UC-ENDPOINT-001 | Operational | Detection Engineering / Endpoint Security | Monthly | 2026-07-02 | Security Engineering Reviewer | Synthetic lab validation required before adoption | Validate endpoint process and alert telemetry before use. |

## Review fields

| Field | Purpose |
| --- | --- |
| Use Case ID | Unique use-case identifier. |
| Status | Draft, Validated, Operational, Tuning Required, or Retired. |
| Owner Role | Role accountable for reviewing and maintaining the use case. |
| Suggested Review Cadence | Review frequency based on severity and operational risk. |
| Last Reviewed | Date the public library content was last reviewed. |
| Reviewer | Role-based reviewer identifier suitable for a public repository. |
| Test Evidence Reference | Synthetic or internal evidence reference. Do not commit sensitive evidence. |
| Notes | Known assumptions, limitations, or adoption warnings. |

## Review checklist

For every review, confirm:

1. Required data sources are still accurate.
2. Detection logic still matches current table and field names.
3. Severity and escalation criteria still match business risk.
4. False-positive and tuning notes remain current.
5. MITRE ATT&CK mappings are still valid.
6. Evidence preservation steps are practical.
7. Response guidance is safe and approval-aware.
8. Metrics review has been performed for operational detections.

## Internal evidence guidance

In a private SOC environment, link this register to:

- SIEM rule ID.
- Change ticket.
- Test result.
- False-positive review.
- Detection owner approval.
- Alert-volume and response metrics.
- Tuning decision record.

Keep those private references outside this public repository unless they are fully synthetic.