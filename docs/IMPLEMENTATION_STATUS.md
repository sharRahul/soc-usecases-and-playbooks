# Implementation Status

This document separates working repository capability from partial, manual, and planned areas. It is intended to prevent documentation drift and help contributors understand where to add value.

## Current working capabilities

| Area | Status | Notes |
| --- | --- | --- |
| Use-case library | Working starter | Five operational use cases exist across identity, cloud, email, and endpoint domains. |
| Use-case front matter | Working | Each use case has YAML front matter that drives generated indexes, coverage tables, Sigma exports, and the ATT&CK Navigator layer. |
| Generated registers | Working | `scripts/generate_registers.py` regenerates MITRE coverage, metrics register, data-source onboarding, use-case index, Sigma exports, and ATT&CK Navigator layer. |
| Generated-file drift check | Working | CI runs `python scripts/generate_registers.py --check` and fails when generated outputs are stale. |
| Detection validation | Working starter | `scripts/validate_detections.py` validates fenced KQL/YAML blocks for basic structure and parseability. |
| Use-case header validation | Working | GitHub Actions checks naming convention, duplicate IDs, and required operational headers. |
| Metrics template | Working | `docs/metrics-template.md` provides generated use-case rows and manual metric fields for monthly review. |
| ATT&CK coverage | Working | `docs/mitre-attack-coverage.md` shows current coverage and backlog gaps. |
| Data-source onboarding | Working starter | `docs/data-source-onboarding.md` is generated from front matter; `docs/data-source-setup-recipes.md` explains practical setup. |
| Rule deployment guidance | Working | `docs/rule-deployment-guide.md` explains how to adapt KQL, Sigma, and generated content into SIEM-specific rules. |
| Safe detection testing | Working | `docs/safe-detection-testing.md` gives safe validation patterns without real incident data. |
| Review metadata | Working documentation | `docs/review-metadata-register.md` tracks review metadata centrally. CI does not yet enforce per-use-case review metadata sections. |

## Current use-case coverage

| Use case | Domain | Status | Notes |
| --- | --- | --- | --- |
| UC-IDENTITY-001 MFA Fatigue Attack | identity | operational | KQL, Sigma, triage, evidence, and central review metadata present. |
| UC-IDENTITY-002 Malicious OAuth App Consent | identity | operational | KQL, Sigma, triage, evidence, and central review metadata present. |
| UC-CLOUD-001 Impossible Travel | cloud | operational | KQL, Sigma, triage, evidence, and central review metadata present. |
| UC-EMAIL-001 Phishing Credential Harvest | email | operational | KQL, Sigma, triage, evidence, and central review metadata present. |
| UC-ENDPOINT-001 Possible LSASS Credential Dump | endpoint | operational | KQL, Sigma, triage, evidence, and central review metadata present. |

## What the validation currently proves

| Validation | Proves | Does not prove |
| --- | --- | --- |
| Required header check | The use case has the expected operational sections. | The content is correct, complete, or production-ready. |
| Front-matter validation | Required metadata exists and maps consistently to generated outputs. | MITRE mapping quality or data-source availability. |
| Generated-file check | Generated files match current front matter and embedded Sigma blocks. | Rules have been deployed in a SIEM. |
| YAML block parsing | YAML blocks are syntactically parseable. | Full Sigma schema correctness or backend compatibility. |
| KQL structural lint | KQL blocks have basic balanced brackets and recognised pipe operators. | KQL compiles against a live Sentinel workspace or tenant schema. |

## Current manual responsibilities

Contributors and adopters must still:

1. Validate detections against their own telemetry schema.
2. Tune thresholds and allowlists to local baseline behaviour.
3. Confirm required data sources are onboarded and retained.
4. Review MITRE ATT&CK mappings for local interpretation.
5. Test escalation and response steps safely.
6. Record alert volume, false positives, MTTD, MTTR, and tuning actions in a controlled metrics location.
7. Avoid committing real incident data, personal data, client data, or credentials.

## Priority backlog

1. Add CI enforcement for `## Review metadata` or move review metadata into required front matter fields.
2. Add optional Sigma schema validation with `sigma-cli` or an equivalent tool.
3. Add optional live or sample-data KQL validation for Microsoft Sentinel queries.
4. Generate Microsoft Sentinel analytics-rule templates from KQL blocks and front matter.
5. Add more use cases for Execution, Defence Evasion, Lateral Movement, Email Collection, and Cloud Persistence.
6. Add Splunk SPL, Elastic/Kibana, and QRadar adaptation examples where practical.
7. Add synthetic sample-event packs for safe testing.

## Completed documentation gaps

- Added explicit implementation status documentation.
- Added data-source setup recipes.
- Added rule deployment/adaptation guidance.
- Added safe detection testing guidance.
- Added central review metadata register.
- Updated README documentation index and quick start flow.

## Contributor rule

When adding or changing a use case:

1. Update the YAML front matter first.
2. Keep all required operational headers.
3. Include KQL, Sigma, or a clearly documented detection format.
4. Update `docs/review-metadata-register.md` or add a `## Review metadata` section to the use case.
5. Run `python3 scripts/generate_registers.py`.
6. Run `python3 scripts/validate_detections.py`.
7. Update `CHANGELOG.md` for material changes to detection logic, severity, escalation, data sources, or response guidance.