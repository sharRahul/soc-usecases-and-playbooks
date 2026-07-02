# Changelog

All notable changes to this repository will be documented in this file.

The format follows the spirit of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this repository uses date-based entries until formal semantic versioning is introduced.

## [Unreleased]

### Added

- YAML front-matter schema for every use case, documented in the use-case template.
- `scripts/generate_registers.py`, which deterministically generates the MITRE ATT&CK coverage tables, the metrics register rows, the use-case index, the data-source onboarding table, Sigma exports in `sigma/`, and an ATT&CK Navigator layer from front-matter.
- `scripts/validate_detections.py`, which validates every embedded KQL and YAML detection block.
- Data-source onboarding table listing the telemetry the library depends on.
- Pull request template with generator and validation checklist.
- Audit-ready SOC documentation stack.
- Detection logic documentation standard.
- Analyst triage instruction template.
- Mermaid playbook flowchart examples.
- MITRE ATT&CK coverage matrix.
- Contribution guidance and MIT licence.

### Changed

- Expanded README into a professional project storefront with quick start guidance, minimum use-case standards, and audit value.

## [2025-12-10]

### Added

- Initial repository README describing the purpose of the SOC use-case and playbook library.
