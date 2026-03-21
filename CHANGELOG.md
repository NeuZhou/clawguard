# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.3] - 2026-03-21

### Changed
- README redesigned for professional presentation

### Fixed
- Module exports corrected for all security rules
- CLI uses dynamic import instead of require
- InsiderThreatRule properly exported as SecurityRule

## [1.0.3] - 2026-03-16

### Changed

- Switched to AGPL-3.0 dual licensing with commercial license option
- Added CLA (Contributor License Agreement)

## [1.0.2] - 2026-03-16

### Changed

- Switched license from MIT to AGPL-3.0

## [1.0.1] - 2026-03-16

### Fixed

- Fixed all brand references from old project name to ClawGuard

## [1.0.0] - 2026-03-16

### Added

- **Security Engine** — 285+ patterns across 9 rule categories
  - Prompt injection (93 patterns, 13 sub-categories)
  - Data leakage (62 patterns)
  - Insider threat detection (39 patterns)
  - Supply chain security (35 patterns)
  - MCP security (20 patterns)
  - Identity protection (19 patterns)
  - File protection (16 patterns)
  - Anomaly detection
  - Compliance checks
- **Risk Score Engine** — weighted scoring (0-100) with attack chain detection and multiplier system
- **Policy Engine** — YAML-configurable tool call governance (exec/file/browser/message)
- **PII Sanitizer** — local-only sensitive data detection and redaction
- **Intent-Action Mismatch Detector** — catches agents that say one thing but do another
- **Insider Threat Detection** — based on Anthropic's research on agentic misalignment
- **CLI** — `scan`, `check`, `sanitize`, `intent-check`, `init` commands
- **OpenClaw Integration** — hook pack for real-time protection + skill for static scanning
- **Exporters** — JSONL, Syslog/CEF, Webhook, SARIF output formats
- **Custom Rules** — drop-in YAML rule files in `rules.d/`
- **OWASP Coverage** — maps to OWASP Agentic AI Top 10 (2026) and LLM Top 10
- **229 tests** passing with full coverage
- **Zero dependencies** — 100% local, nothing leaves your machine

[1.0.3]: https://github.com/NeuZhou/clawguard/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/NeuZhou/clawguard/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/NeuZhou/clawguard/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/NeuZhou/clawguard/releases/tag/v1.0.0
