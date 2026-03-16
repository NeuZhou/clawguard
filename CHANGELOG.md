# Changelog

All notable changes to ClawGuard will be documented in this file.

## [1.0.3] - 2026-03-16

### Added
- Policy Engine with YAML configuration for tool call governance
- Threat intelligence integration
- Compliance reporter
- 67 new tests

## [1.0.2] - 2026-03-15

### Added
- Runtime protection: Anomaly Detector, Cost Tracker, Security Dashboard
- MCP Interceptor with PII filtering and rate limits
- Audit logger with JSONL/Syslog/Webhook exporters
- 54 new tests

## [1.0.1] - 2026-03-14

### Added
- 5 new security rule categories
- SARIF export for GitHub Code Scanning
- Enhanced CI pipeline
- 50+ new tests

## [1.0.0] - 2026-03-13

### Added
- Initial release
- 350+ security patterns across 11 categories
- Risk Score Engine with attack chain detection
- Insider Threat Detection (based on Anthropic research)
- Prompt injection detection (93 patterns, 13 sub-categories)
- Data leakage detection (62 patterns)
- Supply chain security (35 patterns)
- MCP security scanning (20 patterns)
- OpenClaw skill + hook pack integration
- CLI with `scan`, `init` commands
- SARIF + JSON output formats
- Zero native dependencies
