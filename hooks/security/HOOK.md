# Security Hook

Real-time security scanning with OWASP LLM Top 10 alignment.

## Events

- `message:received` — Scan inbound for prompt injection
- `message:preprocessed` — Scan preprocessed content
- `message:sent` — Scan outbound for data leakage

## Rules

- **prompt-injection** (LLM01) — 20+ injection patterns
- **data-leakage** (LLM06) — API keys, credentials, PII
- **anomaly-detection** — Behavioral anomalies
- **compliance** — Audit trail tracking

## Custom Rules

Drop YAML files in `~/.openclaw/ClawGuard/rules.d/`


