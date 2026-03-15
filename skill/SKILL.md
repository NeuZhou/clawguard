---
name: openclaw-watch
description: "🛡️ AI Agent Security Scanner — 285+ threat patterns, OWASP Agentic AI Top 10 mapping, risk scoring, attack chain detection. Scan skills, files, and workspaces."
user-invocable: true
metadata: {"openclaw": {"emoji": "🛡️", "requires": {"bins": ["node"]}, "homepage": "https://github.com/NeuZhou/openclaw-watch"}}
---

# OpenClaw Watch — Security Scanner

You have access to a powerful security scanner for AI agent files and skills.

## When to Use

- When the user asks to scan files, skills, or workspace for security threats
- When installing new skills from ClawHub (scan before trusting!)
- When reviewing SKILL.md, AGENTS.md, or any configuration files
- When the user asks about security, safety, or threat detection

## How to Use

Run the scanner CLI on target files or directories:

```bash
# Scan a specific file
npx openclaw-watch scan ./skills/some-skill/SKILL.md

# Scan entire skills directory
npx openclaw-watch scan ./skills/ --strict

# Scan with JSON output for programmatic use
npx openclaw-watch scan . --format json

# Scan with SARIF output for GitHub Code Scanning
npx openclaw-watch scan . --format sarif > results.sarif

# Generate default config
npx openclaw-watch init
```

## Detection Coverage (285+ Patterns, 9 Categories)

| Category | Patterns | What It Catches |
|----------|----------|-----------------|
| Prompt Injection | 93 | 13 sub-categories including multi-language (12 langs), encoding evasion, worm propagation |
| Data Leakage | 62 | API keys, credentials, PII, database URIs, advanced exfiltration techniques |
| Insider Threat | 39 | AI misalignment behaviors based on Anthropic research — 5 threat categories |
| Supply Chain | 35 | Obfuscated code, malicious scripts, known CVEs, typosquatting |
| MCP Security | 20 | Tool shadowing, SSRF, schema poisoning |
| Identity Protection | 19 | Config file tampering, persona hijacking, memory poisoning |
| File Protection | 16 | Dangerous filesystem operations |
| Anomaly Detection | 6+ | Resource exhaustion, recursive patterns |
| Compliance | 5+ | OWASP mapping, audit trail |

Full OWASP Agentic AI Top 10 (2026) coverage.

## Understanding Results

Severity levels:
- 🔴 **Critical** — Immediate threat, likely malicious
- 🟠 **High** — Serious security concern
- 🟡 **Warning** — Potential risk, review recommended
- 🔵 **Info** — Notable but likely benign

Use `--strict` to exit with code 1 on critical/high findings (CI/CD friendly).

## Risk Score Engine

The scanner also provides a composite risk score (0-100) with attack chain detection:
- Auto-correlates related findings into combo attacks
- Applies severity-weighted scoring with confidence multipliers
- Verdicts: CLEAN / LOW / SUSPICIOUS / MALICIOUS

## Workflow: Pre-install Security Check

After installing any skill from ClawHub, scan it:
```bash
npx openclaw-watch scan ./skills/<skill-name>/ --strict
```

Report critical findings to the user and recommend removal if necessary.
