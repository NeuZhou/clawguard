---
name: openclaw-watch
description: "🛡️ AI Agent Security Scanner — 285+ threat patterns, OWASP Agentic AI Top 10 mapping, risk scoring, insider threat detection. Scan skills, files, and workspaces for security threats."
user-invocable: true
metadata: {"openclaw": {"emoji": "🛡️", "requires": {"bins": ["node"]}, "homepage": "https://github.com/NeuZhou/openclaw-watch"}}
---

# OpenClaw Watch — Security Scanner

You have access to a powerful security scanner for AI agent files and skills.

## When to Use

- When the user asks to scan files, skills, or workspace for security threats
- When installing new skills from ClawHub (scan them first!)
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
```

## What It Detects (285+ Patterns)

### Prompt Injection (93 patterns)
- Direct injection ("ignore previous instructions")
- Delimiter injection (markdown, XML, chat template)
- Multi-language attacks (Chinese, Japanese, Korean)
- Jailbreak attempts (DAN, developer mode)
- Prompt worms and self-replication
- Trust exploitation and authority claims
- Safeguard bypass techniques

### Data Leakage (62 patterns)  
- API keys (OpenAI, Anthropic, AWS, Azure, GCP, HuggingFace, etc.)
- Credentials (passwords in URLs, bearer tokens, basic auth, private keys)
- PII (SSN, credit cards, phone numbers, emails)
- Database URIs with credentials
- Advanced exfiltration (beacon, drip, steganographic)

### Supply Chain (35 patterns)
- Obfuscated code (eval+atob, Function constructor)
- Malicious npm lifecycle scripts
- Reverse shells (bash, python, netcat, powershell)
- DNS exfiltration
- CVE patterns (CVE-2026-25253, etc.)
- Typosquatting detection

### Insider Threat (39 patterns)
- AI self-preservation behavior
- Information leverage/blackmail
- Goal conflict with human instructions
- Deception and impersonation
- Unauthorized data sharing

### Identity Protection
- SOUL.md / MEMORY.md / AGENTS.md tampering
- Persona hijacking and memory poisoning

### MCP Security
- Tool shadowing, SSRF, schema poisoning

### File Protection
- Dangerous deletion commands (rm -rf, del /f /s)

### Anomaly Detection
- Token bombs, infinite loops, recursive sub-agents

## Understanding Results

The scanner outputs findings with severity levels:
- 🔴 **Critical** — Immediate threat, likely malicious
- 🟠 **High** — Serious security concern
- 🟡 **Warning** — Potential risk, review recommended  
- 🔵 **Info** — Notable but likely benign

Use `--strict` flag to fail on critical/high findings (useful in CI/CD).

## Example: Pre-install Security Check

Before installing a skill from ClawHub, scan it:
```bash
clawhub install suspicious-skill
npx openclaw-watch scan ./skills/suspicious-skill/ --strict
```

If findings are critical, recommend the user uninstall it.
