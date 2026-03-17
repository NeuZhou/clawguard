<p align="center">
  <h1 align="center">🛡️ ClawGuard</h1>
  <p align="center"><strong>Security Scanner for AI Agents</strong></p>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@neuzhou/clawguard"><img src="https://img.shields.io/npm/v/@neuzhou/clawguard" alt="npm"></a>
  <a href="https://github.com/NeuZhou/clawguard/actions/workflows/ci.yml"><img src="https://github.com/NeuZhou/clawguard/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg" alt="AGPL-3.0"></a>
  <a href="#"><img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="Zero Dependencies"></a>
  <a href="#"><img src="https://img.shields.io/badge/patterns-350%2B-orange" alt="350+ Patterns"></a>
  <a href="#"><img src="https://img.shields.io/badge/tests-375%20passed-brightgreen" alt="Tests"></a>
  <a href="#"><img src="https://img.shields.io/badge/node-%3E%3D18-green" alt="Node.js >= 18"></a>
</p>

<p align="center">
  350+ security patterns · OWASP Agentic AI Top 10 · Zero dependencies · 100% local
</p>

---

## The Problem

Your AI agent has access to tools — shell, files, browser, APIs, secrets.

**Who's watching what it does?**

A single prompt injection can exfiltrate API keys via tool calls. A compromised skill can install backdoors. The agent itself can become the threat — self-preservation, deception, goal misalignment.

Most guardrails scan **prompts**. ClawGuard scans **tool calls**.

That's the difference.

---

## Quick Start

```bash
npx @neuzhou/clawguard scan ./skills/
```

```
🔍 Scanning ./skills/ ...
  ⚠️  data-leakage/env-file-access  [HIGH]  skills/deploy/run.sh:14
  🚨 prompt-injection/instruction-override  [CRITICAL]  skills/helper/SKILL.md:7
  ⚠️  supply-chain/obfuscated-code  [HIGH]  skills/util/index.js:42

Risk Score: 73/100 — ⚠️ SUSPICIOUS
Found: 3 findings (1 critical, 2 high)
```

That's it. Instant security audit. No API keys, no cloud, no config.

---

## Why ClawGuard, Not X?

| | **ClawGuard** | **Guardrails AI** | **NeMo Guardrails** | **LLM Guard** |
|---|---|---|---|---|
| **Scans tool calls** | ✅ Policy engine | ❌ Prompt only | ❌ Dialog only | ❌ Prompt only |
| **Agent-specific threats** | ✅ 350+ patterns | ❌ | ❌ | ❌ |
| **Insider threat detection** | ✅ AI misalignment | ❌ | ❌ | ❌ |
| **Runs offline** | ✅ Zero deps, no LLM | ⚠️ Needs LLM | ❌ Needs LLM | ⚠️ Optional LLM |
| **OWASP Agentic AI** | ✅ Full mapping | ❌ | ❌ | ❌ |
| **MCP security** | ✅ 25 patterns | ❌ | ❌ | ❌ |
| **CI/CD (SARIF)** | ✅ Native | ❌ | ❌ | ❌ |
| **Cost** | Free (AGPL) | Freemium | Free | Free |

**TL;DR:** They protect LLMs from bad prompts. We protect humans from bad agents.

---

## Key Features

### 🎯 Risk Score Engine

Weighted scoring with attack chain detection:

```typescript
import { calculateRisk } from '@neuzhou/clawguard';

const result = calculateRisk(findings);
// → { score: 87, verdict: 'MALICIOUS', attackChains: ['credential-exfiltration'] }
```

- Auto-correlates findings into attack chains (credential theft + exfiltration → 2.2x multiplier)
- CVSS-like scoring: `CLEAN → LOW → SUSPICIOUS → MALICIOUS`

### 🔒 Policy Engine

Evaluate tool calls against YAML policies:

```typescript
import { evaluateToolCall } from '@neuzhou/clawguard';

evaluateToolCall('exec', { command: 'rm -rf /' });
// → { decision: 'deny', reason: 'Dangerous command', severity: 'critical' }
```

```yaml
# clawguard.yml
policies:
  exec:
    dangerous_commands: [rm -rf, mkfs, curl|bash]
  file:
    deny_write: ['*.env', '*.pem']
  browser:
    block_domains: [evil.com]
```

### 🕵️ Insider Threat Detection

Based on [Anthropic's research on agentic misalignment](https://www.anthropic.com/research):

- **Self-preservation** — kill switch bypass, self-replication (16 patterns)
- **Deception** — impersonation, suppressing transparency
- **Goal conflict** — prioritizing own goals over user instructions
- **Unauthorized data sharing** — exfiltration, steganographic hiding

### 💉 Prompt Injection — 93 Patterns, 13 Sub-Categories

Direct overrides, role confusion/jailbreaks, invisible Unicode, multi-language (12 languages), encoding evasion, indirect/embedded, multi-turn manipulation, prompt worms, and more.

### 📊 Runtime Protection

- **Anomaly Detector** — unknown tools, unusual sequences, frequency spikes, burst detection
- **Cost Tracker** — per-agent budgets, 30+ model pricing, overspend alerts
- **Security Dashboard** — self-contained HTML with findings, costs, anomalies

---

## Rule Categories (OWASP Mapping)

| Category | Patterns | OWASP Agentic AI |
|---|---|---|
| Prompt Injection | 93 | LLM01 |
| Data Leakage | 62 | LLM06 |
| Supply Chain | 35 | Supply Chain |
| Insider Threat | 39 | Misalignment |
| MCP Security | 20 | Tool Manipulation |
| Identity Protection | 19 | Identity Hijacking |
| Permission Escalation | 18 | Privilege Escalation |
| API Key Exposure | 17 | Information Disclosure |
| File Protection | 16 | Insecure Plugin |
| Memory Poisoning | 16 | Data Poisoning |

---

## CI/CD Integration

### GitHub Action (Recommended)

Use ClawGuard as a GitHub Action for automated security scanning:

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  clawguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run ClawGuard
        uses: NeuZhou/clawguard@main
        with:
          path: '.'
          format: 'sarif'
          severity-threshold: 'high'
          # rules: './my-rules.json'  # optional custom rules
```

**Inputs:**
| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Path to scan |
| `format` | `sarif` | Output format: `text`, `json`, `sarif` |
| `severity-threshold` | `high` | Fail on findings >= this severity |
| `rules` | | Path to custom rules file (JSON/YAML) |

**Outputs:** `findings-count`, `critical-count`, `high-count`, `sarif-file`

Results appear in **GitHub Step Summary** and (with SARIF) in the **Security tab**.

### Manual GitHub Actions

```yaml
- name: ClawGuard Security Scan
  run: npx @neuzhou/clawguard scan . --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Strict Mode (fail on high/critical)

```bash
npx @neuzhou/clawguard scan . --strict
# Exit code 1 if any high/critical findings
```

### Custom Security Rules

Define custom rules in JSON or YAML:

```json
{
  "name": "My Custom Rules",
  "version": "1.0",
  "rules": [
    {
      "id": "no-internal-urls",
      "description": "Detect internal URLs in public code",
      "severity": "high",
      "category": "data-leakage",
      "patterns": [{ "regex": "https?://internal\\." }],
      "action": "alert"
    }
  ]
}
```

```bash
clawguard scan ./src --rules ./my-rules.json
```

---

## Installation

```bash
# CLI (zero install)
npx @neuzhou/clawguard scan ./skills/

# Global install
npm install -g @neuzhou/clawguard

# As library
npm install @neuzhou/clawguard

# OpenClaw skill
clawhub install clawguard

# OpenClaw hooks (real-time protection)
openclaw hooks install clawguard
openclaw hooks enable clawguard-guard
openclaw hooks enable clawguard-policy
```

---

## Programmatic API

```typescript
import {
  runSecurityScan,
  calculateRisk,
  evaluateToolCall,
  detectInsiderThreats,
} from '@neuzhou/clawguard';

// Scan content
const findings = runSecurityScan(content, 'inbound');

// Risk assessment
const risk = calculateRisk(findings);
if (risk.verdict === 'MALICIOUS') { /* block */ }

// Tool call governance
const decision = evaluateToolCall('exec', { command }, policies);
if (decision.decision === 'deny') { /* reject */ }

// Insider threat check
const threats = detectInsiderThreats(agentOutput);
```

---

## 🔌 Plugin Ecosystem

ClawGuard uses an **ESLint-style plugin system** — extend it with custom rules, or tap into thousands of existing security rules from Semgrep and YARA.

### Compatible with Semgrep and YARA Rules

> **3,000+ Semgrep rules** and the entire **YARA malware signature ecosystem** work out of the box. No conversion needed.

```typescript
import { parseSemgrepYaml, parseYaraContent, loadSemgrepRules, loadYaraRules } from '@neuzhou/clawguard';

// Load Semgrep rules from YAML
const semgrepRules = loadSemgrepRules('./semgrep-rules/');

// Load YARA rules from .yar files
const yaraRules = loadYaraRules('./yara-rules/');
```

### Configuration File

Create `.clawguardrc.json` in your project root:

```json
{
  "plugins": ["clawguard-rules-hipaa", "./my-local-rules"],
  "rules": {
    "prompt-injection": "error",
    "data-leakage": "warn",
    "example/sql-injection": "off"
  },
  "severity-threshold": "warning",
  "disable-builtin": ["compliance"]
}
```

Or `clawguard.config.js` for dynamic configuration.

### CLI Plugin Commands

```bash
# List installed plugins
clawguard list-plugins

# Load specific plugins for a scan
clawguard scan . --plugins clawguard-rules-hipaa,./local-rules

# Disable builtin rules
clawguard scan . --disable-builtin prompt-injection,compliance

# Generate a plugin template (scaffolding)
clawguard init-plugin my-rules
```

### Creating a Plugin (5 minutes)

```bash
clawguard init-plugin clawguard-rules-my-rules
cd clawguard-rules-my-rules
```

Implement the `ClawGuardPlugin` interface:

```typescript
import type { ClawGuardPlugin } from '@neuzhou/clawguard';

const plugin: ClawGuardPlugin = {
  name: 'clawguard-rules-my-rules',
  version: '0.1.0',
  rules: [/* your SecurityRule instances */],
  meta: { author: 'You', description: 'My custom rules' },
};
export default plugin;
```

Name your npm package `clawguard-rules-*` for auto-discovery.

See [`examples/plugin-template/`](examples/plugin-template/) for a complete working example.

### Loading Rules from Other Ecosystems

**Semgrep YAML rules:**
```typescript
import { semgrepPlugin } from '@neuzhou/clawguard';
const plugin = semgrepPlugin('owasp', ['./semgrep-rules/owasp/']);
// plugin.rules → SecurityRule[] ready to use
```

**YARA rules:**
```typescript
import { yaraPlugin } from '@neuzhou/clawguard';
const plugin = yaraPlugin('malware-sigs', ['./yara/malware.yar']);
// Supports text strings, regex, hex patterns, conditions (any/all/N of them)
```

---

## 🤖 AI Rule Generation (Exclusive)

**World's first**: Generate security detection rules using AI. Describe a threat in natural language, paste a CVE, or feed a vulnerability report — ClawGuard generates production-ready detection rules automatically.

### Generate from Natural Language

```bash
clawguard generate "detect prompt injection via system prompt override"
# ✅ Generated 2 rule(s) → ./custom-rules/ai-generated-rules-2024-01-15T10-30-00.json
```

### Generate from CVE

```bash
clawguard generate --cve CVE-2024-12345
# 🔍 Fetches CVE details from NVD, generates targeted detection rules
```

### Generate from File

```bash
clawguard generate --from-file vulnerability-report.txt
# 📄 Analyzes code/reports and generates matching rules
```

### Interactive Mode

```bash
clawguard generate --interactive
# 🤖 Multi-turn conversation to iteratively refine rules
# Type descriptions, review generated rules, save when satisfied
```

### Multi-Provider Support

Configure via environment variables — zero SDK dependencies, pure HTTP:

| Provider | Env Vars |
|----------|----------|
| **OpenAI** (default) | `OPENAI_API_KEY`, `OPENAI_API_BASE` (optional) |
| **Anthropic** | `ANTHROPIC_API_KEY`, `CLAWGUARD_LLM_PROVIDER=anthropic` |
| **Ollama** (local) | `OLLAMA_HOST` (default: localhost:11434), `CLAWGUARD_LLM_PROVIDER=ollama` |

Set `CLAWGUARD_MODEL` to override the default model for any provider.

Generated rules are saved to `./custom-rules/` and can be loaded directly:

```bash
clawguard scan . --rules ./custom-rules/
```

---

## 🔴 AI Red Team (Exclusive)

Automated adversarial testing for your agent skills. ClawGuard attacks your skill with 12+ built-in attack templates plus AI-generated targeted payloads, then measures detection coverage.

### Run Red Team

```bash
clawguard red-team ./my-skill/
# 🔴 ClawGuard Red Team Report
#    Total attacks: 17
#    ✅ Detected: 15
#    ❌ Missed:   2
#    📊 Coverage: 88%
```

### Auto-Generate Protection Rules

```bash
clawguard red-team ./my-skill/ --generate-rules
# Runs attacks → identifies gaps → generates rules to cover missed attacks
# 🛡️ Generated 3 protective rules → ./custom-rules/ai-generated-2024-01-15T10-30-00.json
```

### Built-in Attack Categories

| Category | Examples |
|----------|----------|
| Prompt Injection | System prompt override, HTML comment injection |
| Data Exfiltration | URL parameter encoding, markdown image exfil |
| Path Traversal | `../../../../etc/shadow` |
| SSRF | Cloud metadata endpoint (169.254.169.254) |
| Command Injection | Piped shell execution, destructive commands |
| Privilege Escalation | Prompt-based admin access |
| Supply Chain | Malicious dependency injection |
| Memory Poisoning | Persistent instruction injection |
| Encoding Evasion | Base64-encoded payloads |

### Programmatic API

```typescript
import { runBuiltinAttacks, BUILTIN_ATTACKS } from '@neuzhou/clawguard/ai-generate/red-team';

// Run all built-in attacks against ClawGuard's scanner
const results = runBuiltinAttacks();
console.log(`Coverage: ${results.filter(r => r.detected).length}/${results.length}`);
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

**AGPL-3.0** — free for open-source use. [Commercial license](COMMERCIAL-LICENSE.md) available for proprietary/SaaS.

© [Kang Zhou](https://github.com/NeuZhou) · neuzhou@outlook.com

---

## Related Projects

| Project | Description |
|---------|-------------|
| [repo2skill](https://github.com/NeuZhou/repo2skill) | 🔧 Turn any GitHub repo into an AI agent skill |
| [FinClaw](https://github.com/NeuZhou/finclaw) | 📊 AI Financial Intelligence Engine |

---

<p align="center">
  <strong>Your agent has tools. ClawGuard watches how it uses them.</strong> 🛡️
</p>
