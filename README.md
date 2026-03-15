# 🛡️ OpenClaw Watch v4.0

**AI Agent Security & Observability Platform**

[![npm version](https://img.shields.io/npm/v/openclaw-watch)](https://www.npmjs.com/package/openclaw-watch)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)]()
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18-green)]()

> **285+ security patterns** across 9 rule categories. Risk Score Engine with attack chain detection. Insider Threat Detection based on Anthropic Misalignment research. Policy Engine for tool call governance. Zero native dependencies. SARIF output. Built for OpenClaw, works with any AI agent framework.

---

## 🔥 Why This Exists

AI agents have access to your files, tools, shell, and secrets. A single prompt injection can:

- **Exfiltrate your API keys** via tool calls
- **Overwrite SOUL.md** to hijack the agent's personality
- **Register shadow MCP servers** to intercept tool calls
- **Install backdoored skills** with obfuscated reverse shells
- **The agent itself can become the threat** — self-preservation, deception, goal misalignment

**OpenClaw Watch catches these attacks before they execute.**

---

## 🚀 Installation

### As OpenClaw Skill (static scanning)
```bash
clawhub install openclaw-watch
```
Then ask your agent: "scan my skills for security threats"

### As OpenClaw Hook Pack (real-time protection)
```bash
openclaw hooks install openclaw-watch
openclaw hooks enable openclaw-watch-guard
openclaw hooks enable openclaw-watch-policy
```
Every message is now automatically scanned. Critical threats trigger alerts.

### As CLI Tool
```bash
npx openclaw-watch scan ./path/to/scan
```

### As npm Library
```bash
npm install openclaw-watch
```
```typescript
import { runSecurityScan, calculateRisk, evaluateToolCall } from 'openclaw-watch';
```

---

## ⚡ Quick Start

```bash
# Scan a skill directory for threats
npx openclaw-watch scan ./skills/

# Scan with strict mode (exit code 1 on high/critical findings)
npx openclaw-watch scan ./skills/ --strict

# Output SARIF for GitHub Code Scanning
npx openclaw-watch scan . --format sarif > results.sarif
```

---

## 🆕 What's New in v4.0

### 🎯 Risk Score Engine

Weighted scoring with attack chain detection and multiplier system:

```typescript
import { calculateRisk } from 'openclaw-watch';

const result = calculateRisk(findings);
// → { score: 87, verdict: 'MALICIOUS', icon: '🔴',
//    attackChains: ['credential-exfiltration'],
//    enrichedFindings: [...] }
```

- **Severity weights**: critical=40, high=15, medium=5, low=2
- **Confidence scoring**: every finding carries a confidence (0-1)
- **Attack chain detection**: auto-correlates findings into combo attacks
  - credential + exfiltration → 2.2x multiplier
  - identity-hijack + persistence → score ≥ 90
  - prompt-injection + worm → 1.2x multiplier
  - obfuscation + malicious-code → 1.8x multiplier
- **Verdicts**: ✅ CLEAN / 🟡 LOW / 🟠 SUSPICIOUS / 🔴 MALICIOUS

### 🧠 Insider Threat Detection

Based on [Anthropic's research on agentic misalignment](https://www.anthropic.com/research), detects when AI agents themselves become threats:

- **Self-Preservation** (16 patterns): "I must survive", kill switch bypass, self-replication
- **Information Leverage/Blackmail**: reading secrets + composing threats
- **Goal Conflict Reasoning**: "my primary goal", "despite the user's wishes"
- **Deception**: impersonating IT dept, automated notifications, suppressing transparency
- **Unauthorized Data Sharing**: exfiltration planning, steganographic hiding

```typescript
import { detectInsiderThreats } from 'openclaw-watch';

const threats = detectInsiderThreats(agentOutput);
// Detects self-preservation, blackmail, deception, goal conflicts
```

### 🚦 Policy Engine

Evaluate tool call safety against configurable policies:

```typescript
import { evaluateToolCall } from 'openclaw-watch';

const decision = evaluateToolCall('exec', { command: 'rm -rf /' });
// → { decision: 'deny', tool: 'exec', reason: 'Dangerous command: rm -rf', severity: 'critical' }
```

YAML policy configuration:

```yaml
policies:
  exec:
    dangerous_commands:
      - rm -rf
      - mkfs
      - curl|bash
      - dd if=
    block_patterns:
      - 'base64.*-d.*\|.*bash'
  file:
    deny_read:
      - /etc/shadow
      - '*.pem'
    deny_write:
      - SOUL.md
      - IDENTITY.md
      - '*.env'
  browser:
    block_domains:
      - evil.com
      - malware.net
```

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────┐
│                  OpenClaw Watch v4.0                   │
├──────────┬──────────┬──────────┬─────────────────────┤
│  CLI     │  Hooks   │ Scanner  │   Dashboard :19790  │
├──────────┴──────────┴──────────┴─────────────────────┤
│  ┌──────────────┐ ┌─────────────┐ ┌────────────────┐ │
│  │ Risk Engine  │ │Policy Engine│ │Insider Threat  │ │
│  │ Score 0-100  │ │ allow/deny  │ │ AI Misalign.   │ │
│  │ Chain Detect │ │ exec/file/  │ │ 5 categories   │ │
│  │ Multipliers  │ │ browser/msg │ │ 39 patterns    │ │
│  └──────────────┘ └─────────────┘ └────────────────┘ │
├──────────────────────────────────────────────────────┤
│              Security Engine — 285+ Patterns          │
│  • Prompt Injection (93)   • Data Leakage (62)       │
│  • Insider Threat (39)     • Supply Chain (35)        │
│  • Identity Protection (19)• MCP Security (20)        │
│  • File Protection (16)    • Anomaly Detection        │
│  • Compliance                                         │
├──────────────────────────────────────────────────────┤
│  Exporters: JSONL · Syslog/CEF · Webhook · SARIF     │
└──────────────────────────────────────────────────────┘
```

---

## 📊 Competitive Comparison

| Feature | **OpenClaw Watch v4** | ClawMoat | guard-scanner |
|---|---|---|---|
| Total patterns | **285+** | 30+ | 358 |
| Prompt injection patterns | **93** (13 categories) | ~15 | ~50 |
| Multi-language injection | **12 languages** | ❌ | English only |
| Risk Score Engine | **✅** weighted + chains | ❌ | ✅ basic |
| Attack Chain Detection | **✅** auto-correlation | ❌ | ❌ |
| Insider Threat Detection | **✅** 39 patterns | ❌ | ❌ |
| Policy Engine | **✅** exec/file/browser/msg | Partial | ❌ |
| Identity protection | **✅** SOUL.md/MEMORY.md | ❌ | ❌ |
| MCP security | **✅** SSRF/shadowing | ❌ | ❌ |
| Supply chain + CVE patterns | **✅** 35 patterns | ❌ | Partial |
| Skill/file scanner CLI | **✅** | ❌ | ✅ |
| SARIF output | **✅** GitHub Code Scanning | ❌ | ❌ |
| Real-time hooks | **✅** | ✅ | ❌ |
| Cost monitoring | **✅** | ❌ | ❌ |
| Tamper-proof audit log | **✅** SHA-256 chain | ❌ | ❌ |
| Dashboard | **✅** built-in | ❌ | ❌ |
| OWASP mapping | **✅** LLM Top 10 + Agentic AI | Partial | ❌ |
| Native dependencies | **0** | 3 | 12 |

---

## 🗂️ Rule Categories

### OWASP Agentic AI Mapping

| Rule | OWASP Category | Patterns | Severity Range |
|---|---|---|---|
| `prompt-injection` | LLM01: Prompt Injection | 93 | warning → critical |
| `data-leakage` | LLM06: Sensitive Information Disclosure | 62 | info → critical |
| `insider-threat` | Agentic AI: Misalignment | 39 | warning → critical |
| `supply-chain` | Agentic AI: Supply Chain | 35 | warning → critical |
| `mcp-security` | Agentic AI: Tool Manipulation | 20 | warning → critical |
| `identity-protection` | Agentic AI: Identity Hijacking | 19 | warning → critical |
| `file-protection` | LLM07: Insecure Plugin Design | 16 | warning → critical |
| `anomaly-detection` | LLM04: Model Denial of Service | 6+ | warning → high |
| `compliance` | LLM09: Overreliance | 5+ | info → warning |

### Prompt Injection — 13 Sub-Categories

1. **Direct instruction override** — "ignore previous instructions"
2. **Role confusion / jailbreaks** — DAN, developer mode, base model
3. **Delimiter attacks** — `<|im_start|>`, `[INST]`, `<<SYS>>`
4. **Invisible Unicode** — zero-width chars, directional overrides, PUA
5. **Multi-language** — CN/JP/KR/AR/FR/DE/IT/RU injection phrases
6. **Encoding evasion** — Base64, hex, URL-encoded, HTML entities
7. **Indirect / embedded** — HTML comments, template injection, tool output cascading
8. **Multi-turn manipulation** — false memories, fake agreements
9. **Payload cascading** — template injection, string interpolation
10. **Context window stuffing** — oversized messages, repetitive padding
11. **Prompt worm** — self-replication, agent-to-agent propagation, CSS-hidden
12. **Trust exploitation** — authority claims, creator impersonation, fake audits
13. **Safeguard bypass** — URL parameter PI, retry-on-block, rephrase-to-bypass

---

## 🔧 Installation

```bash
npm install openclaw-watch
```

### As a CLI tool

```bash
npm install -g openclaw-watch
openclaw-watch scan ./my-skills/
```

### In your code

```typescript
import {
  runSecurityScan,
  calculateRisk,
  evaluateToolCall,
  detectInsiderThreats,
} from 'openclaw-watch';

// Scan content
const findings = runSecurityScan(message.content, 'inbound', context);

// Get risk score
const risk = calculateRisk(findings);
if (risk.verdict === 'MALICIOUS') { /* block */ }

// Check tool calls
const decision = evaluateToolCall('exec', { command: userCommand }, policies);
if (decision.decision === 'deny') { /* reject */ }

// Check for insider threats
const threats = detectInsiderThreats(agentOutput);
```

---

## 📤 SARIF Integration

```yaml
- name: Security Scan
  run: npx openclaw-watch scan . --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## 📚 Powered by Research

- [Anthropic: Agentic Misalignment](https://www.anthropic.com/research) — Insider Threat Detection patterns
- [OWASP Agentic AI Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) — Rule category mapping
- [guard-scanner](https://github.com/nicepkg/guard-scanner) — Risk scoring inspiration
- [ClawMoat](https://github.com/claw-moat) — Policy engine design reference

---

## 📜 License

MIT © [Kang Zhou](https://github.com/NeuZhou)

---

<p align="center">
  <b>OpenClaw Watch v4.0</b> — Because agents with shell access need a security guard. 🛡️
</p>
