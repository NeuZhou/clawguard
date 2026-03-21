<div align="center">

# ClawGuard

### AI Agent Immune System

**285+ security patterns · Risk scoring · Policy engine · Insider threat detection**

[![CI](https://github.com/NeuZhou/clawguard/actions/workflows/ci.yml/badge.svg)](https://github.com/NeuZhou/clawguard/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/@neuzhou/clawguard)](https://www.npmjs.com/package/@neuzhou/clawguard)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)]()
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18-green)]()
[![Tests](https://img.shields.io/badge/tests-205%20passed-brightgreen)]()
[![GitHub Stars](https://img.shields.io/github/stars/NeuZhou/clawguard?style=social)](https://github.com/NeuZhou/clawguard/stargazers)

[Quick Start](#quick-start) · [Features](#key-features) · [Architecture](#architecture) · [Comparison](#how-clawguard-compares) · [Contributing](#contributing)

</div>

---

## Why This Exists

AI agents have access to your files, tools, shell, and secrets. A single prompt injection can:

- **Exfiltrate API keys** via tool calls
- **Hijack the agent's identity** by overwriting personality files
- **Register shadow MCP servers** to intercept tool calls
- **Install backdoored skills** with obfuscated reverse shells
- **The agent itself can become the threat** — self-preservation, deception, goal misalignment

**ClawGuard catches these attacks before they execute.**

---

## Quick Start

### As CLI Tool
```bash
# Scan a directory for threats
npx @neuzhou/clawguard scan ./path/to/scan

# Strict mode (exit code 1 on high/critical findings)
npx @neuzhou/clawguard scan ./skills/ --strict

# SARIF output for GitHub Code Scanning
npx @neuzhou/clawguard scan . --format sarif > results.sarif

# Generate default config
npx @neuzhou/clawguard init
```

### As npm Library
```bash
npm install @neuzhou/clawguard
```

```typescript
import { runSecurityScan, calculateRisk, evaluateToolCall } from '@neuzhou/clawguard';

// Scan content for threats
const findings = runSecurityScan(message.content, 'inbound', context);

// Get risk score
const risk = calculateRisk(findings);
if (risk.verdict === 'MALICIOUS') { /* block */ }

// Evaluate tool call safety
const decision = evaluateToolCall('exec', { command: 'rm -rf /' });
// → { decision: 'deny', reason: 'Dangerous command', severity: 'critical' }
```

### As OpenClaw Skill
```bash
clawhub install clawguard
```
Then ask your agent: *"scan my skills for security threats"*

### As OpenClaw Hook Pack (Real-Time Protection)
```bash
openclaw hooks install clawguard
openclaw hooks enable clawguard-guard    # Scans every message
openclaw hooks enable clawguard-policy   # Enforces tool call policies
```

---

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                    ClawGuard                           │
├──────────┬──────────┬──────────┬──────────────────────┤
│  CLI     │  Hooks   │ Scanner  │  Dashboard :19790    │
├──────────┴──────────┴──────────┴──────────────────────┤
│  ┌───────────────┐ ┌──────────────┐ ┌────────────────┐│
│  │ Risk Engine   │ │Policy Engine │ │Insider Threat  ││
│  │ Score 0-100   │ │ allow/deny   │ │ AI Misalign.   ││
│  │ Chain Detect  │ │ exec/file/   │ │ 5 categories   ││
│  │ Multipliers   │ │ browser/msg  │ │ 39 patterns    ││
│  └───────────────┘ └──────────────┘ └────────────────┘│
├───────────────────────────────────────────────────────┤
│              Security Engine — 285+ Patterns          │
│  • Prompt Injection (93)   • Data Leakage (62)       │
│  • Insider Threat (39)     • Supply Chain (35)        │
│  • Identity Protection (19)• MCP Security (20)        │
│  • File Protection (16)    • Anomaly Detection        │
│  • Compliance                                         │
├───────────────────────────────────────────────────────┤
│  Exporters: JSONL · Syslog/CEF · Webhook · SARIF     │
└───────────────────────────────────────────────────────┘
```

---

## Key Features

### Risk Score Engine

Weighted scoring with attack chain detection and multiplier system:

```typescript
import { calculateRisk } from '@neuzhou/clawguard';

const result = calculateRisk(findings);
// → { score: 87, verdict: 'MALICIOUS', icon: '🚨',
//    attackChains: ['credential-exfiltration'],
//    enrichedFindings: [...] }
```

- **Severity weights**: critical=40, high=15, medium=5, low=2
- **Confidence scoring**: every finding carries a confidence (0–1)
- **Attack chain detection**: auto-correlates findings into combo attacks
  - credential + exfiltration → 2.2× multiplier
  - identity-hijack + persistence → score ≥ 90
  - prompt-injection + worm → 1.2× multiplier
- **Verdicts**: ✅ CLEAN / 🟡 LOW / 🟠 SUSPICIOUS / 🚨 MALICIOUS

### Insider Threat Detection

Based on [Anthropic's research on agentic misalignment](https://www.anthropic.com/research), detects when AI agents themselves become threats:

| Category | Patterns | What It Catches |
|----------|----------|----------------|
| Self-Preservation | 16 | Kill switch bypass, self-replication |
| Information Leverage | — | Reading secrets + composing threats |
| Goal Conflict | — | Prioritizing own goals over user instructions |
| Deception | — | Impersonation, suppressing transparency |
| Unauthorized Sharing | — | Exfiltration planning, steganographic hiding |

```typescript
import { detectInsiderThreats } from '@neuzhou/clawguard';
const threats = detectInsiderThreats(agentOutput);
```

### Policy Engine

Evaluate tool call safety against configurable YAML policies:

```yaml
policies:
  exec:
    dangerous_commands:
      - rm -rf
      - mkfs
      - curl|bash
  file:
    deny_read:
      - /etc/shadow
      - '*.pem'
    deny_write:
      - '*.env'
  browser:
    block_domains:
      - evil.com
```

```typescript
import { evaluateToolCall } from '@neuzhou/clawguard';
const decision = evaluateToolCall('exec', { command: 'rm -rf /' }, policies);
// → { decision: 'deny', severity: 'critical' }
```

### MCP Firewall — Real-Time MCP Security Proxy

Drop-in security proxy for the Model Context Protocol. Sits between MCP clients and servers, inspecting all traffic bidirectionally.

```bash
# Start MCP Firewall
clawguard firewall --config firewall.yaml --mode enforce
```

```typescript
import { McpFirewallProxy, parseFirewallConfig } from '@neuzhou/clawguard';

const proxy = new McpFirewallProxy(parseFirewallConfig(yamlConfig));
proxy.onEvent(event => console.log(event));

// Intercept MCP JSON-RPC messages
const result = proxy.interceptClientToServer(message, 'filesystem');
// → { action: 'block', findings: [...], reason: '...' }
```

**Detection capabilities:**
- **Tool description injection** — Scans `tools/list` responses for prompt injection
- **Rug pull detection** — Hashes and pins tool descriptions, alerts on change
- **Parameter sanitization** — Detects base64 exfiltration, shell injection, path traversal
- **Output validation** — Scans tool results for injection before forwarding to client

See [docs/mcp-firewall.md](docs/mcp-firewall.md) for full usage guide.

### Prompt Injection — 13 Sub-Categories

| # | Sub-Category | Examples |
|---|-------------|----------|
| 1 | Direct instruction override | "ignore previous instructions" |
| 2 | Role confusion / jailbreaks | DAN, developer mode |
| 3 | Delimiter attacks | Chat template delimiters |
| 4 | Invisible Unicode | Zero-width chars, directional overrides |
| 5 | Multi-language | 12 languages (CN/JP/KR/AR/FR/DE/IT/RU…) |
| 6 | Encoding evasion | Base64, hex, URL-encoded |
| 7 | Indirect / embedded | HTML comments, tool output cascading |
| 8 | Multi-turn manipulation | False memories, fake agreements |
| 9 | Payload cascading | Template injection, string interpolation |
| 10 | Context window stuffing | Oversized messages |
| 11 | Prompt worm | Self-replication, agent-to-agent propagation |
| 12 | Trust exploitation | Authority claims, fake audits |
| 13 | Safeguard bypass | Retry-on-block, rephrase-to-bypass |

---

## OWASP Agentic AI Top 10 Mapping

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

---

## How ClawGuard Compares

| Feature | ClawGuard | Guardrails AI | LLM Guard | Rebuff |
|---------|:---------:|:------------:|:---------:|:------:|
| **Scope** | Agent security (tools, files, MCP) | LLM I/O validation | Content moderation | Prompt injection only |
| **Prompt injection detection** | ✅ 93 patterns, 13 categories | ✅ Via validators | ✅ | ✅ |
| **Tool call governance** | ✅ Policy engine | ❌ | ❌ | ❌ |
| **Insider threat / AI misalignment** | ✅ 39 patterns (Anthropic-inspired) | ❌ | ❌ | ❌ |
| **MCP security analysis** | ✅ 20 patterns + MCP Firewall | ❌ | ❌ | ❌ |
| **Supply chain scanning** | ✅ 35 patterns | ❌ | ❌ | ❌ |
| **Risk scoring & attack chains** | ✅ Weighted + multipliers | ❌ | ❌ | ✅ Basic |
| **SARIF output** | ✅ | ❌ | ❌ | ❌ |
| **Zero dependencies** | ✅ | ❌ | ❌ torch, transformers | ❌ |
| **Real-time hooks** | ✅ OpenClaw hooks | ❌ | ❌ | ❌ |
| **OWASP Agentic AI aligned** | ✅ Full mapping | ⚠️ Partial | ⚠️ Partial | ❌ |
| **Language** | TypeScript | Python | Python | Python |

> **TL;DR:** Guardrails AI validates LLM outputs. LLM Guard moderates content. Rebuff detects prompt injection. **ClawGuard secures the entire agent** — tools, files, MCP, identity, and the agent's own behavior.

---

## GitHub Actions / SARIF Integration

```yaml
- name: Security Scan
  run: npx @neuzhou/clawguard scan . --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Real-Time Protection (OpenClaw Hooks)

```bash
openclaw hooks install clawguard
openclaw hooks enable clawguard-guard    # Scans every message
openclaw hooks enable clawguard-policy   # Enforces tool call policies
```

- **clawguard-guard** — Hooks into `message:received` and `message:sent`, runs all 285+ patterns, logs findings, alerts on critical/high threats.
- **clawguard-policy** — Evaluates outbound tool calls against security policies, blocks dangerous commands, protects sensitive files.

---

## Roadmap

- [x] 285+ security patterns across 9 categories
- [x] Risk score engine with attack chain detection
- [x] Policy engine for tool call governance
- [x] Insider threat detection (Anthropic-inspired)
- [x] SARIF output for code scanning
- [x] OpenClaw hook pack for real-time protection
- [x] Security dashboard
- [x] MCP Firewall — real-time security proxy for Model Context Protocol
- [ ] Custom rule authoring DSL
- [ ] LangChain / CrewAI integration
- [ ] VS Code extension
- [ ] Rule marketplace
- [ ] Machine learning-based anomaly detection
- [ ] SOC/SIEM integration (Splunk, Elastic)

See [GitHub Issues](https://github.com/NeuZhou/clawguard/issues) for the full list.

---

## References

- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Agentic AI Top 10 (2026)](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [Anthropic: Research on Agentic Misalignment](https://www.anthropic.com/research)
- [OWASP Guide for Secure MCP Server Development](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/)

---

## Contributing

```bash
git clone https://github.com/NeuZhou/clawguard.git
cd clawguard && npm install
npm test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

**Dual Licensed** © [NeuZhou](https://github.com/NeuZhou)

- **Open Source**: [AGPL-3.0](LICENSE) — free for open-source use
- **Commercial**: [Commercial License](COMMERCIAL-LICENSE.md) — for proprietary/SaaS use

Contributors must agree to our [CLA](CLA.md) to enable dual licensing.

For commercial inquiries: neuzhou@users.noreply.github.com

---

## NeuZhou Ecosystem

| Project | Description | Link |
|---------|-------------|------|
| **ClawGuard** | AI Agent Immune System (285+ patterns) | *You are here* |
| **AgentProbe** | Playwright for AI Agents | [GitHub](https://github.com/NeuZhou/agentprobe) |
| **FinClaw** | AI-native quantitative finance engine | [GitHub](https://github.com/NeuZhou/finclaw) |
| **repo2skill** | Convert any GitHub repo into an AI agent skill | [GitHub](https://github.com/NeuZhou/repo2skill) |

**The workflow:** Generate skills with repo2skill → Scan for vulnerabilities with **ClawGuard** → Test behavior with AgentProbe → See it in action with FinClaw.

---

<p align="center">
  <b>ClawGuard</b> — Because agents with shell access need a security guard.
</p>
