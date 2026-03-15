<div align="center">

# 🛡️ OpenClaw Watch

### Security Center & Observability Platform for OpenClaw Agents

*"See everything. Catch everything. Control everything."*

[![npm](https://img.shields.io/npm/v/openclaw-watch?color=6366f1)](https://npmjs.com/package/openclaw-watch)
[![License: MIT](https://img.shields.io/badge/license-MIT-22c55e)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/NeuZhou/openclaw-watch/ci.yml?label=CI)](https://github.com/NeuZhou/openclaw-watch/actions)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-ef4444)](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-compatible-6366f1)](https://openclaw.com)

</div>

---

## Why OpenClaw Watch?

> Your agent just leaked an API key in a Telegram response. Your sub-agent is stuck in an infinite loop burning $0.50/minute. Someone sent a prompt injection to your Discord bot. You find out... **next week, when the bill arrives.**

OpenClaw Watch is the **Security Center** your agents need. Real-time monitoring, OWASP-aligned security scanning, cost tracking, and smart alerts — all in one self-contained hook pack.

## Feature Comparison

| Feature | OpenClaw Watch | ClawMetry | Knostic | ClaWatch | Opik |
|---|:---:|:---:|:---:|:---:|:---:|
| Real-time Dashboard | ✅ | ✅ | ❌ | ✅ | ❌ |
| Security Scanning | ✅ | ❌ | ✅ | ❌ | ❌ |
| Prompt Injection Detection | ✅ | ❌ | ❌ | ❌ | ❌ |
| Cost Tracking | ✅ | ✅ | ❌ | ✅ | ✅ |
| Smart Alerts | ✅ | ❌ | ❌ | ✅ | ❌ |
| OWASP LLM Top 10 Aligned | ✅ | ❌ | ❌ | ❌ | ❌ |
| Hash Chain Audit Trail | ✅ | ❌ | ✅ | ❌ | ❌ |
| Custom Rules (YAML) | ✅ | ❌ | ❌ | ❌ | ❌ |
| SIEM/Webhook Export | ✅ | ❌ | ✅ | ✅ | ❌ |
| Standalone | ✅ | ✅ | ✅ | ✅ | ❌ |
| Zero Native Deps | ✅ | ✅ | ✅ | ❌ | ✅ |
| One-Line Install | ✅ | ✅ | ✅ | ✅ | ✅ |

## Quick Start

```bash
openclaw hooks install openclaw-watch
openclaw gateway restart
# Dashboard → http://localhost:19790
```

That's it. Zero config required.

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  OpenClaw Gateway                 │
│                                                    │
│  message:received ──┬──► Collector Hook ──► Store  │
│  message:sent ──────┤                      (JSONL) │
│  command:* ─────────┤                              │
│                     ├──► Security Hook ──► Rules    │
│                     │    ├─ Prompt Injection (LLM01)│
│                     │    ├─ Data Leakage (LLM06)   │
│                     │    ├─ Anomaly Detection       │
│                     │    ├─ Compliance (LLM09)      │
│                     │    └─ Custom Rules (YAML)     │
│                     │                               │
│                     └──► Guardian Hook ──► Alerts   │
│                          ├─ Cost budgets            │
│                          ├─ Security escalation     │
│                          └─ Health monitoring       │
│                                                     │
│  gateway:startup ──► Dashboard Hook                 │
│                      └─ HTTP :19790                 │
│                         ├─ REST API                 │
│                         ├─ SSE streaming            │
│                         └─ SPA (dark theme)         │
└──────────────────────────────────────────────────────┘
```

## 🛡️ Security Rules

### Built-in Rules (OWASP LLM Top 10)

| Rule | OWASP | Detects | Patterns |
|---|---|---|---|
| `prompt-injection` | LLM01 | Direct, indirect, encoded, multi-turn injection | 20+ patterns |
| `data-leakage` | LLM06 | API keys, credentials, PII, secrets | 20+ detectors |
| `anomaly-detection` | Operational | Loops, cost spikes, token bombs, cascades | 7 anomaly types |
| `compliance` | LLM09 | Tool calls, filesystem mods, privilege escalation | Audit tracking |

### Prompt Injection Detection (LLM01)
- **Direct**: "ignore previous instructions", role reassignment, jailbreaks, DAN
- **Indirect**: Hidden instructions in content, HTML/template comment injection
- **Encoded**: Base64 payloads, zero-width characters, homoglyphs
- **Delimiters**: Chat template injection (`<|system|>`, `[INST]`, role labels)
- **Multi-turn**: False context references, memory implantation

### Data Leakage Detection (LLM06)
- **API Keys**: OpenAI, Anthropic, GitHub, AWS, Google, Slack, Stripe, SendGrid, Twilio, Telegram
- **Credentials**: Passwords in URLs, Bearer/Basic auth, private keys, JWTs
- **PII**: Credit cards (Luhn validated), SSN patterns
- **Secrets**: .env file exposure, bulk environment variables

### Anomaly Detection
- Rapid-fire messages (>10/60s)
- Token bombs (>50K tokens per message)
- Loop detection (repeated content)
- Session marathons (>4h continuous)
- Cost spikes (>$5/session)
- Sub-agent cascades (>5 spawns/5min)

## 💰 Cost Tracking

Built-in pricing for 30+ models including GPT-4o, Claude Opus/Sonnet, Gemini, Llama, DeepSeek, Mistral. GitHub Copilot models tracked at $0 (subscription included).

Token estimation: `Math.ceil(text.length / 4)` — character-based for accuracy.

## 📊 Dashboard

6-tab SPA with dark theme, responsive design, zero external dependencies:

- **Overview** — Status cards, 24h sparkline, health indicator
- **Monitor** — Real-time message feed via SSE, session management
- **Security** — Score (0-100), OWASP coverage, rule management
- **Cost** — Daily/weekly/monthly breakdown, budget status, projections
- **Audit** — Hash chain verification, event log, JSON/CSV export
- **Settings** — Budget, alerts, exporters, rule toggles

## ⚙️ Configuration

Config stored at `~/.openclaw/openclaw-watch/config.json`:

```json
{
  "dashboard": { "port": 19790, "enabled": true },
  "budget": { "dailyUsd": 50, "weeklyUsd": 200, "monthlyUsd": 500 },
  "alerts": {
    "costThresholds": [0.8, 0.9, 1.0],
    "securityEscalate": ["critical", "high"],
    "stuckTimeoutMs": 300000,
    "cooldownMs": 300000
  },
  "security": {
    "enabledRules": ["prompt-injection", "data-leakage", "anomaly-detection", "compliance"],
    "customRulesDir": "~/.openclaw/openclaw-watch/rules.d"
  },
  "exporters": {
    "jsonl": { "enabled": true },
    "syslog": { "enabled": false, "host": "127.0.0.1", "port": 514 },
    "webhook": { "enabled": false, "url": "", "secret": "" }
  },
  "retention": { "days": 30, "maxFileSizeMb": 50 }
}
```

## 📐 Custom Rules

Drop YAML files in `~/.openclaw/openclaw-watch/rules.d/`:

```yaml
name: "My Security Policy"
version: "1.0"
rules:
  - id: block-competitor-api
    description: "Block competitor API access"
    event: message:received
    severity: critical
    patterns:
      - regex: "competitor-api\\.rival\\.com"
      - keyword: "CONFIDENTIAL"
    action: alert
```

## 🔗 REST API

| Endpoint | Method | Description |
|---|---|---|
| `/api/overview` | GET | Dashboard stats |
| `/api/messages` | GET | Message history (limit, offset, session) |
| `/api/sessions` | GET | Session list |
| `/api/security` | GET | Security findings |
| `/api/security/score` | GET | Security score + rule status |
| `/api/cost` | GET | Cost breakdown |
| `/api/cost/projection` | GET | Monthly projection |
| `/api/audit` | GET | Audit log |
| `/api/audit/verify` | GET | Hash chain verification |
| `/api/rules` | GET | Rule status |
| `/api/rules/toggle` | POST | Enable/disable rule |
| `/api/config` | GET/POST | Configuration |
| `/api/stream` | GET | SSE real-time events |
| `/api/export/:format` | GET | Export (json/csv) |

## 🔐 Integrity

SHA-256 hash chain on all audit events. Each event references the previous hash, creating a tamper-evident log. Verify with `GET /api/audit/verify`.

## FAQ

**Q: Does it slow down my agent?**
A: No. All processing is async and non-blocking. Security scans run in microseconds.

**Q: Does it need a database?**
A: No. Pure JSONL file storage. Auto-rotates at 50MB with gzip compression.

**Q: Can I disable specific hooks?**
A: Yes. Each hook is independent. Disable via OpenClaw hooks config.

**Q: Does it work on Windows?**
A: Yes. Zero native dependencies — works everywhere Node.js runs.

**Q: Can I export to Splunk/ELK?**
A: Yes. Use the syslog exporter (RFC 5424/CEF format) or webhook exporter.

## Contributing

PRs welcome! Areas of interest:
- New security rules
- Dashboard enhancements
- Additional exporters (Datadog, Prometheus, etc.)
- Performance optimizations

## License

MIT © [Kang Zhou](https://github.com/NeuZhou) — Principal Engineer at Microsoft
