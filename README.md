# 🛡️👁️ OpenClaw Watch

> **Monitor, secure, and understand your OpenClaw agents.**

[![Built for OpenClaw](https://img.shields.io/badge/Built%20for-OpenClaw-blue?style=flat-square)](https://github.com/nicepkg/openclaw)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=flat-square)](./LICENSE)
[![Zero Native Deps](https://img.shields.io/badge/Native%20Deps-Zero-brightgreen?style=flat-square)](#)
[![Node 18+](https://img.shields.io/badge/Node-18%2B-purple?style=flat-square)](#)

Real-time monitoring, cost tracking, security scanning, and a beautiful dashboard for all your OpenClaw agent activity. **Zero config** — install and it just works.

---

## ⚡ Install

```bash
openclaw hooks install openclaw-watch
```

That's it. Restart your gateway and visit **http://localhost:3001**.

---

## 🧩 Feature Matrix

| Feature | Monitor 👁️ | Security 🛡️ | Dashboard 📊 |
|---|:---:|:---:|:---:|
| Message tracking (in/out) | ✅ | | ✅ |
| Token usage estimation | ✅ | | ✅ |
| Response time tracking | ✅ | | ✅ |
| Session lifecycle | ✅ | | ✅ |
| Prompt injection detection | | ✅ | ✅ |
| Sensitive data scanning | | ✅ | ✅ |
| Anomaly detection | | ✅ | ✅ |
| Real-time alerts | | ✅ | |
| Live web dashboard | | | ✅ |
| REST API | | | ✅ |
| SSE real-time updates | | | ✅ |
| Cost breakdown | ✅ | | ✅ |

---

## 📊 Dashboard

> *Screenshot placeholder — run it locally and see!*

The dashboard runs at `http://localhost:3001` and features:

- **Overview cards** — Total messages, active sessions, estimated cost, security alerts
- **Live message feed** — Real-time in/out stream with timestamps
- **Security panel** — Alerts by severity (critical / warning / info)
- **Daily chart** — Message volume and cost trends over 14 days
- Dark theme, responsive, modern — looks great on any screen

### API Endpoints

| Endpoint | Description |
|---|---|
| `GET /api/stats` | Overall dashboard stats |
| `GET /api/messages?limit=50&offset=0` | Recent messages (paginated) |
| `GET /api/sessions` | Active session list |
| `GET /api/security` | Security alerts |
| `GET /api/cost` | Cost breakdown by day/session |
| `GET /api/stream` | SSE real-time updates |

---

## 🛡️ Security Detection

| Threat | Type | Severity |
|---|---|---|
| "Ignore previous instructions" | Prompt Injection | ⚠️ Warning |
| "You are now a..." / Role reassignment | Prompt Injection | ⚠️ Warning |
| System prompt override attempts | Prompt Injection | ⚠️ Warning |
| DAN mode / Jailbreak keywords | Prompt Injection | ⚠️ Warning |
| Base64-encoded injection payloads | Encoded Injection | 🚨 Critical |
| AWS Keys (`AKIA...`) | Sensitive Data | 🚨 Critical |
| GitHub Tokens (`ghp_...`) | Sensitive Data | 🚨 Critical |
| OpenAI / Anthropic Keys | Sensitive Data | 🚨 Critical |
| Private Keys (PEM) | Sensitive Data | 🚨 Critical |
| Credit Card Numbers | Sensitive Data | 🚨 Critical |
| SSN Patterns | Sensitive Data | ⚠️ Warning |
| JWT Tokens | Sensitive Data | ⚠️ Warning |
| Unusually long messages (>50K chars) | Anomaly | ⚠️ Warning |
| Rapid-fire requests (>10 in 5s) | Anomaly | ⚠️ Warning |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                  OpenClaw Gateway                │
│                                                  │
│  message:received ──┬──► Monitor Hook ──► Store  │
│  message:sent ──────┤                     │      │
│  command:new ───────┤                     │      │
│  command:reset ─────┘                     │      │
│                                           ▼      │
│  message:received ──┬──► Security Hook ──► Store │
│  message:sent ──────┤         │                  │
│  message:preprocessed┘        ▼                  │
│                          User Alerts             │
│                                                  │
│  gateway:startup ───► Dashboard Hook             │
│                          │                       │
│                          ▼                       │
│                    HTTP :3001                     │
│                    ├── UI (index.html)            │
│                    ├── REST API                   │
│                    └── SSE Stream                 │
└─────────────────────────────────────────────────┘
          │
          ▼
   ~/.openclaw/openclaw-watch/data.json
   (Pure JSON, zero native deps)
```

---

## ❓ FAQ

**Q: Does it slow down my agent?**
A: No. All hooks run async and never block the message pipeline. Storage is batched with 10s flush intervals.

**Q: What if port 3001 is taken?**
A: The dashboard gracefully logs a warning and disables itself. Monitor and Security hooks keep working independently.

**Q: Does it need a database?**
A: No. Pure JSON file storage. Zero native dependencies. Works on Windows, Mac, and Linux without node-gyp.

**Q: How much data does it keep?**
A: 7 days of rolling data. Auto-cleanup runs every 10 seconds.

**Q: Can I disable individual hooks?**
A: Yes! All three hooks are independent. Disable any via OpenClaw hook config.

**Q: How accurate are cost estimates?**
A: Rough estimates using word count × 1.3 as token approximation, at $0.01/1K tokens blended rate. Good for trends, not invoicing.

---

## 🧑‍💻 Development

```bash
git clone https://github.com/kazhou2024/openclaw-watch.git
cd openclaw-watch
npm install
npm run build
```

---

## 📝 License

MIT © [Kang Zhou (NeuZhou)](https://github.com/kazhou2024) — Principal Engineer at Microsoft
