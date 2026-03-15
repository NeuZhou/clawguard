---
name: openclaw-watch-guard
description: "🛡️ Real-time security guard — scans every message for prompt injection, data leakage, and threats"
metadata: {"openclaw": {"emoji": "🛡️", "events": ["message:received", "message:sent"], "requires": {"config": ["hooks.internal.enabled"]}}}
---

# OpenClaw Watch Guard

Real-time security monitoring hook. Scans every inbound and outbound message for:
- Prompt injection attempts (93 patterns)
- Data leakage (API keys, credentials, PII)  
- Insider threat behaviors
- Identity file tampering

## How It Works

1. Hooks into `message:received` and `message:sent` events
2. Runs all 285+ security patterns against message content
3. Logs findings to `~/.openclaw/openclaw-watch/findings.jsonl`
4. For critical/high findings, pushes a warning message to the user

## Configuration

No configuration needed. Install and enable:

```bash
openclaw hooks install ./path/to/openclaw-watch
openclaw hooks enable openclaw-watch-guard
```
