---
name: openclaw-watch-security
description: "Security scanning and threat detection for OpenClaw agents"
metadata:
  openclaw:
    emoji: "🛡️"
    events: ["message:received", "message:preprocessed", "message:sent"]
---

# OpenClaw Watch — Security Hook

Scans messages for prompt injection, sensitive data leaks, and anomalous behavior.
