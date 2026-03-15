---
name: openclaw-watch-policy
description: "🔒 Tool call policy enforcement — blocks dangerous exec/file/browser operations"
metadata: {"openclaw": {"emoji": "🔒", "events": ["message:sent"], "requires": {"config": ["hooks.internal.enabled"]}}}
---

# OpenClaw Watch Policy

Evaluates outbound tool calls against security policies. Blocks or warns on:
- Dangerous exec commands (rm -rf, reverse shells, etc.)
- File access to sensitive paths (.env, .ssh, private keys)
- Browser access to blocked domains

## Configuration

Create `~/.openclaw/openclaw-watch/policies.yaml`:
```yaml
exec:
  dangerous_commands:
    - rm -rf
    - mkfs
    - dd if=
    - curl.*|.*bash
file:
  deny_read:
    - "**/.env*"
    - "**/.ssh/*"
  deny_write:
    - "**/SOUL.md"
    - "**/IDENTITY.md"
browser:
  block_domains:
    - evil.com
```
