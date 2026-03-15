# Architecture

## Hook Pipeline

ClawGuard registers 4 hooks into the OpenClaw Gateway:

```
Gateway Events
    │
    ├─► Collector Hook ──► Store (JSONL files)
    │   Captures all messages, estimates tokens/cost
    │
    ├─► Security Hook ──► Security Engine ──► Rule Pipeline
    │   Runs all enabled rules against message content
    │   Built-in rules + custom YAML rules
    │
    ├─► Guardian Hook ──► Alert Engine
    │   Budget monitoring, security escalation, health checks
    │
    └─► Dashboard Hook ──► HTTP Server (:19790)
        REST API + SSE streaming + SPA frontend
```

## Storage

All data is stored as JSONL files in `~/.openclaw/clawguard/`:

| File | Contents |
|------|----------|
| `messages.jsonl` | All intercepted messages |
| `security.jsonl` | Security findings |
| `audit.jsonl` | Hash-chained audit events |
| `sessions.json` | Active session state (in-memory + periodic flush) |
| `config.json` | User configuration |

Auto-rotation at configurable size limit (default 50MB) with gzip compression.

## Security Engine

```
Content + Direction + Context
    │
    ├─► prompt-injection (inbound only)
    ├─► data-leakage (outbound only)
    ├─► anomaly-detection (both)
    ├─► compliance (both)
    ├─► file-protection (both)
    └─► custom YAML rules
    │
    ▼
SecurityFinding[] ──► Store + Alert Engine
```

Each rule implements the `SecurityRule` interface:

```typescript
interface SecurityRule {
  id: string;
  name: string;
  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[];
}
```

## Integrity

SHA-256 hash chain on audit events. Each event's hash = `SHA256(prevHash + JSON(event))`. Verifiable via `/api/audit/verify`.

## Design Principles

- **Zero native dependencies** — runs everywhere Node.js runs
- **Non-blocking** — all processing is synchronous but fast (microseconds)
- **Self-contained** — no external databases, services, or APIs required
- **Privacy-first** — all data stays local
