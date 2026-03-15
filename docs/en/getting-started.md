# Getting Started

## Installation

```bash
openclaw hooks install clawguard
openclaw gateway restart
```

Dashboard available at **http://localhost:19790**

## Requirements

- Node.js ≥ 18
- OpenClaw Gateway running

## Configuration

Config is auto-created at `~/.openclaw/clawguard/config.json` on first run.

### Budget Limits

```json
{
  "budget": {
    "dailyUsd": 50,
    "weeklyUsd": 200,
    "monthlyUsd": 500
  }
}
```

### Security Rules

All rules are enabled by default. Disable specific rules:

```json
{
  "security": {
    "enabledRules": ["prompt-injection", "data-leakage", "anomaly-detection"]
  }
}
```

### Custom Rules

Drop YAML files in `~/.openclaw/clawguard/rules.d/` — they're loaded automatically.

## Verify Installation

```bash
# Check dashboard is running
curl http://localhost:19790/api/overview

# Check security score
curl http://localhost:19790/api/security/score
```

## Next Steps

- [Security Rules Reference](security-rules.md)
- [Custom Rules Guide](custom-rules.md)
- [Dashboard Guide](dashboard.md)
