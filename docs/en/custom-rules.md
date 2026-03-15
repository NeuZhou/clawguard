# Custom Rules Guide

## Overview

Custom rules are YAML files placed in `~/.openclaw/openclaw-watch/rules.d/`. They're loaded automatically when the gateway starts.

## Schema

```yaml
name: "Rule Pack Name"
version: "1.0"
rules:
  - id: unique-rule-id
    description: "What this rule detects"
    event: message:received    # or message:sent
    severity: critical         # critical | high | warning | info
    patterns:
      - regex: "pattern"       # Regular expression (case-insensitive)
      - keyword: "word"        # Simple keyword match (case-insensitive)
    action: alert              # alert | log | block
```

## Examples

### Block competitor mentions

```yaml
name: "Competitor Policy"
version: "1.0"
rules:
  - id: no-competitor-api
    description: "Block competitor API references"
    event: message:sent
    severity: high
    patterns:
      - regex: "competitor-api\\.rival\\.com"
    action: alert
```

### Detect internal project names

```yaml
name: "Internal Projects"
version: "1.0"
rules:
  - id: project-codename
    description: "Internal codename leak"
    event: message:sent
    severity: high
    patterns:
      - keyword: "PROJECT PHOENIX"
      - keyword: "PROJECT TITAN"
    action: alert
```

## Pattern Matching

- **regex**: Standard JavaScript regex, always case-insensitive
- **keyword**: Simple substring match, case-insensitive
- Multiple patterns in a rule are OR-matched (any pattern triggers)

## Community Rules

See [`community-rules/`](../../community-rules/) for industry-specific rule packs (HIPAA, PCI-DSS, DLP).
