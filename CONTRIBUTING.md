# Contributing to OpenClaw Watch

Thank you for helping make AI agents safer! 🛡️

## 🌍 Community Security Rules

The easiest way to contribute is by sharing security rules!

### How to Create a Custom Rule

1. Create a YAML file in `rules.d/`:

```yaml
name: "My Company Rules"
version: "1.0"
rules:
  - id: my-rule-001
    description: "Detect sensitive project names in output"
    event: message:sent
    severity: high
    patterns:
      - regex: "PROJECT_CODENAME_\\w+"
      - keyword: "CONFIDENTIAL"
    action: alert
```

2. Test it locally by placing in `~/.openclaw/openclaw-watch/rules.d/`
3. Submit a PR to `community-rules/`

### Rule Severity Guide

| Severity | Meaning | Example |
|----------|---------|---------|
| **critical** | Immediate threat, agent should be paused | API key in outbound message |
| **high** | Significant risk, requires attention | Recursive delete command |
| **warning** | Potential issue, monitor | Unusual cost spike |
| **info** | Informational, for audit trail | Tool call logged |

### YAML Rule Schema

```yaml
name: string          # Rule pack name
version: string       # Semantic version
rules:
  - id: string        # Unique rule ID (e.g., "my-org-001")
    description: string
    event: string      # "message:received" | "message:sent"
    severity: string   # "critical" | "high" | "warning" | "info"
    patterns:
      - regex: string  # Regular expression (case-insensitive)
      - keyword: string # Simple keyword match
    action: string     # "alert" | "log" | "block"
```

## 💻 Code Contributions

### Setup

```bash
git clone https://github.com/NeuZhou/openclaw-watch.git
cd openclaw-watch
npm install
```

### Development

```bash
npm run lint      # Type-check without emitting
npm test          # Run test suite
npm run build     # Compile TypeScript
```

### Adding a New Security Rule

1. Create `src/rules/your-rule.ts` implementing `SecurityRule` interface
2. Export from `src/rules/index.ts`
3. Add to `builtinRules` array
4. Add tests in `tests/rules/your-rule.test.ts`
5. Update documentation in `docs/`

### Code Style

- TypeScript strict mode
- Zero native dependencies
- Use `node:crypto` for UUIDs and hashing
- Follow existing patterns in `src/rules/`

### Pull Request Checklist

- [ ] `npx tsc --noEmit` passes
- [ ] `npm test` passes
- [ ] New rules have test coverage (true positives AND true negatives)
- [ ] Documentation updated if applicable
- [ ] No native dependencies added

## 🐛 Bug Reports

Include:
- OpenClaw Watch version
- Node.js version
- OS
- Steps to reproduce
- Expected vs actual behavior

## 📜 License

By contributing, you agree your contributions are licensed under MIT.
