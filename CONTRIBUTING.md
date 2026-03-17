# Contributing to ClawGuard 🛡️

First off — thank you! Every contribution makes AI agents safer.

## Quick Start

```bash
git clone https://github.com/NeuZhou/clawguard.git
cd clawguard
npm install
npm test        # Run the test suite
npm run check   # TypeScript type check
```

## What We Need Most

| Area | Difficulty | Impact |
|------|-----------|--------|
| **New detection patterns** | 🟢 Easy | 🔥 High |
| **False positive fixes** | 🟢 Easy | 🔥 High |
| **MCP server scanning rules** | 🟡 Medium | 🔥 High |
| **Documentation improvements** | 🟢 Easy | 🟡 Medium |
| **Plugin ecosystem** | 🟡 Medium | 🟡 Medium |
| **New scanner engines** | 🔴 Hard | 🔥 High |

## Adding a Security Pattern (Easiest Contribution)

1. Find the right rule file in `src/rules/`
2. Add your pattern:
   ```typescript
   { regex: /your-pattern/i, severity: 'high', confidence: 85, description: 'What it detects' }
   ```
3. Add a test in `tests/`
4. Run `npm test`
5. Submit a PR!

## Development Workflow

```bash
git checkout -b feat/my-feature   # Create branch
# Make changes...
npm test                           # Tests pass?
npm run check                      # Types check?
git commit -m "feat: add X"       # Commit (conventional commits)
git push origin feat/my-feature   # Push & open PR
```

### Commit Convention

- `feat:` — New feature or pattern
- `fix:` — Bug fix or false positive fix
- `test:` — Test additions
- `docs:` — Documentation
- `refactor:` — Code restructuring

## Ground Rules

- **Zero runtime dependencies** — This is a core principle. Don't add `npm install` anything.
- **Every pattern needs a test** — No exceptions.
- **TypeScript strict mode** — Fix all type errors.
- **Don't break existing patterns** — Run the full test suite.

## Security Vulnerabilities

Found a security issue in ClawGuard itself? **Do not open a public issue.** Email [neuzhou@outlook.com](mailto:neuzhou@outlook.com) directly.

## CLA

Contributors must agree to our [CLA](CLA.md) to enable dual licensing (AGPL-3.0 + Commercial).

## Questions?

Open a [Discussion](https://github.com/NeuZhou/clawguard/discussions) or file an issue. We're friendly! 🦀
