# 🛡️ ClawGuard — Systematic Code Review Report

**Reviewer:** 螃蟹 🦀 (AI Code Reviewer)  
**Date:** 2026-03-18  
**Commit range:** 4fd08d1..5c1828b (9 fixes applied)  
**Version reviewed:** 1.0.3

---

## 📊 Health Score: **B+**

ClawGuard is a well-structured, zero-dependency TypeScript library with real security value. The rule patterns are comprehensive and genuinely useful. Code quality is mostly high, but there were several "last-mile" integration issues where modules existed but weren't properly wired together.

---

## ✅ Test Results

| Metric | Before | After |
|--------|--------|-------|
| Total tests | 503 | 515 |
| Passing | 503 | 515 |
| Failing | 0 | 0 |
| Test files | 41 | 41 |
| Source files | 34 | 34 |
| TypeScript strict | ✅ | ✅ |
| `as any` in src/ | 1 | 0 |
| Duration | ~69s | ~66s |

---

## 🏗️ Architecture Overview

```
src/
├── index.ts              — Barrel export (public API)
├── types.ts              — Full type definitions, DEFAULT_CONFIG
├── security-engine.ts    — Main scan pipeline, custom rule loading
├── risk-engine.ts        — Weighted scoring + attack chains
├── policy-engine.ts      — Tool call governance (allow/deny/warn)
├── sanitizer.ts          — PII/credential sanitization
├── intent-action.ts      — Intent vs action mismatch detection
├── alert-engine.ts       — Alert dispatch + budget monitoring
├── cost-engine.ts        — Token/cost estimation, model pricing
├── integrity.ts          — SHA-256 hash chain audit trail
├── store.ts              — JSONL file storage engine
├── yara-engine.ts        — Lightweight YARA rule parser
├── cli.ts                — CLI entry point
├── skill-scanner.ts      — File/directory scanner
├── rules/                — 14 security rule modules (285+ patterns)
│   ├── prompt-injection.ts    (93+ patterns, 14 categories)
│   ├── data-leakage.ts        (62+ patterns)
│   ├── insider-threat.ts      (39+ patterns) ← newly integrated as SecurityRule
│   ├── supply-chain.ts        (35+ patterns)
│   ├── mcp-security.ts        (20+ patterns)
│   ├── identity-protection.ts (19+ patterns)
│   ├── file-protection.ts     (16+ patterns)
│   ├── anomaly-detection.ts   (8+ checks)
│   ├── compliance.ts          (audit tracking)
│   ├── compliance-frameworks.ts (GDPR/CCPA/SOX)
│   ├── privilege-escalation.ts
│   ├── rug-pull.ts
│   ├── resource-abuse.ts
│   └── cross-agent-contamination.ts
└── exporters/
    ├── sarif.ts           — SARIF 2.1.0 output
    ├── jsonl.ts           — JSONL export
    ├── syslog.ts          — RFC 5424 + CEF
    └── webhook.ts         — HMAC-signed HTTP POST
```

---

## 🐛 Issues Found & Fixed (TDD)

### ✅ Fixed (9 commits)

| # | Severity | Issue | Fix |
|---|----------|-------|-----|
| 1 | **High** | CLI `VERSION = '1.0.0'` hardcoded, package.json at 1.0.3 | Read from package.json dynamically |
| 2 | **Medium** | CLI used `as any` cast for RuleContext | Proper `RuleContext` type construction |
| 3 | **High** | `alert-engine`, `cost-engine`, `integrity`, exporters NOT exported from `index.ts` | Added all to barrel export |
| 4 | **Medium** | SARIF `toSarif()` default version hardcoded `'2.0.0'` | Read from package.json |
| 5 | **Medium** | CLI `sanitize` and `intent-check` used `require()` instead of static imports | Replaced with `import` |
| 6 | **High** | `insiderThreatRule` not a proper `SecurityRule` — couldn't integrate with scan pipeline | Added SecurityRule wrapper |
| 7 | **High** | `insider-threat` not in `builtinRules` array or `DEFAULT_CONFIG.enabledRules` | Added to both |
| 8 | **Medium** | `package.json` path resolution would fail from `dist/` in production | Added `findPackageJson()` that walks up directory tree |
| 9 | **Low** | Added regression test for `containsPII` consistency across repeated calls | Added defensive test |

### ⚠️ Remaining Issues (not fixed)

| # | Severity | Issue | Recommendation |
|---|----------|-------|----------------|
| 1 | **Medium** | CLI `start` and `dashboard` commands are stubs — just print text | Either implement or remove and document as unimplemented |
| 2 | **Medium** | `store.getMessages()` reads ALL data then filters — O(n) for every query | Add index or use SQLite for large datasets |
| 3 | **Low** | `sendWebhook()` silently swallows all errors | Add optional error callback or logging |
| 4 | **Low** | Several exported modules (`store`, `alert-engine`) lack JSDoc on individual methods | Add comprehensive JSDoc |
| 5 | **Low** | `webhook.test.ts` sends real HTTP to httpbin.org — flaky in CI without network | Mock the HTTP request |
| 6 | **Info** | Model pricing in `cost-engine.ts` will go stale over time | Consider loading from external config or noting the pricing date |
| 7 | **Info** | `IDENTITY_FILES` list in identity-protection.ts is hardcoded | Could be made configurable |
| 8 | **Info** | `init` CLI command generates YAML config but the parser is a custom ad-hoc YAML parser | Consider documenting limitations or using JSON config |

---

## 🔍 Quality Audit Summary

### Strengths 💪

1. **Zero dependencies** — genuinely zero native deps, everything is stdlib Node.js
2. **TypeScript strict mode** — compiles cleanly with `strict: true`
3. **No `any` types in source** (after fix) — proper typing throughout
4. **Comprehensive pattern coverage** — 285+ real, well-researched security patterns
5. **OWASP alignment** — proper mapping to LLM Top 10 and Agentic AI Top 10
6. **Attack chain detection** — correlates findings into combo attacks with multipliers
7. **Multi-language injection detection** — 12 languages including CJK
8. **Real tests** — tests check actual logic, not just mocks. Good true-positive and true-negative coverage
9. **Clean architecture** — clear separation: rules → engine → exporters
10. **Insider threat patterns based on Anthropic research** — novel and well-thought-out

### Weaknesses 🔧

1. **Dashboard is vapor** — README shows architecture diagram with "Dashboard :19790" but it's not implemented
2. **CLI commands `start`/`dashboard` are stubs** — print messages but do nothing
3. **Store is file-based JSONL** — reads entire files on every query, won't scale
4. **Custom YAML parser** — fragile, doesn't handle all YAML features (intentional zero-dep choice, but should be documented)
5. **No test for CLI actual execution** — tests check source content, not CLI behavior

### Dead Code: None found ✅

All exported functions are either used internally, by tests, or by the public API. The `hooks/` directory contains OpenClaw-specific handlers that are used by the hook system.

### Fake/Stub Implementations

- `cli.ts` → `start` command: prints message only
- `cli.ts` → `dashboard` command: prints message only
- These are documented as "use OpenClaw hooks integration" — honest about being stubs

### Test Quality Assessment

| Category | Count | Quality |
|----------|-------|---------|
| Real unit tests | ~450 | **Excellent** — test actual pattern matching, scoring, sanitization |
| Integration tests | ~30 | **Good** — test module interaction, custom rules, scan pipeline |
| File existence tests | ~35 | **Acceptable** — verify project structure (Python bindings, GH action) |
| Trivial tests | ~0 | None found |

Tests would catch real regressions. The pattern-based tests verify both true positives and true negatives, which is critical for a security scanner.

---

## 📈 Recommendations

### High Priority

1. **Implement or clearly deprecate `start`/`dashboard` CLI commands** — they mislead users
2. **Consider adding `insiderThreatRule` to scan pipeline** (✅ Done)
3. **Export all public modules from index.ts** (✅ Done)

### Medium Priority

4. **Add integration test that actually runs CLI** — use `child_process.execSync` to test real CLI behavior
5. **Document custom YAML parser limitations** — users may expect full YAML support
6. **Add error reporting to webhook exporter** — at minimum log to stderr when WATCH_DEBUG is set

### Low Priority

7. **Consider SQLite for store** — current JSONL approach won't scale past ~10MB
8. **Add configurable model pricing** — allow users to override stale prices
9. **Version the SARIF tool section** with actual release notes URL

---

## 📝 What Was Changed

### Files Modified
- `src/cli.ts` — Dynamic version, static imports, proper RuleContext, findPackageJson
- `src/index.ts` — Export alert-engine, cost-engine, integrity, exporters, insiderThreatRule
- `src/types.ts` — Add 'insider-threat' to DEFAULT_CONFIG.enabledRules
- `src/rules/index.ts` — Add insiderThreatRule to builtinRules, export it
- `src/rules/insider-threat.ts` — Add SecurityRule wrapper
- `src/exporters/sarif.ts` — Dynamic version from package.json, findPackageJson
- `tests/cli.test.ts` — 3 new tests (version from pkg, no `as any`, no `require()`)
- `tests/index-exports.test.ts` — 4 new tests (alert, cost, integrity, exporter exports)
- `tests/sarif-improvements.test.ts` — 1 new test (default version matches pkg.json)
- `tests/security-engine.test.ts` — 1 new test (insider-threat via runSecurityScan)
- `tests/rules/insider-threat.test.ts` — 2 new tests (SecurityRule integration)
- `tests/sanitizer.test.ts` — 1 new test (containsPII consistency)

### Commits (9)
1. `3403aab` fix: read CLI version from package.json instead of hardcoding
2. `29fbc6a` fix: remove 'as any' cast in CLI, use proper RuleContext type
3. `7f33d61` fix: export alert-engine, cost-engine, integrity, and exporters from index.ts
4. `b2db6ca` test: add containsPII consistency regression test
5. `0d441d2` fix: SARIF exporter reads version from package.json instead of hardcoding
6. `363e102` fix: replace require() with static imports in CLI
7. `f6e5d57` feat: add insiderThreatRule as proper SecurityRule
8. `c1baf4e` fix: use findPackageJson() to locate package.json robustly
9. `5c1828b` fix: add insiderThreatRule to builtinRules and DEFAULT_CONFIG.enabledRules

---

*Generated by 螃蟹 🦀 — Systematic Code Review*
