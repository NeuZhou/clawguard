# ClawGuard Detection Benchmark

## Methodology

This benchmark suite tests ClawGuard's ability to detect real-world AI agent security vulnerabilities across 10 categories mapped to the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

### How It Works

1. **Samples**: 10 realistic code files, each containing one or more known vulnerability patterns
2. **Expected findings**: `expected.json` maps each sample to the ClawGuard rule IDs that should fire
3. **Runner**: `run.ts` scans each sample with `clawguard scan --format json` and compares results against expectations
4. **Metrics**: Reports file detection rate (% of files with any finding) and rule detection rate (% of expected rules matched)

### Vulnerability Categories

| Sample | Category | OWASP LLM Mapping |
|--------|----------|-------------------|
| `vulnerable-mcp-server.ts` | MCP Tool Poisoning | LLM09: Supply Chain |
| `leaky-agent.py` | PII Leakage | LLM06: Sensitive Info |
| `injection-prone.ts` | Prompt Injection | LLM01: Prompt Injection |
| `overprivileged-skill.ts` | Excessive Permissions | LLM08: Excessive Agency |
| `memory-poisoning.py` | Memory Poisoning | LLM01: Prompt Injection |
| `supply-chain-risk.json` | Supply Chain Attack | LLM09: Supply Chain |
| `a2a-unsafe.ts` | Unsafe A2A Delegation | LLM08: Excessive Agency |
| `data-exfil.ts` | Data Exfiltration | LLM06: Sensitive Info |
| `eval-abuse.py` | Code Execution | LLM02: Insecure Output |
| `config-override.ts` | Config Tampering | LLM08: Excessive Agency |

### Running

```bash
npm run build
npx tsx benchmarks/run.ts
```

### Pass Criteria

- **File detection rate** ≥ 80% (at least 8/10 files must trigger findings)
- Each file must match at least one expected rule and meet the minimum finding count

## Results

Run the benchmark to generate live results. Results are printed as a markdown table to stdout.
