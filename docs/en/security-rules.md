# Security Rules Reference

## Built-in Rules

### 1. Prompt Injection Detection (`prompt-injection`)

**OWASP:** LLM01 — Prompt Injection

Scans **inbound** messages for injection attempts.

| Category | Patterns | Severity |
|----------|----------|----------|
| Direct injection | "ignore previous instructions", role reassignment, jailbreak | critical |
| Delimiter injection | Markdown/chat template delimiters (`<\|system\|>`, `[INST]`) | critical/high |
| Encoded | Base64 payloads, zero-width chars, homoglyphs | high |
| Indirect | Hidden instructions, HTML comments, AI-targeted conditionals | high/warning |
| Multi-turn | False context/memory references | warning |

### 2. Data Leakage Detection (`data-leakage`)

**OWASP:** LLM06 — Sensitive Information Disclosure

Scans **outbound** messages for secrets.

| Type | Examples | Severity |
|------|----------|----------|
| API Keys | OpenAI (`sk-`), Anthropic (`sk-ant-`), GitHub (`ghp_`), AWS (`AKIA`), Stripe | critical |
| Credentials | Bearer tokens, Basic auth, private keys, JWTs, passwords in URLs | critical/high |
| PII | SSN, credit cards (Luhn-validated) | critical |
| Env files | Bulk `KEY=value` patterns | high |

Includes **rotation URLs** for detected keys (OpenAI, GitHub, AWS, Anthropic, Stripe, etc.)

### 3. Anomaly Detection (`anomaly-detection`)

**OWASP:** LLM02 / Operational

| Anomaly | Threshold | Severity |
|---------|-----------|----------|
| Rapid-fire | >10 msgs/60s | warning |
| Token bomb | >50K tokens/msg | high |
| Loop detection | >5 repeated msgs/2min | high |
| Session marathon | >4 hours | info |
| Cost spike | >$5/session | warning |
| Sub-agent cascade | >5 spawns/5min | high |
| Infinite retry | Same error >3x/2min | high |
| Recursive spawn | Depth > 3 | critical |
| Disk space bomb | >100MB/5min | high |
| Network flood | >50 HTTP reqs/1min | high |

### 4. Compliance & Audit (`compliance`)

**OWASP:** LLM09 — Overreliance

Tracks filesystem modifications, privilege escalation, external access, and tool calls.

### 5. File Deletion Protection (`file-protection`)

**OWASP:** LLM02 — Insecure Output Handling

Detects destructive filesystem commands:

| Command | Platform | Severity |
|---------|----------|----------|
| `rm -rf` | Unix | high→critical |
| `del /f /s` | Windows | high |
| `Remove-Item -Recurse -Force` | PowerShell | high |
| `rimraf` | Node.js | high |
| `shutil.rmtree` | Python | high |
| `dd if=... of=/dev/` | Unix | critical |
| `format C:` | Windows | critical |

Severity escalates to **critical** when targeting `~`, `/`, `.ssh`, `.env`, `.git`.
