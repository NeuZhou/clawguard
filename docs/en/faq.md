# FAQ

## General

**Q: Does it slow down my agent?**
No. Security scans run in microseconds. Storage is async append-only JSONL.

**Q: Does it need a database?**
No. Pure file storage (JSONL + JSON). Auto-rotates with gzip compression.

**Q: Does it work on Windows?**
Yes. Zero native dependencies — pure Node.js.

**Q: Can I disable specific rules?**
Yes. Via dashboard Settings tab or config:
```json
{ "security": { "enabledRules": ["prompt-injection", "data-leakage"] } }
```

## Security

**Q: What OWASP categories are covered?**
LLM01 (Prompt Injection), LLM02 (Insecure Output), LLM06 (Data Leakage), LLM09 (Overreliance).

**Q: Can it block messages?**
Rules can set `action: "block"` but enforcement depends on gateway integration. Currently alerts are the primary mechanism.

**Q: What happens when a key is detected?**
An alert is generated with the key type, redacted evidence, and a rotation URL for the provider.

## Cost

**Q: How accurate is token estimation?**
Uses `ceil(text.length / 4)` — roughly accurate for English text. Actual tokenizer would be more precise but adds dependencies.

**Q: Are GitHub Copilot models tracked?**
Yes, at $0 cost (subscription-included).

## Export

**Q: Can I export to Splunk/ELK?**
Yes. Enable the syslog exporter (RFC 5424) or webhook exporter for any HTTP endpoint.

**Q: What formats are available?**
JSON and CSV via `/api/export/json` and `/api/export/csv`.
