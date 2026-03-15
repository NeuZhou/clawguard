# Custom Rules Directory

Drop your custom YAML security rules here.

## Format

```yaml
name: "My Company Security Policy"
version: "1.0"
rules:
  - id: my-rule-id
    description: "What this rule detects"
    event: message:received
    severity: critical  # critical | high | warning | info
    patterns:
      - regex: "pattern-to-match"
      - keyword: "keyword-to-find"
    action: alert  # alert | log | block
```

## Example

```yaml
name: "ACME Corp Rules"
version: "1.0"
rules:
  - id: acme-no-secrets
    description: "Block internal API endpoints"
    event: message:received
    severity: critical
    patterns:
      - regex: "internal-api\\.acme\\.com"
      - keyword: "ACME-SECRET"
    action: alert
```

Rules are loaded automatically when the security hook starts.
