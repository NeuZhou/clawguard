# Community Security Rules

Community-contributed security rule packs for ClawGuard.

## Available Rule Packs

| Pack | Industry | Rules | Description |
|------|----------|-------|-------------|
| [healthcare-hipaa.yaml](healthcare-hipaa.yaml) | Healthcare | 4 | HIPAA compliance — PHI, MRN, medical terms |
| [finance-pci.yaml](finance-pci.yaml) | Finance | 3 | PCI-DSS — credit card handling, CVV exposure |
| [enterprise-dlp.yaml](enterprise-dlp.yaml) | Enterprise | 4 | Data Loss Prevention — classification labels, internal URLs |

## Usage

Copy any YAML file to your rules directory:

```bash
cp community-rules/healthcare-hipaa.yaml ~/.openclaw/clawguard/rules.d/
```

Rules are loaded automatically on next gateway restart.

## Contributing

1. Create a YAML file following the [rule schema](../CONTRIBUTING.md)
2. Test locally
3. Submit a PR to this directory
