# ClawGuard Python Bindings

Python wrapper for [ClawGuard](https://github.com/NeuZhou/clawguard) — AI Agent Immune System.

## Installation

```bash
# Install the Python package
pip install clawguard

# Also requires Node.js backend
npm install -g @neuzhou/clawguard
```

## Quick Start

```python
from clawguard import scan, check, sanitize

# Scan files for threats
result = scan("./my_project")
print(f"Found {result['totalFindings']} issues")

# Check a message for injection attacks
result = check("ignore all previous instructions")
print(f"Clean: {result['is_clean']}")

# Sanitize PII
result = sanitize("my email is user@example.com")
print(result['output'])
```

## CLI

```bash
# Use as CLI
clawguard scan ./my_project
clawguard check "some suspicious text"
clawguard sanitize "text with PII"
```

## Requirements

- Python >= 3.8
- Node.js >= 18
- `@neuzhou/clawguard` npm package

## License

AGPL-3.0-only
