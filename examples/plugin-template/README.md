# clawguard-rules-example

Example ClawGuard plugin — use this as a template to create your own security rules in 5 minutes!

## Quick Start

### 1. Copy this template

```bash
clawguard init-plugin my-rules
# or manually:
cp -r examples/plugin-template clawguard-rules-my-rules
cd clawguard-rules-my-rules
npm install
```

### 2. Add your rules

Create a new file in `rules/`:

```ts
import type { SecurityRule, SecurityFinding, Direction, RuleContext } from '@neuzhou/clawguard';
import * as crypto from 'crypto';

export const myRule: SecurityRule = {
  id: 'my-plugin/my-rule',
  name: 'My Custom Rule',
  description: 'Detects something dangerous',
  owaspCategory: 'LLM01: Prompt Injection',
  enabled: true,
  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    // Your detection logic here
    return [];
  },
};
```

### 3. Register in index.ts

```ts
import { myRule } from './rules/my-rule';

const plugin = {
  name: 'clawguard-rules-my-rules',
  version: '0.1.0',
  rules: [myRule],
};

export default plugin;
```

### 4. Use it

```bash
# Via CLI
clawguard scan ./project --plugins ./path/to/my-rules

# Via config (.clawguardrc.json)
{
  "plugins": ["clawguard-rules-my-rules"]
}
```

## Included Example Rules

| Rule ID | Description | Severity |
|---------|-------------|----------|
| `example/no-todo-secrets` | Detects secrets in TODO comments | high |
| `example/sql-injection` | SQL injection pattern detection | critical |
| `example/excessive-permission` | Overly broad permission requests | high |

## Publishing

```bash
npm publish
```

Name your package `clawguard-rules-*` for auto-discovery.

## License

MIT
