// clawguard-rules-example — Example ClawGuard Plugin
// Copy this template and modify to create your own security rules!

import type { SecurityRule } from '@neuzhou/clawguard';
import { noTodoSecretsRule } from './rules/no-todo-secrets';
import { sqlInjectionRule } from './rules/sql-injection';
import { excessivePermissionRule } from './rules/excessive-permission';

// Define and export the plugin
const plugin = {
  name: 'clawguard-rules-example',
  version: '0.1.0',
  rules: [noTodoSecretsRule, sqlInjectionRule, excessivePermissionRule] as SecurityRule[],
  meta: {
    author: 'ClawGuard Community',
    description: 'Example rules plugin — demonstrates how to create custom security rules',
    homepage: 'https://github.com/NeuZhou/clawguard/tree/main/examples/plugin-template',
  },
};

export default plugin;
export { plugin };
