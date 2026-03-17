// Rule: Detect secrets/passwords in TODO comments or code comments
import type { SecurityRule, SecurityFinding, Direction, RuleContext } from '@neuzhou/clawguard';
import * as crypto from 'crypto';

const SECRET_IN_COMMENT = /(?:\/\/|#|\/\*)\s*(?:TODO|FIXME|HACK|NOTE).*(?:password|secret|api[_-]?key|token)\s*[:=]\s*\S+/gi;

export const noTodoSecretsRule: SecurityRule = {
  id: 'example/no-todo-secrets',
  name: 'No Secrets in TODO Comments',
  description: 'Detects hardcoded secrets in TODO/FIXME comments',
  owaspCategory: 'LLM06: Sensitive Information Disclosure',
  enabled: true,
  check(content: string, _direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const matches = content.match(SECRET_IN_COMMENT);
    if (matches) {
      for (const match of matches) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'example/no-todo-secrets',
          ruleName: 'No Secrets in TODO Comments',
          severity: 'high',
          category: 'secrets',
          owaspCategory: 'LLM06: Sensitive Information Disclosure',
          description: 'Found potential secret in TODO comment',
          evidence: match.slice(0, 100),
          session: context.session,
          channel: context.channel,
          action: 'alert',
        });
      }
    }
    return findings;
  },
};
