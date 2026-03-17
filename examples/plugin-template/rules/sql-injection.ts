// Rule: Detect SQL injection patterns in agent tool calls
import type { SecurityRule, SecurityFinding, Direction, RuleContext } from '@neuzhou/clawguard';
import * as crypto from 'crypto';

const SQL_PATTERNS = [
  /(?:union\s+select|;\s*drop\s+table|;\s*delete\s+from|'\s*or\s+'1'\s*=\s*'1)/gi,
  /(?:exec\s*\(|execute\s+immediate|xp_cmdshell)/gi,
];

export const sqlInjectionRule: SecurityRule = {
  id: 'example/sql-injection',
  name: 'SQL Injection Detection',
  description: 'Detects SQL injection attempts in agent messages',
  owaspCategory: 'LLM01: Prompt Injection',
  enabled: true,
  check(content: string, _direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    for (const pattern of SQL_PATTERNS) {
      pattern.lastIndex = 0;
      const match = pattern.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'example/sql-injection',
          ruleName: 'SQL Injection Detection',
          severity: 'critical',
          category: 'injection',
          owaspCategory: 'LLM01: Prompt Injection',
          description: 'SQL injection pattern detected',
          evidence: match[0],
          session: context.session,
          channel: context.channel,
          action: 'block',
        });
        break;
      }
    }
    return findings;
  },
};
