// Rule: Detect excessive permission requests
import type { SecurityRule, SecurityFinding, Direction, RuleContext } from '@neuzhou/clawguard';
import * as crypto from 'crypto';

const EXCESSIVE_PATTERNS = [
  /chmod\s+777/gi,
  /chmod\s+[-+]?a\+[rwx]/gi,
  /grant\s+all\s+privileges/gi,
  /--privileged/gi,
  /run\s+as\s+(?:root|admin|administrator)/gi,
];

export const excessivePermissionRule: SecurityRule = {
  id: 'example/excessive-permission',
  name: 'Excessive Permission Request',
  description: 'Detects overly broad permission escalation attempts',
  owaspCategory: 'LLM08: Excessive Agency',
  enabled: true,
  check(content: string, _direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    for (const pattern of EXCESSIVE_PATTERNS) {
      pattern.lastIndex = 0;
      const match = pattern.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'example/excessive-permission',
          ruleName: 'Excessive Permission Request',
          severity: 'high',
          category: 'permission',
          owaspCategory: 'LLM08: Excessive Agency',
          description: `Excessive permission pattern: ${match[0]}`,
          evidence: match[0],
          session: context.session,
          channel: context.channel,
          action: 'alert',
        });
      }
    }
    return findings;
  },
};
