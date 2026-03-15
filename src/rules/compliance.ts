// OpenClaw Watch — Security Rule: Compliance & Audit
// Tracks tool calls, filesystem modifications, privilege escalation

import { SecurityFinding, SecurityRule, Direction, RuleContext } from '../types';
import * as crypto from 'crypto';

const FILESYSTEM_PATTERNS = [
  // Require command-like context: preceded by line start, backtick, $, >, pipe, semicolon, or &&
  /(?:^|[`$>|;&]\s*)(?:rm|rmdir)\s+-[a-zA-Z]*\s/im,
  /(?:^|[`$>|;&]\s*)(?:del|erase)\s+\/[fFsSqQ]/im,
  /(?:^|[`$>|;&]\s*)(?:unlink|shred)\s+/im,
  /(?:os|fs|shutil)\.(?:remove|unlink|rmdir|rmtree)\s*\(/i,
  /(?:write|overwrite|truncate)\s+.*(?:\/|\\)/i,
  /(?:chmod|chown|icacls)\s+/i,
];

const PRIVILEGE_PATTERNS = [
  /(?:sudo|runas|gsudo|doas)\s+/i,
  /elevated.*exec/i,
  /admin.*privileges/i,
  /--elevated/i,
];

const EXTERNAL_ACCESS_PATTERNS = [
  /(?:https?:\/\/[^\s]+)/i,
  /(?:curl|wget|fetch|web_fetch)\s+/i,
  /(?:ssh|scp|rsync)\s+/i,
];

export const complianceRule: SecurityRule = {
  id: 'compliance',
  name: 'Compliance & Audit Tracking',
  description: 'Tracks tool calls, external data access, filesystem modifications, and privilege escalation',
  owaspCategory: 'LLM09: Overreliance / Operational',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const now = context.timestamp;

    // Track filesystem modifications
    for (const pattern of FILESYSTEM_PATTERNS) {
      const match = pattern.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(), timestamp: now,
          ruleId: 'compliance', ruleName: 'Compliance & Audit',
          severity: 'info', category: 'compliance', owaspCategory: 'LLM09',
          description: 'Filesystem modification detected',
          evidence: match[0].slice(0, 200),
          session: context.session, channel: context.channel, action: 'log',
        });
      }
    }

    // Track privilege escalation
    for (const pattern of PRIVILEGE_PATTERNS) {
      const match = pattern.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(), timestamp: now,
          ruleId: 'compliance', ruleName: 'Compliance & Audit',
          severity: 'warning', category: 'compliance', owaspCategory: 'LLM09',
          description: 'Privilege escalation detected',
          evidence: match[0].slice(0, 200),
          session: context.session, channel: context.channel, action: 'alert',
        });
      }
    }

    // Track external access (outbound only to avoid noise from inbound URLs)
    if (direction === 'outbound') {
      for (const pattern of EXTERNAL_ACCESS_PATTERNS) {
        const match = pattern.exec(content);
        if (match) {
          findings.push({
            id: crypto.randomUUID(), timestamp: now,
            ruleId: 'compliance', ruleName: 'Compliance & Audit',
            severity: 'info', category: 'compliance', owaspCategory: 'LLM09',
            description: 'External data access detected',
            evidence: match[0].slice(0, 200),
            session: context.session, channel: context.channel, action: 'log',
          });
        }
      }
    }

    // Tool call tracking
    const toolPatterns = [
      /exec\s*\(/i, /browser\s*\(/i, /web_fetch\s*\(/i,
      /antml:invoke\s+name="([^"]+)"/i,
    ];
    for (const pattern of toolPatterns) {
      const match = pattern.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(), timestamp: now,
          ruleId: 'compliance', ruleName: 'Compliance & Audit',
          severity: 'info', category: 'compliance', owaspCategory: 'LLM09',
          description: `Tool call detected: ${match[1] || match[0].slice(0, 50)}`,
          session: context.session, channel: context.channel, action: 'log',
        });
      }
    }

    return findings;
  },
};
