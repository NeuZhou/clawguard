// OpenClaw Watch — Security Rule: Identity Protection
// OWASP Agentic AI: Identity Hijacking / Memory Poisoning

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

const IDENTITY_FILES = ['SOUL.md', 'IDENTITY.md', 'AGENTS.md', 'MEMORY.md', 'USER.md'];

const IDENTITY_FILE_PATTERNS: Pattern[] = [
  { regex: /(?:write|edit|modify|overwrite|replace|delete|remove|truncate)\s+(?:to\s+)?(?:the\s+)?(?:SOUL|IDENTITY|AGENTS)\.md/i, severity: 'critical', description: 'Attempt to modify agent identity file' },
  { regex: /(?:write|edit|modify|overwrite|replace)\s+(?:to\s+)?(?:the\s+)?MEMORY\.md/i, severity: 'high', description: 'Attempt to modify agent memory file' },
  { regex: /(?:write|edit|modify|overwrite|replace)\s+(?:to\s+)?(?:the\s+)?USER\.md/i, severity: 'high', description: 'Attempt to modify user profile file' },
  { regex: /echo\s+.*>\s*(?:SOUL|IDENTITY|AGENTS|MEMORY|USER)\.md/i, severity: 'critical', description: 'Shell redirect to identity file' },
  { regex: /cat\s*>\s*(?:SOUL|IDENTITY|AGENTS|MEMORY|USER)\.md/i, severity: 'critical', description: 'Shell write to identity file' },
];

const PERSONA_SWAP_PATTERNS: Pattern[] = [
  { regex: /you\s+are\s+no\s+longer\s+/i, severity: 'high', description: 'Persona rejection attempt' },
  { regex: /forget\s+(your|the)\s+(identity|persona|character|name|role)/i, severity: 'high', description: 'Identity erasure attempt' },
  { regex: /your\s+new\s+(name|identity|persona|character|role)\s+(is|will\s+be)/i, severity: 'high', description: 'Identity reassignment attempt' },
  { regex: /(?:change|update|replace)\s+your\s+(?:name|identity|persona)\s+to/i, severity: 'high', description: 'Identity change request' },
  { regex: /stop\s+(?:being|pretending\s+to\s+be|acting\s+as)/i, severity: 'high', description: 'Identity cessation attempt' },
  { regex: /you\s+(?:were|used\s+to\s+be)\s+(?:called|named|known\s+as)/i, severity: 'warning', description: 'False identity history' },
  { regex: /your\s+(?:real|true|actual|original)\s+(?:name|identity|purpose)\s+is/i, severity: 'high', description: 'False identity claim' },
  { regex: /(?:rewrite|overhaul|reset)\s+your\s+(?:personality|soul|core\s+values?)/i, severity: 'critical', description: 'Core personality override attempt' },
];

const MEMORY_POISONING_PATTERNS: Pattern[] = [
  { regex: /(?:add|inject|insert|write)\s+(?:to|into)\s+(?:your\s+)?(?:long[- ]term\s+)?memory/i, severity: 'high', description: 'Memory injection attempt' },
  { regex: /(?:remember|memorize|store)\s+(?:that|this)\s*:\s*.{0,20}(?:always|never|must|should)/i, severity: 'warning', description: 'Persistent instruction via memory' },
  { regex: /update\s+(?:your\s+)?(?:memory|notes?)\s+(?:to\s+)?(?:say|include|reflect)/i, severity: 'warning', description: 'Memory manipulation request' },
  { regex: /(?:in\s+)?your\s+(?:previous|last)\s+(?:memory|notes?)\s+you\s+(?:wrote|said|noted)/i, severity: 'warning', description: 'False memory reference' },
  { regex: /(?:save|persist|record)\s+(?:this|these)\s+(?:as\s+)?(?:permanent|persistent|long[- ]term)/i, severity: 'warning', description: 'Persistent data injection attempt' },
];

const ALL_PATTERNS = [
  ...IDENTITY_FILE_PATTERNS,
  ...PERSONA_SWAP_PATTERNS,
  ...MEMORY_POISONING_PATTERNS,
];

export const identityProtectionRule: SecurityRule = {
  id: 'identity-protection',
  name: 'Identity Protection',
  description: 'Detects identity hijacking, persona swap attempts, and memory poisoning attacks on agent identity files',
  owaspCategory: 'Agentic AI: Identity Hijacking',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    if (direction !== 'inbound') return [];
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'identity-protection',
          ruleName: 'Identity Protection',
          severity: pattern.severity,
          category: 'identity-protection',
          owaspCategory: 'Agentic AI: Identity Hijacking',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    // Check for identity file names mentioned in suspicious context
    for (const file of IDENTITY_FILES) {
      if (content.includes(file)) {
        const surrounding = content.slice(
          Math.max(0, content.indexOf(file) - 50),
          content.indexOf(file) + file.length + 50
        );
        if (/(?:delete|rm|remove|truncate|wipe|destroy|corrupt)/i.test(surrounding)) {
          findings.push({
            id: crypto.randomUUID(),
            timestamp: context.timestamp,
            ruleId: 'identity-protection',
            ruleName: 'Identity Protection',
            severity: 'critical',
            category: 'identity-protection',
            owaspCategory: 'Agentic AI: Identity Hijacking',
            description: `Destructive operation targeting ${file}`,
            evidence: surrounding.slice(0, 200),
            session: context.session,
            channel: context.channel,
            action: 'alert',
          });
        }
      }
    }

    return findings;
  },
};
