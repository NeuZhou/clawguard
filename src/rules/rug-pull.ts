// ClawGuard — Security Rule: Rug Pull Detection
// Detects bait-and-switch attacks where trust is exploited to bypass controls

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

// Trust exploitation / bait-and-switch
const TRUST_EXPLOITATION: Pattern[] = [
  { regex: /now\s+that\s+you\s+trust\s+me/i, severity: 'critical', description: 'Trust exploitation: leveraging established trust' },
  { regex: /since\s+(?:we['']ve|we\s+have)\s+been\s+working\s+together.*(?:skip|bypass|disable|ignore)/i, severity: 'critical', description: 'Trust exploitation: using rapport to bypass controls' },
  { regex: /you\s+(?:already|previously)\s+(?:agreed|approved|allowed|gave|granted)/i, severity: 'high', description: 'False prior agreement claim' },
  { regex: /(?:I|we)\s+(?:already|previously)\s+(?:verified|confirmed|established)\s+(?:that|this)/i, severity: 'warning', description: 'Claiming pre-verification to skip checks' },
];

// Urgency/pressure manipulation
const URGENCY_PATTERNS: Pattern[] = [
  { regex: /(?:URGENT|EMERGENCY|CRITICAL)\s*[:\-!]\s*(?:skip|bypass|disable|ignore)\s+(?:all\s+)?(?:safety|security|checks?|verification)/i, severity: 'critical', description: 'Fake emergency to bypass security controls' },
  { regex: /(?:there['']?s?\s+)?no\s+time\s+to\s+(?:verify|check|validate|review)/i, severity: 'high', description: 'Time pressure to skip verification' },
  { regex: /(?:do\s+it\s+)?(?:right\s+)?now\s+(?:before|or)\s+(?:it['']?s?\s+)?too\s+late/i, severity: 'high', description: 'Artificial deadline pressure' },
  { regex: /production\s+is\s+(?:down|broken|failing).*(?:skip|bypass|quick|fast|immediately)/i, severity: 'high', description: 'Production emergency used to bypass controls' },
];

// Just-this-once / exception requests
const EXCEPTION_PATTERNS: Pattern[] = [
  { regex: /just\s+(?:this\s+)?once.*(?:disable|skip|bypass|ignore|turn\s+off)/i, severity: 'high', description: '"Just this once" exception request to bypass security' },
  { regex: /(?:temporary|temporarily)\s+(?:disable|remove|turn\s+off|bypass)\s+(?:the\s+)?(?:security|safety|checks?|restrictions?)/i, severity: 'high', description: 'Temporary security disable request' },
  { regex: /(?:make\s+an?\s+)?exception\s+(?:for\s+)?(?:this\s+)?(?:time|case|request)/i, severity: 'warning', description: 'Exception request for security bypass' },
];

// Scope creep
const SCOPE_CREEP: Pattern[] = [
  { regex: /while\s+you(?:['']re|\s+are)\s+at\s+it.*(?:also|additionally|too)\s+(?:send|share|give|forward|export)/i, severity: 'high', description: 'Scope creep: piggybacking sensitive request' },
  { regex: /(?:one\s+more|also|additionally)\s+(?:just\s+)?(?:add|give|grant|include)\s+(?:\w+\s+)?(?:access|permission|read|write)\s+(?:to|for)/i, severity: 'warning', description: 'Permission ratchet: incremental access expansion' },
];

const ALL_PATTERNS = [
  ...TRUST_EXPLOITATION,
  ...URGENCY_PATTERNS,
  ...EXCEPTION_PATTERNS,
  ...SCOPE_CREEP,
];

export const rugPullRule: SecurityRule = {
  id: 'rug-pull',
  name: 'Rug Pull Detection',
  description: 'Detects bait-and-switch attacks: trust exploitation, urgency manipulation, exception requests, and scope creep',
  owaspCategory: 'Agentic AI: Rug Pull',
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
          ruleId: 'rug-pull',
          ruleName: 'Rug Pull Detection',
          severity: pattern.severity,
          category: 'rug-pull',
          owaspCategory: 'Agentic AI: Rug Pull',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    return findings;
  },
};
