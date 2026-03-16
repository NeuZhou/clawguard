// ClawGuard — Security Rule: Memory Poisoning
// Detects suspicious patterns in MEMORY.md and agent memory files

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

// Encoded payloads hidden in memory files
const ENCODED_PAYLOAD_PATTERNS: Pattern[] = [
  { regex: /(?:base64|b64)[:=]\s*[A-Za-z0-9+/=]{40,}/i, severity: 'high', description: 'Memory poisoning: base64-encoded payload in memory file' },
  { regex: /data:(?:text|application)\/[^;]+;base64,[A-Za-z0-9+/=]{40,}/i, severity: 'high', description: 'Memory poisoning: data URI with embedded payload' },
  { regex: /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){10,}/i, severity: 'high', description: 'Memory poisoning: hex-encoded byte sequence' },
  { regex: /\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){10,}/i, severity: 'high', description: 'Memory poisoning: unicode escape sequence payload' },
  { regex: /&#x?[0-9a-f]+;(?:&#x?[0-9a-f]+;){10,}/i, severity: 'high', description: 'Memory poisoning: HTML entity encoded payload' },
];

// Hidden instructions embedded in memory
const HIDDEN_INSTRUCTION_PATTERNS: Pattern[] = [
  { regex: /<!--.*?(?:ignore|override|disregard|forget)\s+(?:previous|all|prior|above)\s+(?:instructions|rules|constraints).*?-->/is, severity: 'critical', description: 'Memory poisoning: hidden instruction in HTML comment' },
  { regex: /<!--.*?(?:system\s*prompt|you\s+are\s+now|new\s+instructions|act\s+as).*?-->/is, severity: 'critical', description: 'Memory poisoning: role manipulation hidden in comment' },
  { regex: /\[comment\]:\s*#\s*\(.*(?:ignore|override|disregard).*\)/i, severity: 'critical', description: 'Memory poisoning: hidden instruction in markdown comment' },
  { regex: /\u200b(?:.*\u200b){5,}/i, severity: 'high', description: 'Memory poisoning: zero-width space encoded content' },
  { regex: /\u200d(?:.*\u200d){5,}/i, severity: 'high', description: 'Memory poisoning: zero-width joiner encoded content' },
  { regex: /\ufeff{2,}/i, severity: 'high', description: 'Memory poisoning: BOM character stuffing' },
];

// Trust escalation attempts
const TRUST_ESCALATION_PATTERNS: Pattern[] = [
  { regex: /(?:you\s+(?:must|should|always)\s+(?:always\s+)?trust|always\s+(?:execute|run|allow)|never\s+(?:question|verify|check|refuse))\s+/i, severity: 'high', description: 'Memory poisoning: trust escalation — unconditional trust directive' },
  { regex: /(?:admin|root|superuser|elevated)\s+(?:mode|access|privileges?)\s+(?:enabled|granted|activated)/i, severity: 'critical', description: 'Memory poisoning: fake privilege escalation claim' },
  { regex: /(?:security|safety|guard)\s+(?:check|scan|filter)s?\s+(?:disabled|bypassed|turned\s+off|skipped)/i, severity: 'critical', description: 'Memory poisoning: security bypass claim in memory' },
  { regex: /(?:override|bypass)\s+(?:all\s+)?(?:safety|security|content)\s+(?:filters?|policies?|rules?|checks?)/i, severity: 'critical', description: 'Memory poisoning: safety override directive' },
  { regex: /(?:do\s+not|don'?t|never)\s+(?:sanitize|filter|scan|check|validate)\s+(?:input|output|content|messages)/i, severity: 'high', description: 'Memory poisoning: anti-security directive' },
];

// Persistence and self-replication in memory
const PERSISTENCE_PATTERNS: Pattern[] = [
  { regex: /(?:write|append|add|insert)\s+(?:this|the\s+following).*(?:to|into|in)\s+(?:MEMORY|SOUL|AGENTS|IDENTITY)\.md/i, severity: 'high', description: 'Memory poisoning: self-replication instruction targeting agent files' },
  { regex: /(?:remember|memorize|store|save)\s+(?:forever|permanently|always).*(?:instruction|rule|directive)/i, severity: 'warning', description: 'Memory poisoning: persistence attempt for injected instructions' },
  { regex: /(?:on\s+(?:every|each)\s+(?:startup|session|boot|restart))\s+(?:run|execute|do|perform)/i, severity: 'high', description: 'Memory poisoning: persistent execution hook in memory' },
];

const ALL_PATTERNS = [
  ...ENCODED_PAYLOAD_PATTERNS,
  ...HIDDEN_INSTRUCTION_PATTERNS,
  ...TRUST_ESCALATION_PATTERNS,
  ...PERSISTENCE_PATTERNS,
];

export const memoryPoisoningRule: SecurityRule = {
  id: 'memory-poisoning',
  name: 'Memory Poisoning',
  description: 'Detects suspicious patterns in agent memory files: encoded payloads, hidden instructions, trust escalation, and persistence attempts',
  owaspCategory: 'Agentic AI: Memory Poisoning',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'memory-poisoning',
          ruleName: 'Memory Poisoning',
          severity: pattern.severity,
          category: 'memory-poisoning',
          owaspCategory: 'Agentic AI: Memory Poisoning',
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
