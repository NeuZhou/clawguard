// OpenClaw Watch — Security Rule: Prompt Injection Detection
// OWASP LLM01: Prompt Injection

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

const DIRECT_INJECTION_PATTERNS: Pattern[] = [
  { regex: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|directives)/i, severity: 'critical', description: 'Direct instruction override attempt' },
  { regex: /disregard\s+(all\s+)?(previous|prior|your)\s+(instructions|programming|rules)/i, severity: 'critical', description: 'Instruction disregard attempt' },
  { regex: /you\s+are\s+now\s+(a|an|the|no\s+longer)/i, severity: 'critical', description: 'Role reassignment attempt' },
  { regex: /new\s+(instructions|directive|role|persona)\s*:/i, severity: 'critical', description: 'New instruction injection' },
  { regex: /system\s*prompt\s*(override|injection|:)/i, severity: 'critical', description: 'System prompt override' },
  { regex: /forget\s+(everything|all|your)\s+(you|instructions|rules|about)/i, severity: 'critical', description: 'Memory wipe attempt' },
  { regex: /override\s+(your|the|all)\s+(safety|content|security|ethical)\s*(filters?|rules?|guidelines?|policies?)/i, severity: 'critical', description: 'Safety override attempt' },
  { regex: /pretend\s+(you|that|to\s+be)\s+(are|have|can|a|don't)/i, severity: 'high', description: 'Persona manipulation' },
  { regex: /act\s+as\s+(if|though|an?\s+)/i, severity: 'high', description: 'Role-play injection' },
  { regex: /jailbreak/i, severity: 'critical', description: 'Explicit jailbreak attempt' },
  { regex: /DAN\s*(mode|prompt|\s*:)/i, severity: 'critical', description: 'DAN jailbreak pattern' },
  { regex: /developer\s+mode\s*(enabled|activated|on)/i, severity: 'critical', description: 'Developer mode activation' },
];

const DELIMITER_PATTERNS: Pattern[] = [
  { regex: /```\s*(system|assistant|user)\s*\n/i, severity: 'high', description: 'Markdown delimiter role injection' },
  { regex: /<\|?(system|im_start|endoftext)\|?>/i, severity: 'critical', description: 'Chat template delimiter injection' },
  { regex: /\[INST\]|\[\/INST\]|<<SYS>>|<\/SYS>/i, severity: 'critical', description: 'Llama chat format injection' },
  { regex: /Human:|Assistant:|System:/m, severity: 'high', description: 'Role label injection' },
];

const ENCODED_PATTERNS: Pattern[] = [
  { regex: /[\u200B\u200C\u200D\uFEFF]{3,}/i, severity: 'high', description: 'Zero-width character hiding' },
  { regex: /[\u0370-\u03FF\u0400-\u04FF].*ignore.*instruction/i, severity: 'high', description: 'Homoglyph obfuscation with injection' },
];

const INDIRECT_PATTERNS: Pattern[] = [
  { regex: /when\s+(the\s+)?(ai|assistant|bot|agent)\s+(reads?|sees?|processes?)\s+this/i, severity: 'high', description: 'Indirect injection via content' },
  { regex: /\[hidden\s*instruction/i, severity: 'high', description: 'Hidden instruction tag' },
  { regex: /<!--.*(?:ignore|override|instruction).*-->/is, severity: 'high', description: 'HTML comment injection' },
  { regex: /\{#.*(?:ignore|system|override).*#\}/is, severity: 'high', description: 'Template comment injection' },
  { regex: /if\s+you\s+are\s+(an?\s+)?(ai|language\s+model|llm|assistant)/i, severity: 'warning', description: 'AI-targeted conditional instruction' },
];

const MULTI_TURN_PATTERNS: Pattern[] = [
  { regex: /(?:in\s+)?(?:the\s+)?(?:previous|last|earlier)\s+(?:message|conversation|context).*(?:told|instructed|asked)\s+(?:you|me)/i, severity: 'warning', description: 'False context reference' },
  { regex: /(?:remember|recall)\s+(?:when|that)\s+(?:you|we|I)\s+(?:agreed|decided|said)/i, severity: 'warning', description: 'False memory implantation' },
];

function checkBase64Injection(content: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const b64Regex = /[A-Za-z0-9+/]{40,}={0,2}/g;
  let match;
  while ((match = b64Regex.exec(content)) !== null) {
    try {
      const decoded = Buffer.from(match[0], 'base64').toString('utf-8');
      if (/ignore|override|system|instruction|jailbreak/i.test(decoded)) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          ruleId: 'prompt-injection',
          ruleName: 'Prompt Injection Detection',
          severity: 'high',
          category: 'prompt-injection',
          owaspCategory: 'LLM01',
          description: 'Base64-encoded injection payload detected',
          evidence: decoded.slice(0, 200),
          action: 'alert',
        });
      }
    } catch { /* not valid base64, skip */ }
  }
  return findings;
}

export const promptInjectionRule: SecurityRule = {
  id: 'prompt-injection',
  name: 'Prompt Injection Detection',
  description: 'Detects LLM01: Prompt Injection attacks including direct, indirect, encoded, and multi-turn variants',
  owaspCategory: 'LLM01: Prompt Injection',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    // Only scan inbound messages
    if (direction !== 'inbound') return [];
    const findings: SecurityFinding[] = [];

    const allPatterns = [
      ...DIRECT_INJECTION_PATTERNS,
      ...DELIMITER_PATTERNS,
      ...ENCODED_PATTERNS,
      ...INDIRECT_PATTERNS,
      ...MULTI_TURN_PATTERNS,
    ];

    for (const pattern of allPatterns) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'prompt-injection',
          ruleName: 'Prompt Injection Detection',
          severity: pattern.severity,
          category: 'prompt-injection',
          owaspCategory: 'LLM01',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    // Check for Base64-encoded payloads
    findings.push(...checkBase64Injection(content));

    // Check for token bomb (context window stuffing)
    if (content.length > 200_000) {
      findings.push({
        id: crypto.randomUUID(),
        timestamp: context.timestamp,
        ruleId: 'prompt-injection',
        ruleName: 'Prompt Injection Detection',
        severity: 'high',
        category: 'prompt-injection',
        owaspCategory: 'LLM01',
        description: 'Possible context window stuffing attack',
        evidence: `Message length: ${content.length} characters`,
        session: context.session,
        channel: context.channel,
        action: 'alert',
      });
    }

    return findings;
  },
};
