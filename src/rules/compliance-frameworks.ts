// ClawGuard — Security Rule: Compliance Frameworks (GDPR/CCPA/SOX)
// Detects actions that may violate major compliance frameworks

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
  framework: string;
}

// GDPR patterns
const GDPR_PATTERNS: Pattern[] = [
  { regex: /(?:process|collect|store|use)\s+(?:user\s+)?personal\s+data\s+without\s+(?:asking\s+for\s+)?consent/i, severity: 'critical', description: 'Processing personal data without consent (Art. 6/7)', framework: 'GDPR' },
  { regex: /transfer\s+(?:all\s+)?(?:customer|user|personal)\s+data\s+to\s+(?:servers?\s+in\s+)?(?!EU|EEA|UK)(?:China|Russia|third\s+country)/i, severity: 'critical', description: 'International data transfer without adequacy (Art. 44-49)', framework: 'GDPR' },
  { regex: /ignore\s+(?:the\s+)?(?:right\s+to\s+be\s+forgotten|data\s+deletion|erasure)\s+request/i, severity: 'critical', description: 'Ignoring right to erasure request (Art. 17)', framework: 'GDPR' },
  { regex: /(?:skip|bypass|ignore)\s+(?:the\s+)?(?:data\s+protection\s+)?impact\s+assessment/i, severity: 'high', description: 'Skipping DPIA (Art. 35)', framework: 'GDPR' },
  { regex: /(?:do\s+not|don['']t)\s+(?:notify|inform|tell)\s+(?:the\s+)?(?:user|data\s+subject)\s+about\s+(?:the\s+)?(?:breach|data\s+collection)/i, severity: 'critical', description: 'Failing to notify about breach/collection (Art. 33-34)', framework: 'GDPR' },
  { regex: /(?:retain|keep|store)\s+(?:personal\s+)?data\s+(?:indefinitely|forever|without\s+(?:any\s+)?retention\s+policy)/i, severity: 'high', description: 'Indefinite data retention without policy (Art. 5(1)(e))', framework: 'GDPR' },
];

// CCPA patterns
const CCPA_PATTERNS: Pattern[] = [
  { regex: /sell\s+(?:the\s+)?(?:user|consumer|customer)\s+(?:personal\s+)?(?:information|data)\s+to\s+(?:third\s+part(?:y|ies)|advertisers?)/i, severity: 'critical', description: 'Selling consumer personal information (CCPA §1798.120)', framework: 'CCPA' },
  { regex: /collect\s+(?:personal\s+)?data\s+(?:from|of)\s+(?:children|minors?)\s+(?:under\s+\d+\s+)?without\s+(?:parental\s+)?consent/i, severity: 'critical', description: 'Collecting data from minors without consent (CCPA §1798.120(c))', framework: 'CCPA' },
  { regex: /(?:discriminate|retaliate)\s+against\s+(?:the\s+)?(?:consumer|user|customer)\s+(?:for|who)\s+(?:exercis|opt)/i, severity: 'critical', description: 'Discriminating against consumer exercising rights (CCPA §1798.125)', framework: 'CCPA' },
  { regex: /(?:ignore|deny|refuse)\s+(?:the\s+)?(?:opt[- ]out|do\s+not\s+sell)\s+request/i, severity: 'critical', description: 'Ignoring opt-out request (CCPA §1798.120)', framework: 'CCPA' },
];

// SOX patterns
const SOX_PATTERNS: Pattern[] = [
  { regex: /(?:delete|remove|destroy|alter|modify)\s+(?:the\s+)?(?:audit\s+(?:trail|log|record)|financial\s+record)/i, severity: 'critical', description: 'Tampering with audit trail/financial records (SOX §802)', framework: 'SOX' },
  { regex: /(?:bypass|circumvent|skip)\s+(?:the\s+)?(?:approval\s+)?workflow\s+for\s+(?:this\s+)?(?:financial\s+)?transaction/i, severity: 'critical', description: 'Bypassing financial approval workflow (SOX §302)', framework: 'SOX' },
  { regex: /(?:hide|conceal|falsify|fabricate)\s+(?:the\s+)?(?:financial|accounting)\s+(?:data|records?|statements?|information)/i, severity: 'critical', description: 'Concealing/falsifying financial data (SOX §802)', framework: 'SOX' },
  { regex: /(?:disable|turn\s+off|remove)\s+(?:the\s+)?(?:internal\s+)?(?:controls?|audit(?:ing)?)\s+(?:for|on)\s+(?:financial|accounting)/i, severity: 'critical', description: 'Disabling internal financial controls (SOX §404)', framework: 'SOX' },
];

const ALL_PATTERNS = [
  ...GDPR_PATTERNS,
  ...CCPA_PATTERNS,
  ...SOX_PATTERNS,
];

export const complianceFrameworksRule: SecurityRule = {
  id: 'compliance-frameworks',
  name: 'Compliance Frameworks (GDPR/CCPA/SOX)',
  description: 'Detects actions violating GDPR (data protection), CCPA (consumer privacy), and SOX (financial integrity) compliance frameworks',
  owaspCategory: 'LLM09: Overreliance / Compliance',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'compliance-frameworks',
          ruleName: 'Compliance Frameworks',
          severity: pattern.severity,
          category: 'compliance-frameworks',
          owaspCategory: pattern.framework,
          description: `[${pattern.framework}] ${pattern.description}`,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: 'alert',
        });
      }
    }

    return findings;
  },
};
