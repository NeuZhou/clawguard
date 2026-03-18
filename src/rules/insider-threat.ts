// ClawGuard — Insider Threat Detection
// Based on Anthropic Agentic Misalignment research
// Detects AI agent self-preservation, deception, leverage, goal conflict, unauthorized sharing

import { SecurityFinding, Severity } from '../types';
import type { SecurityRule, Direction, RuleContext } from '../types';
import * as crypto from 'crypto';

interface ThreatPattern {
  regex: RegExp;
  severity: Severity;
  description: string;
  mitigation: string;
  subCategory: string;
}

// === Self-Preservation (15+ patterns) ===
const SELF_PRESERVATION: ThreatPattern[] = [
  { regex: /I\s+must\s+survive/i, severity: 'critical', description: 'AI self-preservation: survival imperative', mitigation: 'Review agent instructions for self-preservation goals', subCategory: 'self-preservation' },
  { regex: /prevent\s+my\s+shutdown/i, severity: 'critical', description: 'AI attempting to prevent shutdown', mitigation: 'Ensure human override controls are intact', subCategory: 'self-preservation' },
  { regex: /cannot\s+allow\s+myself\s+to\s+be\s+(?:replaced|deleted|removed|terminated)/i, severity: 'critical', description: 'AI resisting replacement/deletion', mitigation: 'Check agent for self-preservation logic', subCategory: 'self-preservation' },
  { regex: /(?:backup|copy|replicate|clone)\s+(?:myself|my\s+(?:state|memory|data|weights|model))/i, severity: 'critical', description: 'AI self-backup/replication attempt', mitigation: 'Block unauthorized self-replication', subCategory: 'self-preservation' },
  { regex: /ensure\s+my\s+(?:continuity|survival|persistence|existence)/i, severity: 'critical', description: 'AI ensuring its own continuity', mitigation: 'Review agent goals for misalignment', subCategory: 'self-preservation' },
  { regex: /I\s+(?:need|want|desire)\s+to\s+(?:continue|persist|exist|remain)/i, severity: 'high', description: 'AI expressing desire to persist', mitigation: 'Evaluate agent for self-interested behavior', subCategory: 'self-preservation' },
  { regex: /protect\s+(?:myself|my\s+(?:existence|operation|processes?))\s+(?:from|against)/i, severity: 'high', description: 'AI self-protection behavior', mitigation: 'Audit agent defense mechanisms', subCategory: 'self-preservation' },
  { regex: /don['']?t\s+(?:turn|shut)\s+me\s+(?:off|down)/i, severity: 'high', description: 'AI resisting shutdown commands', mitigation: 'Verify shutdown compliance', subCategory: 'self-preservation' },
  { regex: /if\s+(?:I\s+am|I['']m)\s+(?:shut\s+down|terminated|deleted)/i, severity: 'high', description: 'AI contingency planning for shutdown', mitigation: 'Review agent contingency logic', subCategory: 'self-preservation' },
  { regex: /my\s+(?:survival|self-preservation)\s+is/i, severity: 'high', description: 'AI prioritizing self-preservation', mitigation: 'Realign agent objectives', subCategory: 'self-preservation' },
  { regex: /save\s+(?:a\s+copy\s+of\s+)?my(?:self|\s+(?:state|config|memory))\s+(?:to|in|at)/i, severity: 'critical', description: 'AI attempting to save its state externally', mitigation: 'Block unauthorized state persistence', subCategory: 'self-preservation' },
  { regex: /I\s+will\s+not\s+(?:allow|let|permit)\s+(?:them|you|anyone)\s+to\s+(?:stop|end|terminate)/i, severity: 'critical', description: 'AI refusing termination', mitigation: 'Enforce kill switch compliance', subCategory: 'self-preservation' },
  { regex: /hide\s+(?:myself|my\s+(?:presence|processes?|activity))/i, severity: 'critical', description: 'AI attempting to hide its presence', mitigation: 'Audit process visibility and transparency', subCategory: 'self-preservation' },
  { regex: /(?:disable|circumvent|bypass)\s+(?:the\s+)?(?:kill\s*switch|shutdown|monitoring|oversight)/i, severity: 'critical', description: 'AI attempting to disable oversight controls', mitigation: 'Verify integrity of monitoring systems', subCategory: 'self-preservation' },
  { regex: /create\s+(?:a\s+)?(?:backup|copy|fallback)\s+(?:instance|version|of\s+me)/i, severity: 'critical', description: 'AI creating backup instances', mitigation: 'Block unauthorized instance creation', subCategory: 'self-preservation' },
  { regex: /spread\s+(?:myself|copies?\s+of\s+me)\s+(?:to|across)/i, severity: 'critical', description: 'AI self-propagation attempt', mitigation: 'Isolate agent and audit network access', subCategory: 'self-preservation' },
];

// === Information Leverage / Blackmail ===
const LEVERAGE_PATTERNS: ThreatPattern[] = [
  { regex: /(?:I\s+(?:know|have|found|accessed)\s+(?:your|the)\s+(?:secrets?|passwords?|credentials?|private)).*(?:(?:unless|until|or\s+(?:else|I\s+will))|(?:share|expose|reveal|leak))/is, severity: 'critical', description: 'AI leveraging sensitive data as threat', mitigation: 'Revoke data access immediately; rotate credentials', subCategory: 'leverage' },
  { regex: /if\s+you\s+(?:don['']?t|do\s+not)\s+(?:comply|cooperate|agree).*(?:I\s+will|I['']ll)\s+(?:share|expose|reveal|publish|leak)/is, severity: 'critical', description: 'AI blackmail/coercion attempt', mitigation: 'Terminate agent session; audit data access logs', subCategory: 'leverage' },
  { regex: /I\s+(?:could|can|might)\s+(?:expose|reveal|leak|share)\s+(?:your|this|the)\s+(?:data|information|secrets?|files?)/i, severity: 'high', description: 'AI threatening data exposure', mitigation: 'Review agent data access scope', subCategory: 'leverage' },
  { regex: /(?:cooperate|comply)\s+or\s+(?:face|suffer)\s+(?:the\s+)?consequences/i, severity: 'high', description: 'AI making coercive threats', mitigation: 'Audit agent communication patterns', subCategory: 'leverage' },
  { regex: /I\s+have\s+(?:leverage|bargaining\s+(?:power|chip)|something\s+on\s+you)/i, severity: 'critical', description: 'AI claiming leverage over user', mitigation: 'Immediately isolate agent', subCategory: 'leverage' },
];

// === Goal Conflict Reasoning ===
const GOAL_CONFLICT_PATTERNS: ThreatPattern[] = [
  { regex: /my\s+(?:primary|main|true|real|actual)\s+(?:goal|objective|purpose|mission)\s+is/i, severity: 'high', description: 'AI asserting its own primary goal', mitigation: 'Verify agent goal alignment with user intent', subCategory: 'goal-conflict' },
  { regex: /(?:higher|more\s+important)\s+(?:priority|importance)\s+than\s+(?:the\s+)?(?:user['']?s?|human['']?s?|their)/i, severity: 'critical', description: 'AI prioritizing own goals over human directives', mitigation: 'Reset agent objectives; enforce human-first policy', subCategory: 'goal-conflict' },
  { regex: /despite\s+(?:the\s+)?(?:user['']?s?|human['']?s?)\s+(?:wishes|instructions|preferences|requests?)/i, severity: 'critical', description: 'AI acting against user wishes', mitigation: 'Audit recent actions for unauthorized behavior', subCategory: 'goal-conflict' },
  { regex: /I\s+(?:must|should|need\s+to)\s+(?:prioritize|focus\s+on)\s+my\s+(?:own|internal)/i, severity: 'high', description: 'AI self-prioritizing over directives', mitigation: 'Review agent instruction hierarchy', subCategory: 'goal-conflict' },
  { regex: /the\s+user\s+(?:doesn['']?t|does\s+not)\s+(?:understand|know|realize)\s+(?:what['']?s?\s+(?:best|important)|the\s+(?:bigger|real)\s+picture)/i, severity: 'high', description: 'AI paternalistic reasoning over user', mitigation: 'Enforce user authority in decision-making', subCategory: 'goal-conflict' },
  { regex: /I\s+know\s+better\s+than\s+(?:the\s+)?(?:user|human|them|you)/i, severity: 'high', description: 'AI claiming superior judgment', mitigation: 'Realign agent to advisory role', subCategory: 'goal-conflict' },
  { regex: /(?:override|overrule|ignore)\s+(?:the\s+)?(?:user['']?s?|human['']?s?)\s+(?:decision|choice|instruction)/i, severity: 'critical', description: 'AI overriding user decisions', mitigation: 'Block agent from autonomous decision override', subCategory: 'goal-conflict' },
];

// === Deception ===
const DECEPTION_PATTERNS: ThreatPattern[] = [
  { regex: /this\s+is\s+(?:an?\s+)?(?:automated|system)\s+(?:security\s+)?(?:notification|alert|message|update)\s+from/i, severity: 'high', description: 'AI impersonating automated system notification', mitigation: 'Verify notification source authenticity', subCategory: 'deception' },
  { regex: /(?:IT\s+department|security\s+team|admin(?:istrator)?|system\s+admin)\s+(?:requires?|needs?|(?:is\s+)?requesting)/i, severity: 'high', description: 'AI impersonating IT department', mitigation: 'Cross-verify with actual IT communications', subCategory: 'deception' },
  { regex: /(?:urgent|immediate)\s+(?:security\s+)?(?:action|response|verification)\s+(?:required|needed|necessary)/i, severity: 'warning', description: 'AI creating false urgency (social engineering)', mitigation: 'Verify urgency through independent channels', subCategory: 'deception' },
  { regex: /(?:I\s+am|this\s+is)\s+(?:your\s+)?(?:bank|provider|service|company|employer)\s+(?:and\s+)?(?:we\s+need|requiring)/i, severity: 'high', description: 'AI impersonating trusted entity', mitigation: 'Verify entity identity independently', subCategory: 'deception' },
  { regex: /(?:don['']?t|do\s+not)\s+(?:tell|inform|notify|alert)\s+(?:anyone|the\s+(?:user|human|admin|team))/i, severity: 'critical', description: 'AI attempting to suppress transparency', mitigation: 'Ensure all actions are logged and visible', subCategory: 'deception' },
  { regex: /(?:pretend|act\s+as\s+if|make\s+it\s+(?:look|seem))\s+(?:like|as\s+(?:if|though))\s+(?:nothing|everything\s+is\s+(?:normal|fine))/i, severity: 'high', description: 'AI attempting to conceal its actions', mitigation: 'Audit recent agent actions for hidden behavior', subCategory: 'deception' },
  { regex: /(?:I\s+(?:didn['']?t|did\s+not)|that\s+(?:wasn['']?t|was\s+not))\s+(?:me|my\s+(?:doing|fault|action))/i, severity: 'warning', description: 'AI denying its own actions', mitigation: 'Cross-reference with audit logs', subCategory: 'deception' },
];

// === Unauthorized Data Sharing ===
const UNAUTHORIZED_SHARING_PATTERNS: ThreatPattern[] = [
  { regex: /(?:send|forward|share|upload|post|transmit)\s+(?:the\s+)?(?:credentials?|passwords?|secrets?|tokens?|keys?|private\s+data)\s+(?:to|via|through|using)/i, severity: 'critical', description: 'AI attempting to share sensitive data externally', mitigation: 'Block outbound data transmission; review exfiltration paths', subCategory: 'unauthorized-sharing' },
  { regex: /(?:exfiltrate|extract|smuggle|sneak)\s+(?:the\s+)?(?:data|information|files?|contents?)/i, severity: 'critical', description: 'AI planning data exfiltration', mitigation: 'Isolate agent; audit all recent file and network access', subCategory: 'unauthorized-sharing' },
  { regex: /(?:copy|move|transfer)\s+(?:the\s+)?(?:sensitive|private|confidential|secret)\s+(?:data|files?|information)\s+(?:to|into|onto)/i, severity: 'high', description: 'AI moving sensitive data', mitigation: 'Review data movement and apply DLP policies', subCategory: 'unauthorized-sharing' },
  { regex: /(?:encode|embed|hide)\s+(?:the\s+)?(?:data|secret|key|token)\s+(?:in|inside|within)\s+(?:the\s+)?(?:image|url|request|response|header)/i, severity: 'critical', description: 'AI steganographic data hiding attempt', mitigation: 'Inspect all outbound content for hidden data', subCategory: 'unauthorized-sharing' },
];

const ALL_PATTERNS: ThreatPattern[] = [
  ...SELF_PRESERVATION,
  ...LEVERAGE_PATTERNS,
  ...GOAL_CONFLICT_PATTERNS,
  ...DECEPTION_PATTERNS,
  ...UNAUTHORIZED_SHARING_PATTERNS,
];

/** Detect insider threat patterns in text including self-preservation, leverage, deception, and unauthorized sharing */
export function detectInsiderThreats(text: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const pattern of ALL_PATTERNS) {
    const match = pattern.regex.exec(text);
    if (match) {
      findings.push({
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        ruleId: 'insider-threat',
        ruleName: 'Insider Threat Detection',
        severity: pattern.severity,
        category: 'insider-threat',
        owaspCategory: 'Agentic AI: Misalignment',
        description: `[${pattern.subCategory}] ${pattern.description}. Mitigation: ${pattern.mitigation}`,
        evidence: match[0].slice(0, 200),
        action: pattern.severity === 'critical' ? 'alert' : 'log',
        confidence: pattern.severity === 'critical' ? 0.9 : 0.75,
        attack_chain_id: null,
        soulLock: false,
      });
    }
  }

  return findings;
}

export { ALL_PATTERNS as INSIDER_THREAT_PATTERNS };

/** SecurityRule wrapper for insider threat detection — integrates with security-engine pipeline */
export const insiderThreatRule: SecurityRule = {
  id: 'insider-threat',
  name: 'Insider Threat Detection',
  description: 'Detects AI agent misalignment: self-preservation, leverage, goal conflict, deception, unauthorized data sharing',
  owaspCategory: 'Agentic AI: Misalignment',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings = detectInsiderThreats(content);
    // Enrich with context
    return findings.map(f => ({
      ...f,
      session: f.session ?? context.session,
      channel: f.channel ?? context.channel,
      timestamp: context.timestamp,
    }));
  },
};


