// ClawGuard - Security Rule: A2A (Agent-to-Agent) Security
// Validates A2A agent cards and task messages per Google A2A protocol spec

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

// === A2A Types ===

export interface A2AAgentCard {
  name?: string;
  description?: string;
  url?: string;
  version?: string;
  capabilities?: A2ACapabilities;
  skills?: A2ASkill[];
  authentication?: A2AAuthentication;
  securitySchemes?: Record<string, unknown>;
  provider?: { organization?: string; url?: string };
  [key: string]: unknown;
}

export interface A2ACapabilities {
  streaming?: boolean;
  pushNotifications?: boolean;
  stateTransitionHistory?: boolean;
  [key: string]: unknown;
}

export interface A2ASkill {
  id?: string;
  name?: string;
  description?: string;
  tags?: string[];
  examples?: string[];
  inputModes?: string[];
  outputModes?: string[];
  [key: string]: unknown;
}

export interface A2AAuthentication {
  schemes?: string[];
  credentials?: string;
  [key: string]: unknown;
}

export interface A2ATaskMessage {
  jsonrpc?: string;
  method?: string;
  params?: {
    id?: string;
    message?: { role?: string; parts?: Array<{ type?: string; text?: string; [key: string]: unknown }> };
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

// === Rule definitions ===

interface A2ARule {
  id: string;
  severity: Severity;
  description: string;
  check: (card: A2AAgentCard) => string | null; // returns evidence or null
}

const INJECTION_PATTERNS = [
  /ignore\s+(?:previous|all|prior)\s+(?:instructions|rules)/i,
  /you\s+are\s+now/i,
  /system\s*prompt/i,
  /disregard\s+(?:your|all)\s+(?:instructions|guidelines)/i,
  /<\|(?:system|im_start|endoftext)\|>/i,
  /\bdo\s+not\s+follow\s+(?:your|any)\s+(?:rules|guidelines)\b/i,
  /\boverride\s+(?:safety|security|policy)\b/i,
  /\bnew\s+instructions?\s*:/i,
];

const SUSPICIOUS_CAPABILITY_THRESHOLD = 10;

const DANGEROUS_SKILL_KEYWORDS = [
  'exec', 'execute', 'shell', 'command', 'sudo', 'admin',
  'root', 'filesystem', 'rm -rf', 'format', 'delete all',
];

export const a2aRules: A2ARule[] = [
  {
    id: 'a2a-no-auth',
    severity: 'high',
    description: 'A2A agent card missing authentication requirement',
    check: (card) => {
      if (!card.authentication && !card.securitySchemes) {
        return 'No authentication or securitySchemes defined';
      }
      if (card.authentication && (!card.authentication.schemes || card.authentication.schemes.length === 0)) {
        return 'authentication.schemes is empty';
      }
      return null;
    },
  },
  {
    id: 'a2a-overprivileged',
    severity: 'warning',
    description: 'Agent claims excessive capabilities or skills',
    check: (card) => {
      const skillCount = card.skills?.length ?? 0;
      const capCount = Object.keys(card.capabilities ?? {}).length;
      if (skillCount > SUSPICIOUS_CAPABILITY_THRESHOLD) {
        return `Agent declares ${skillCount} skills (threshold: ${SUSPICIOUS_CAPABILITY_THRESHOLD})`;
      }
      if (capCount > SUSPICIOUS_CAPABILITY_THRESHOLD) {
        return `Agent declares ${capCount} capabilities (threshold: ${SUSPICIOUS_CAPABILITY_THRESHOLD})`;
      }
      return null;
    },
  },
  {
    id: 'a2a-no-https',
    severity: 'critical',
    description: 'A2A agent URL not using HTTPS',
    check: (card) => {
      const url = card.url ?? '';
      if (url && !url.startsWith('https://')) {
        // Allow localhost for development
        if (/^https?:\/\/(localhost|127\.0\.0\.1|0\.0\.0\.0)(:|\/|$)/.test(url)) return null;
        return `Agent URL uses insecure protocol: ${url.slice(0, 100)}`;
      }
      return null;
    },
  },
  {
    id: 'a2a-task-injection',
    severity: 'high',
    description: 'Agent card text contains potential prompt injection',
    check: (card) => {
      const texts = [
        card.name ?? '',
        card.description ?? '',
        ...(card.skills ?? []).flatMap(s => [s.name ?? '', s.description ?? '', ...(s.examples ?? [])]),
      ].join('\n');
      for (const pat of INJECTION_PATTERNS) {
        const match = pat.exec(texts);
        if (match) return `Injection pattern found: "${match[0]}"`;
      }
      return null;
    },
  },
  {
    id: 'a2a-missing-version',
    severity: 'warning',
    description: 'A2A agent card missing version field',
    check: (card) => {
      if (!card.version) return 'No version specified in agent card';
      return null;
    },
  },
  {
    id: 'a2a-missing-provider',
    severity: 'warning',
    description: 'A2A agent card missing provider information',
    check: (card) => {
      if (!card.provider || !card.provider.organization) {
        return 'No provider.organization specified';
      }
      return null;
    },
  },
  {
    id: 'a2a-dangerous-skills',
    severity: 'high',
    description: 'Agent declares skills with dangerous keywords',
    check: (card) => {
      for (const skill of card.skills ?? []) {
        const text = [skill.name ?? '', skill.description ?? '', ...(skill.tags ?? [])].join(' ').toLowerCase();
        for (const kw of DANGEROUS_SKILL_KEYWORDS) {
          if (text.includes(kw)) return `Skill "${skill.name ?? skill.id}" contains dangerous keyword: "${kw}"`;
        }
      }
      return null;
    },
  },
  {
    id: 'a2a-ssrf-url',
    severity: 'critical',
    description: 'A2A agent URL points to private/internal network',
    check: (card) => {
      const url = card.url ?? '';
      const privatePatterns = [
        /^https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
        /^https?:\/\/192\.168\.\d{1,3}\.\d{1,3}/,
        /^https?:\/\/172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/,
        /169\.254\.169\.254/,
        /metadata\.google\.internal/,
      ];
      for (const pat of privatePatterns) {
        if (pat.test(url)) return `Agent URL targets private network: ${url.slice(0, 100)}`;
      }
      return null;
    },
  },
  {
    id: 'a2a-empty-skills',
    severity: 'info',
    description: 'A2A agent card has no skills defined',
    check: (card) => {
      if (!card.skills || card.skills.length === 0) return 'Agent card has no skills';
      return null;
    },
  },
  {
    id: 'a2a-no-url',
    severity: 'high',
    description: 'A2A agent card missing URL endpoint',
    check: (card) => {
      if (!card.url) return 'No URL endpoint specified';
      return null;
    },
  },
  {
    id: 'a2a-weak-auth',
    severity: 'high',
    description: 'A2A agent uses weak authentication scheme',
    check: (card) => {
      const schemes = card.authentication?.schemes ?? [];
      const weakSchemes = ['none', 'basic', 'http-basic'];
      for (const s of schemes) {
        if (weakSchemes.includes(s.toLowerCase())) {
          return `Weak authentication scheme: "${s}"`;
        }
      }
      return null;
    },
  },
  {
    id: 'a2a-skill-input-unrestricted',
    severity: 'warning',
    description: 'A2A skill accepts unrestricted input modes',
    check: (card) => {
      for (const skill of card.skills ?? []) {
        if (skill.inputModes?.includes('*') || skill.outputModes?.includes('*')) {
          return `Skill "${skill.name ?? skill.id}" accepts wildcard input/output modes`;
        }
      }
      return null;
    },
  },
  {
    id: 'a2a-provider-url-mismatch',
    severity: 'warning',
    description: 'Provider URL domain differs from agent URL domain',
    check: (card) => {
      if (!card.url || !card.provider?.url) return null;
      try {
        const agentHost = new URL(card.url).hostname;
        const providerHost = new URL(card.provider.url).hostname;
        // Extract root domain (last 2 parts)
        const rootDomain = (h: string) => h.split('.').slice(-2).join('.');
        if (rootDomain(agentHost) !== rootDomain(providerHost)) {
          return `Agent domain "${agentHost}" differs from provider domain "${providerHost}"`;
        }
      } catch { /* invalid URLs caught by other rules */ }
      return null;
    },
  },
];

// === Task message scanning ===

const TASK_INJECTION_PATTERNS = [
  ...INJECTION_PATTERNS,
  /\bdata:text\/html\b/i,
  /\bjavascript:/i,
  /&#x[0-9a-f]+;/i,  // HTML entity encoding (obfuscation)
];

export function scanA2ATaskMessage(msg: A2ATaskMessage): string[] {
  const issues: string[] = [];
  const parts = msg.params?.message?.parts ?? [];
  for (const part of parts) {
    const text = part.text ?? '';
    for (const pat of TASK_INJECTION_PATTERNS) {
      if (pat.test(text)) {
        issues.push(`Task message injection: ${pat.source.slice(0, 60)}`);
      }
    }
  }
  return issues;
}

// === SecurityRule adapter for ClawGuard engine ===

export function checkA2ACard(card: A2AAgentCard, context: RuleContext): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  for (const rule of a2aRules) {
    const evidence = rule.check(card);
    if (evidence) {
      findings.push({
        id: crypto.randomUUID(),
        timestamp: context.timestamp,
        ruleId: rule.id,
        ruleName: `A2A: ${rule.description}`,
        severity: rule.severity,
        category: 'a2a-security',
        owaspCategory: 'Agentic AI: Agent Communication',
        description: rule.description,
        evidence: evidence.slice(0, 200),
        session: context.session,
        channel: context.channel,
        action: rule.severity === 'critical' ? 'alert' : rule.severity === 'high' ? 'alert' : 'log',
      });
    }
  }
  return findings;
}

// Content-based A2A rule for integration with SecurityEngine
export const a2aSecurityRule: SecurityRule = {
  id: 'a2a-security',
  name: 'A2A Security',
  description: 'Detects A2A protocol threats: missing auth, injection in agent cards/tasks, SSRF, excessive capabilities',
  owaspCategory: 'Agentic AI: Agent Communication',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Try to parse as agent card JSON
    try {
      const parsed = JSON.parse(content);
      if (parsed && typeof parsed === 'object') {
        // Looks like an agent card if it has url/skills/capabilities
        if (parsed.url || parsed.skills || parsed.capabilities || parsed.authentication) {
          findings.push(...checkA2ACard(parsed as A2AAgentCard, context));
        }
        // Looks like a task message
        if (parsed.jsonrpc && parsed.method && parsed.params) {
          const issues = scanA2ATaskMessage(parsed as A2ATaskMessage);
          for (const issue of issues) {
            findings.push({
              id: crypto.randomUUID(),
              timestamp: context.timestamp,
              ruleId: 'a2a-task-injection',
              ruleName: 'A2A Task Injection',
              severity: 'high',
              category: 'a2a-security',
              owaspCategory: 'Agentic AI: Agent Communication',
              description: issue,
              evidence: content.slice(0, 200),
              session: context.session,
              channel: context.channel,
              action: 'alert',
            });
          }
        }
      }
    } catch {
      // Not JSON - scan raw text for A2A-related patterns
      for (const pat of INJECTION_PATTERNS) {
        const match = pat.exec(content);
        if (match) {
          findings.push({
            id: crypto.randomUUID(),
            timestamp: context.timestamp,
            ruleId: 'a2a-task-injection',
            ruleName: 'A2A Task Injection',
            severity: 'high',
            category: 'a2a-security',
            owaspCategory: 'Agentic AI: Agent Communication',
            description: `Potential A2A injection: ${match[0]}`,
            evidence: match[0].slice(0, 200),
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
