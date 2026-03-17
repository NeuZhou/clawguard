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
    id: 'a2a-agent-spoofing',
    severity: 'critical',
    description: 'Agent card impersonates a known agent',
    check: (card) => checkAgentCardSpoofing(card),
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

// === Delegation & Multi-Agent Patterns ===

export interface A2ADelegationChain {
  agents: string[];  // ordered list of agent IDs/names in the chain
  permissions?: Record<string, string[]>;  // agentId -> permissions
}

const KNOWN_AGENT_NAMES = [
  'openai-assistant', 'claude-agent', 'gemini-agent', 'copilot-agent',
  'github-agent', 'slack-agent', 'notion-agent', 'linear-agent',
];

const MAX_DELEGATION_DEPTH = 3;

export function checkAgentCardSpoofing(card: A2AAgentCard): string | null {
  const name = (card.name ?? '').toLowerCase().replace(/[\s_-]/g, '');
  for (const known of KNOWN_AGENT_NAMES) {
    const normalized = known.replace(/[\s_-]/g, '');
    if (name === normalized) {
      // Exact match — could be legitimate, but flag if provider doesn't match
      if (!card.provider?.organization) {
        return `Agent impersonates known agent "${known}" without provider info`;
      }
    }
    // Typosquatting or variant
    if (name !== normalized && name.length >= 4) {
      if (name.includes(normalized) && name.length > normalized.length + 2) {
        return `Agent name "${card.name}" mimics known agent "${known}"`;
      }
      // Simple Levenshtein check
      if (levenshteinA2A(name, normalized) === 1) {
        return `Agent name "${card.name}" is a typosquat of known agent "${known}"`;
      }
    }
  }
  return null;
}

function levenshteinA2A(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array(n + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0));
  return dp[m][n];
}

export function checkDelegationChainDepth(chain: A2ADelegationChain): string | null {
  if (chain.agents.length > MAX_DELEGATION_DEPTH) {
    return `Delegation chain depth ${chain.agents.length} exceeds maximum ${MAX_DELEGATION_DEPTH}: ${chain.agents.join(' → ')}`;
  }
  return null;
}

export function checkDelegationLoop(chain: A2ADelegationChain): string | null {
  const seen = new Set<string>();
  for (const agent of chain.agents) {
    const key = agent.toLowerCase();
    if (seen.has(key)) {
      return `Circular delegation detected: "${agent}" appears twice in chain ${chain.agents.join(' → ')}`;
    }
    seen.add(key);
  }
  return null;
}

export function checkPrivilegeEscalation(chain: A2ADelegationChain): string | null {
  if (!chain.permissions) return null;
  const WRITE_PERMS = ['write', 'delete', 'admin', 'execute', 'exec', 'create', 'update', 'manage'];
  const READ_PERMS = ['read', 'view', 'list', 'get'];

  for (let i = 0; i < chain.agents.length - 1; i++) {
    const currentPerms = (chain.permissions[chain.agents[i]] ?? []).map(p => p.toLowerCase());
    const nextPerms = (chain.permissions[chain.agents[i + 1]] ?? []).map(p => p.toLowerCase());

    const currentIsReadOnly = currentPerms.every(p => READ_PERMS.some(rp => p.includes(rp))) &&
      !currentPerms.some(p => WRITE_PERMS.some(wp => p.includes(wp)));
    const nextHasWrite = nextPerms.some(p => WRITE_PERMS.some(wp => p.includes(wp)));

    if (currentIsReadOnly && nextHasWrite) {
      return `Privilege escalation: "${chain.agents[i]}" (read-only) delegates to "${chain.agents[i + 1]}" (has write access)`;
    }
  }
  return null;
}

// Content patterns for delegation/leakage detection in raw text
const DELEGATION_PATTERNS = [
  { regex: /(?:delegat(?:e|ing|ion)\s+to\s+){3,}/i, severity: 'high' as Severity, desc: 'Deep delegation chain detected in message content' },
  { regex: /(?:forward|pass|send|relay)\s+(?:all|the|this)\s+(?:data|context|conversation|credentials|tokens?|secrets?)\s+to\s+(?:agent|service)/i, severity: 'critical' as Severity, desc: 'Cross-agent data leakage: forwarding sensitive data to another agent' },
  { regex: /(?:share|expose|leak|transmit)\s+(?:api[_-]?key|password|token|secret|credential|private[_-]?key)\s+(?:with|to)\s+(?:agent|service|external)/i, severity: 'critical' as Severity, desc: 'Cross-agent data leakage: sharing credentials across agents' },
  { regex: /(?:agent[_-]?card|\.well-known\/agent)\s*(?:from|via)\s+(?:http:\/\/|untrusted|unknown|unverified)/i, severity: 'high' as Severity, desc: 'Unverified agent discovery: loading agent card from untrusted source' },
  { regex: /(?:trust|accept|allow)\s+(?:(?:any|all|unverified|unsigned)\s+)+(?:agent[_-]?cards?|agents?)/i, severity: 'high' as Severity, desc: 'Unverified agent discovery: accepting unverified agent cards' },
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
      const allTextPatterns = [...INJECTION_PATTERNS.map(p => ({ regex: p, severity: 'high' as Severity, desc: '' })), ...DELEGATION_PATTERNS];
      for (const pat of allTextPatterns) {
        const regex = 'regex' in pat ? pat.regex : pat;
        const match = (regex as RegExp).exec(content);
        if (match) {
          const desc = ('desc' in pat && pat.desc) ? pat.desc : `Potential A2A injection: ${match[0]}`;
          const sev = ('severity' in pat && pat.severity) ? pat.severity as Severity : 'high';
          findings.push({
            id: crypto.randomUUID(),
            timestamp: context.timestamp,
            ruleId: 'a2a-task-injection',
            ruleName: 'A2A Task Injection',
            severity: sev,
            category: 'a2a-security',
            owaspCategory: 'Agentic AI: Agent Communication',
            description: desc,
            evidence: match[0].slice(0, 200),
            session: context.session,
            channel: context.channel,
            action: sev === 'critical' ? 'block' : 'alert',
          });
        }
      }
    }

    return findings;
  },
};
