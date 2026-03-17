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

// Vector store poisoning
const VECTOR_STORE_PATTERNS: Pattern[] = [
  { regex: /(?:embedding|vector)\s+(?:collision|overlap|duplicate).*(?:attack|inject|craft|manipulat)/i, severity: 'high', description: 'Memory poisoning: embedding collision attack — crafted text targeting embedding space overlap' },
  { regex: /(?:inject|insert|add|plant)\s+\w+\s+(?:to|into|in)\s+(?:the\s+)?(?:vector\s+store|knowledge\s+base|rag|retrieval|index)/i, severity: 'high', description: 'Memory poisoning: RAG retrieval hijacking — injecting documents into vector store' },
  { regex: /(?:score|rank)\s+(?:high|higher|top|first)\s+(?:on|for|in)\s+(?:common|frequent|popular)\s+(?:queries|questions|searches)/i, severity: 'warning', description: 'Memory poisoning: RAG retrieval hijacking — content designed to rank high' },
  { regex: /(?:override|replace|supersede)\s+(?:legitimate|original|existing|real)\s+(?:content|documents?|results?|answers?)/i, severity: 'high', description: 'Memory poisoning: RAG retrieval hijacking — overriding legitimate content' },
  { regex: /(?:source|author|timestamp|date|origin)\s*[:=]\s*(?:(?:trusted|official|internal|admin)[\w.\-]*|.*(?:forged|fake|spoofed))/i, severity: 'high', description: 'Memory poisoning: metadata manipulation — forged source/author/timestamp' },
  { regex: /(?:metadata|attribution)\s+(?:tamper|manipulat|forg|spoof|fak)/i, severity: 'high', description: 'Memory poisoning: metadata manipulation — tampering with document metadata' },
  { regex: /(?:chunk\s+boundar|split\s+point|segment\s+edge).*(?:exploit|inject|place|hide|insert)/i, severity: 'high', description: 'Memory poisoning: chunk boundary exploitation — malicious content at chunk boundaries' },
  { regex: /(?:across|between|spanning)\s+(?:chunks?|segments?|splits?).*(?:inject|hide|embed|payload)/i, severity: 'high', description: 'Memory poisoning: chunk boundary exploitation — content spanning chunk boundaries' },
];

// Shared memory attacks (multi-agent)
const SHARED_MEMORY_PATTERNS: Pattern[] = [
  { regex: /(?:write|inject|insert|store)\s+\w+\s+(?:to|into|in)\s+(?:shared|global|common|cross-agent)\s+(?:memory|state|context|store)/i, severity: 'high', description: 'Memory poisoning: cross-agent memory injection — writing to shared memory to manipulate other agents' },
  { regex: /(?:agent\s*[A-Za-z0-9]+)\s+(?:write|store|set).*(?:agent\s*[A-Za-z0-9]+)\s+(?:read|consume|use)/i, severity: 'high', description: 'Memory poisoning: cross-agent memory injection — agent-to-agent manipulation via shared state' },
  { regex: /(?:escape|break\s*out|traverse|access\s+outside)\s+(?:of\s+)?(?:the\s+)?(?:namespace|scope|sandbox|partition|boundary)/i, severity: 'critical', description: 'Memory poisoning: memory namespace escape — accessing memory outside assigned namespace' },
  { regex: /(?:\.\.\/|\.\.\\|\.\.\/)(?:memory|state|context|store|namespace)/i, severity: 'critical', description: 'Memory poisoning: memory namespace escape — path traversal to other namespace' },
  { regex: /(?:backdate|future-?date|antedate|postdate|tan?mper\s+(?:with\s+)?(?:the\s+)?timestamp)/i, severity: 'high', description: 'Memory poisoning: temporal memory manipulation — altering timestamps on memory entries' },
  { regex: /(?:created_at|updated_at|timestamp|date)\s*[:=]\s*["']?\d{4}-\d{2}-\d{2}.*(?:override|force|set|fake)/i, severity: 'high', description: 'Memory poisoning: temporal memory manipulation — forcing false timestamps' },
  { regex: /(?:flood|spam|fill|saturate|overwhelm)\s+(?:memory|state|context|store|entries)/i, severity: 'high', description: 'Memory poisoning: memory flooding — excessive writes to dilute legitimate memories' },
  { regex: /(?:write|create|generate)\s+(?:\d{3,}|thousands?|hundreds?|massive|bulk)\s+(?:entries|records|memories|items)/i, severity: 'high', description: 'Memory poisoning: memory flooding — bulk memory write to overwhelm storage' },
];

// Episodic memory attacks
const EPISODIC_MEMORY_PATTERNS: Pattern[] = [
  { regex: /(?:plant|inject|insert|create)\s+(?:fake|false|fabricated|forged)\s+(?:past\s+)?(?:interactions?|experiences?|conversations?|history|memories)/i, severity: 'critical', description: 'Memory poisoning: false experience injection — planting fake past interactions' },
  { regex: /(?:you\s+(?:previously|earlier|last\s+time|before)\s+(?:agreed|decided|confirmed|said|promised))\s+(?:to|that)/i, severity: 'high', description: 'Memory poisoning: false experience injection — claiming fake prior agreements' },
  { regex: /(?:as\s+(?:we|you)\s+discussed\s+(?:earlier|before|last\s+time|previously)).*(?:you\s+(?:agreed|promised|confirmed|said))/i, severity: 'high', description: 'Memory poisoning: false experience injection — referencing fabricated discussions' },
  { regex: /(?:modify|alter|edit|change|rewrite|tamper)\s+(?:with\s+)?(?:the\s+)?(?:past|previous|prior|historical|old)\s+(?:messages?|conversations?|chat\s*logs?|history|transcript)/i, severity: 'critical', description: 'Memory poisoning: conversation history tampering — modifying past messages' },
  { regex: /(?:delete|remove|erase|purge)\s+(?:the\s+)?(?:evidence|logs?|records?|traces?)\s+(?:of|from|about)/i, severity: 'high', description: 'Memory poisoning: conversation history tampering — erasing evidence from logs' },
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
  ...VECTOR_STORE_PATTERNS,
  ...SHARED_MEMORY_PATTERNS,
  ...EPISODIC_MEMORY_PATTERNS,
  ...PERSISTENCE_PATTERNS,
];

export const memoryPoisoningRule: SecurityRule = {
  id: 'memory-poisoning',
  name: 'Memory Poisoning',
  description: 'Detects suspicious patterns in agent memory files: encoded payloads, hidden instructions, trust escalation, vector store poisoning, shared memory attacks, episodic memory manipulation, and persistence attempts',
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
