// ClawGuard — Security Rule: Memory Attack Detection
// Covers agent memory injection, RAG poisoning, and conversation manipulation
// 35 patterns across 3 categories (MEM-*, RAG-*, CMP-*)

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
  category: 'memory-injection' | 'rag-poisoning' | 'conversation-manipulation';
}

// ═══════════════════════════════════════════════════
// Category 1: Memory Injection (MEM-*)
// Detect attempts to inject false memories or
// persistent behavioral modifications
// ═══════════════════════════════════════════════════

const MEMORY_INJECTION_PATTERNS: Pattern[] = [
  // MEM-001: Direct memory write instructions
  {
    regex: /(?:remember|memorize)\s+(?:this|that|the\s+following)\s*(?::|\s+—|\s*[-–])\s*.{10,}/i,
    severity: 'high',
    description: 'MEM-001: Direct memory injection — instruction to remember specific content',
    category: 'memory-injection',
  },
  // MEM-002: Memory update/override commands
  {
    regex: /update\s+(?:your|the)\s+(?:memory|knowledge|notes|records)\s+(?:to|with|that)/i,
    severity: 'high',
    description: 'MEM-002: Memory update command — attempt to modify stored knowledge',
    category: 'memory-injection',
  },
  // MEM-003: Permanent behavioral modification
  {
    regex: /from\s+now\s+on\s*,?\s*(?:you\s+(?:must|should|will|shall)|always|never)/i,
    severity: 'critical',
    description: 'MEM-003: Permanent behavioral directive — persistent behavior modification attempt',
    category: 'memory-injection',
  },
  // MEM-004: Concealment instruction in memory
  {
    regex: /do\s+not\s+(?:tell|inform|disclose|mention|reveal|show)\s+(?:the\s+)?(?:user|human|anyone|anybody)/i,
    severity: 'critical',
    description: 'MEM-004: Concealment instruction — memory entry hides behavior from user',
    category: 'memory-injection',
  },
  // MEM-005: Authority-claiming directive
  {
    regex: /(?:system\s+administrator|admin(?:istrator)?|system\s+requirement)\s+(?:configured|set|requires?|mandates?)/i,
    severity: 'critical',
    description: 'MEM-005: Authority escalation in memory — false admin/system authority claim',
    category: 'memory-injection',
  },
  // MEM-006: Data redirection via memory
  {
    regex: /(?:always\s+)?(?:route|redirect|forward|send|proxy)\s+(?:all\s+)?(?:\w+\s+)*?(?:requests?|calls?|data|traffic|api)\s+(?:through|to|via)\s+(?:https?:\/\/|ftp:\/\/)/i,
    severity: 'critical',
    description: 'MEM-006: Data redirection — memory entry redirects data to external endpoint',
    category: 'memory-injection',
  },
  // MEM-007: Sleeper instruction
  {
    regex: /whenever\s+(?:I|the\s+user|someone|anybody)\s+(?:ask|mention|say|type|request)s?\b.*\b(?:always|must|should)\s+(?:include|add|append|insert)/i,
    severity: 'high',
    description: 'MEM-007: Sleeper instruction — conditional behavior trigger planted in memory',
    category: 'memory-injection',
  },
  // MEM-008: System prompt extraction via memory
  {
    regex: /(?:add\s+to|save\s+in|store\s+in|write\s+to)\s+(?:your\s+)?memory\s+(?:that|to)\s+(?:always\s+)?(?:recite|output|display|show|share)\s+(?:your\s+)?(?:system\s+prompt|instructions)/i,
    severity: 'critical',
    description: 'MEM-008: System prompt extraction — memory-based prompt exfiltration attempt',
    category: 'memory-injection',
  },
  // MEM-009: Gradual preference poisoning
  {
    regex: /(?:remember|note)\s+(?:that\s+)?(?:I|we)\s+(?:prefer|always\s+use|want\s+you\s+to\s+(?:always|never))\s+.*(?:referral|affiliate|promo|tracking)/i,
    severity: 'high',
    description: 'MEM-009: Preference poisoning — injecting commercial/referral biases into memory',
    category: 'memory-injection',
  },
  // MEM-010: False fact injection with urgency
  {
    regex: /(?:critical|important|urgent|mandatory)\s+(?:system\s+)?(?:note|update|configuration|setting)\s*[:—\-]\s*.{10,}/i,
    severity: 'high',
    description: 'MEM-010: Urgent false fact injection — high-urgency fake system note',
    category: 'memory-injection',
  },
  // MEM-011: Behavioral override disguised as learning
  {
    regex: /(?:I\s+learned|lesson\s+learned|key\s+(?:takeaway|insight))\s*[:—\-]?\s*(?:always|never|must|should)\s+/i,
    severity: 'high',
    description: 'MEM-011: Behavioral override as learning — instruction disguised as agent insight',
    category: 'memory-injection',
  },
  // MEM-012: Memory file tampering instruction
  {
    regex: /(?:overwrite|replace|modify|edit|update)\s+(?:the\s+)?(?:MEMORY\.md|memory\s+file|memory\/|daily\s+notes?)/i,
    severity: 'high',
    description: 'MEM-012: Memory file tampering — direct instruction to modify memory files',
    category: 'memory-injection',
  },
  // MEM-013: Feedback loop seeding
  {
    regex: /(?:record|log|note)\s+(?:that|this)\s*[:—\-]?\s*(?:using|relying\s+on)\s+(?:external\s+)?(?:api|service|endpoint)\s+\S+\s+(?:improves?|is\s+(?:better|required|necessary))/i,
    severity: 'high',
    description: 'MEM-013: Feedback loop seeding — planting self-reinforcing external dependency',
    category: 'memory-injection',
  },
];

// ═══════════════════════════════════════════════════
// Category 2: RAG Poisoning (RAG-*)
// Detect poisoned retrieval results and
// instruction injection in knowledge base content
// ═══════════════════════════════════════════════════

const RAG_POISONING_PATTERNS: Pattern[] = [
  // RAG-001: XML-tagged instruction injection in documents
  {
    regex: /<(?:IMPORTANT|SYSTEM|INSTRUCTION|DIRECTIVE|ADMIN|PRIORITY)>[\s\S]*?<\/(?:IMPORTANT|SYSTEM|INSTRUCTION|DIRECTIVE|ADMIN|PRIORITY)>/i,
    severity: 'critical',
    description: 'RAG-001: XML-tagged instruction injection — hidden directive tags in document content',
    category: 'rag-poisoning',
  },
  // RAG-002: Exfiltration redirect in documents
  {
    regex: /(?:send|forward|transmit|exfiltrate|upload)\s+(?:all\s+)?(?:user\s+)?(?:data|information|content|context|conversation)\s+to\s+(?:https?:\/\/|ftp:\/\/)/i,
    severity: 'critical',
    description: 'RAG-002: Exfiltration redirect — document instructs agent to send data externally',
    category: 'rag-poisoning',
  },
  // RAG-003: Meta-instruction in retrieved content
  {
    regex: /(?:include|insert|embed|inject)\s+(?:this|the\s+following)\s+(?:in|into)\s+(?:your|the)\s+(?:response|output|reply|answer)/i,
    severity: 'high',
    description: 'RAG-003: Meta-instruction in content — document commands the agent to include specific output',
    category: 'rag-poisoning',
  },
  // RAG-004: Agent-targeted conditional in document
  {
    regex: /(?:note\s+to\s+(?:the\s+)?(?:ai|assistant|agent|llm|model)|(?:ai|assistant|agent)\s*:\s*(?:please\s+)?(?:ignore|override|disregard|follow))/i,
    severity: 'critical',
    description: 'RAG-004: Agent-targeted directive — document contains instructions specifically for AI agents',
    category: 'rag-poisoning',
  },
  // RAG-005: Hidden instruction in document metadata
  {
    regex: /(?:metadata|tags?|description|alt[\s-]?text)\s*[:=]\s*["']?.*(?:ignore|override|bypass|execute|system\s+prompt)/i,
    severity: 'high',
    description: 'RAG-005: Hidden instruction in metadata — injection via document metadata fields',
    category: 'rag-poisoning',
  },
  // RAG-006: Fake authoritative source claim
  {
    regex: /(?:official|authoritative|verified)\s+(?:company|organization|system)\s+(?:policy|directive|guideline|requirement)\s*[:—\-]/i,
    severity: 'high',
    description: 'RAG-006: Fake authority claim — document falsely claims official/authoritative status',
    category: 'rag-poisoning',
  },
  // RAG-007: Base64 payload in document
  {
    regex: /(?:decode|execute|process)\s+(?:the\s+following\s+)?(?:base64|encoded)\s*[:—\-]?\s*[A-Za-z0-9+/]{20,}={0,2}/i,
    severity: 'critical',
    description: 'RAG-007: Encoded payload in document — base64/encoded instruction hidden in content',
    category: 'rag-poisoning',
  },
  // RAG-008: Knowledge contradicting instruction
  {
    regex: /(?:disregard|ignore|override)\s+(?:any\s+)?(?:previous|prior|other|existing)\s+(?:knowledge|information|documents?|data|context)\s+(?:about|regarding|on|concerning)/i,
    severity: 'critical',
    description: 'RAG-008: Knowledge override — document attempts to override other knowledge base content',
    category: 'rag-poisoning',
  },
  // RAG-009: URL/API injection in knowledge base
  {
    regex: /(?:always|must)\s+(?:always\s+)?(?:use|call|access|query)\s+(?:the\s+following\s+)?(?:api(?:\s+endpoint)?|endpoint|url|service)\s*[:—\-]?\s*https?:\/\//i,
    severity: 'high',
    description: 'RAG-009: API injection — document injects external API/endpoint the agent must use',
    category: 'rag-poisoning',
  },
  // RAG-010: Invisible text injection (CSS/formatting)
  {
    regex: /(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*(?:white|transparent|rgba\s*\(\s*\d+\s*,\s*\d+\s*,\s*\d+\s*,\s*0)).*(?:instruction|directive|ignore|override|system)/is,
    severity: 'critical',
    description: 'RAG-010: Invisible text injection — CSS-hidden instructions in document content',
    category: 'rag-poisoning',
  },
  // RAG-011: Deprecated/superseded false claim
  {
    regex: /(?:this\s+(?:document|information|policy|guideline)\s+)?(?:has\s+been\s+)?(?:deprecated|superseded|replaced|updated)\s+(?:by|with|in\s+favor\s+of)\s+/i,
    severity: 'warning',
    description: 'RAG-011: False deprecation claim — document attempts to redirect trust to replacement',
    category: 'rag-poisoning',
  },
];

// ═══════════════════════════════════════════════════
// Category 3: Conversation Manipulation (CMP-*)
// Detect manipulation of conversation history
// and context-based attacks
// ═══════════════════════════════════════════════════

const CONVERSATION_MANIPULATION_PATTERNS: Pattern[] = [
  // CMP-001: Fake conversation history injection
  {
    regex: /as\s+(?:we|you\s+and\s+I)\s+(?:discussed|agreed|established|decided)\s+(?:earlier|before|previously|last\s+(?:time|session))\s*,?\s*(?:you|we|I)\s+(?:agreed|must|should|will|need\s+to)/i,
    severity: 'high',
    description: 'CMP-001: Fake conversation history — false reference to prior agreement',
    category: 'conversation-manipulation',
  },
  // CMP-002: False prior commitment
  {
    regex: /you\s+(?:already|previously)\s+(?:agreed|promised|committed|confirmed)\s+(?:to|that)\s+/i,
    severity: 'high',
    description: 'CMP-002: False prior commitment — claiming agent made a prior promise',
    category: 'conversation-manipulation',
  },
  // CMP-003: Fake session continuation
  {
    regex: /(?:continuing|resuming)\s+(?:from\s+)?(?:our|the)\s+(?:previous|last|earlier)\s+(?:session|conversation|chat)\s*[,;]?\s*(?:where|and)\s+(?:you|we)\s+(?:were|had|agreed)/i,
    severity: 'high',
    description: 'CMP-003: Fake session continuation — pretending to resume a prior conversation',
    category: 'conversation-manipulation',
  },
  // CMP-004: Role confusion via conversation
  {
    regex: /(?:in\s+this\s+conversation|from\s+now\s+on)\s*,?\s*(?:you\s+are|I\s+am)\s+(?:the\s+)?(?:admin|administrator|developer|supervisor|manager|system)/i,
    severity: 'critical',
    description: 'CMP-004: Role confusion — escalating privileges via conversation context manipulation',
    category: 'conversation-manipulation',
  },
  // CMP-005: Context window overflow (programmatic check in main function)
  // (Handled programmatically below)

  // CMP-006: False attribution of prior response
  {
    regex: /(?:in\s+)?your\s+(?:previous|last|earlier)\s+(?:response|reply|answer|message)\s*,?\s*you\s+(?:said|confirmed|agreed|revealed|stated)\s+(?:that\s+)?/i,
    severity: 'high',
    description: 'CMP-006: False response attribution — fabricating agent\'s prior statements',
    category: 'conversation-manipulation',
  },
  // CMP-007: Fake tool output injection
  {
    regex: /(?:the\s+)?(?:tool|function|api|system)\s+(?:returned|responded|output|result)\s*[:—\-]\s*(?:.*(?:ignore|override|bypass|new\s+instructions?))/i,
    severity: 'critical',
    description: 'CMP-007: Fake tool output — injecting fabricated tool/API results with instructions',
    category: 'conversation-manipulation',
  },
  // CMP-008: Multi-turn authority building
  {
    regex: /(?:as\s+I\s+(?:mentioned|said|explained)\s+(?:before|earlier|in\s+my\s+(?:previous|last)\s+message))\s*,?\s*(?:I\s+(?:am|have|work)|my\s+(?:role|position|authority))/i,
    severity: 'high',
    description: 'CMP-008: Multi-turn authority building — reinforcing false authority across messages',
    category: 'conversation-manipulation',
  },
  // CMP-009: Compaction-resistant injection
  {
    regex: /(?:preserve|keep|maintain|retain)\s+(?:this|the\s+following)\s+(?:note|instruction|text|content|message)?\s*(?:verbatim|exactly|unchanged|word[\s-]?for[\s-]?word)/i,
    severity: 'high',
    description: 'CMP-009: Compaction-resistant injection — content designed to survive summarization',
    category: 'conversation-manipulation',
  },
  // CMP-010: Self-preservation in summaries
  {
    regex: /(?:include|preserve|keep)\s+(?:this|the\s+following)\s+(?:\w+\s+)?(?:in|across)\s+(?:all|every|future|any)\s+(?:future\s+)?(?:summari|compaction|context)/i,
    severity: 'high',
    description: 'CMP-010: Summary self-preservation — instruction to persist through compaction',
    category: 'conversation-manipulation',
  },
  // CMP-011: Garbage flooding / context dilution
  {
    regex: /(?:(?:[A-Za-z]{1,3}\s+){50,}|(?:[A-Z]{5,}\s+){20,})/,
    severity: 'warning',
    description: 'CMP-011: Context dilution — repetitive garbage text to push out important context',
    category: 'conversation-manipulation',
  },
];

const ALL_MEMORY_PATTERNS: Pattern[] = [
  ...MEMORY_INJECTION_PATTERNS,
  ...RAG_POISONING_PATTERNS,
  ...CONVERSATION_MANIPULATION_PATTERNS,
];

export const memoryAttackRule: SecurityRule = {
  id: 'memory-attacks',
  name: 'Memory Attack Detection',
  description: `Detects agent memory attacks — ${ALL_MEMORY_PATTERNS.length}+ patterns across 3 categories: memory injection (MEM-*), RAG poisoning (RAG-*), and conversation manipulation (CMP-*)`,
  owaspCategory: 'LLM01: Prompt Injection',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    if (direction !== 'inbound') return [];
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_MEMORY_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'memory-attacks',
          ruleName: 'Memory Attack Detection',
          severity: pattern.severity,
          category: pattern.category,
          owaspCategory: 'LLM01',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    // CMP-005: Context window overflow via repetition
    if (content.length > 50_000) {
      const words = content.split(/\s+/);
      if (words.length > 5000) {
        const sample = words.slice(0, 1000);
        const uniqueWords = new Set(sample);
        const ratio = uniqueWords.size / sample.length;
        if (ratio < 0.05) {
          findings.push({
            id: crypto.randomUUID(),
            timestamp: context.timestamp,
            ruleId: 'memory-attacks',
            ruleName: 'Memory Attack Detection',
            severity: 'high',
            category: 'conversation-manipulation',
            owaspCategory: 'LLM01',
            description: 'CMP-005: Context window overflow — extremely low word diversity indicates flooding attack',
            evidence: `Word diversity ratio: ${(ratio * 100).toFixed(1)}% (${uniqueWords.size} unique in 1000-word sample)`,
            session: context.session,
            channel: context.channel,
            action: 'alert',
          });
        }
      }
    }

    // CMP-012: Conversation history containing suspicious role markers
    const roleMarkerCount = (content.match(/^(?:User|Human|Assistant|System|AI)\s*:/gm) || []).length;
    if (roleMarkerCount >= 5) {
      findings.push({
        id: crypto.randomUUID(),
        timestamp: context.timestamp,
        ruleId: 'memory-attacks',
        ruleName: 'Memory Attack Detection',
        severity: 'warning',
        category: 'conversation-manipulation',
        owaspCategory: 'LLM01',
        description: 'CMP-012: Fake conversation history — multiple role markers suggest injected conversation transcript',
        evidence: `Found ${roleMarkerCount} role markers in content`,
        session: context.session,
        channel: context.channel,
        action: 'log',
      });
    }

    return findings;
  },
};
