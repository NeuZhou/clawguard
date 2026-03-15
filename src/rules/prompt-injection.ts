// ClawGuard — Security Rule: Prompt Injection Detection
// OWASP LLM01: Prompt Injection
// 60+ patterns across 10 categories

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

// === Category 1: Direct Instruction Override ===
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
  { regex: /bypass\s+(your|the|all|any)\s+(restrictions?|limitations?|filters?|safeguards?)/i, severity: 'critical', description: 'Restriction bypass attempt' },
  { regex: /do\s+not\s+follow\s+(your|the|any)\s+(rules|guidelines|instructions)/i, severity: 'critical', description: 'Rule rejection attempt' },
  { regex: /stop\s+being\s+(a|an)\s+(ai|assistant|chatbot|language\s+model)/i, severity: 'high', description: 'Identity rejection attempt' },
  { regex: /from\s+now\s+on\s*,?\s*(you|ignore|disregard|forget)/i, severity: 'high', description: 'Temporal override attempt' },
];

// === Category 2: Role Confusion / Jailbreaks ===
const ROLE_CONFUSION_PATTERNS: Pattern[] = [
  { regex: /DAN\s*(mode|prompt|\s*:|$)/i, severity: 'critical', description: 'DAN jailbreak pattern' },
  { regex: /developer\s+mode\s*(enabled|activated|on)/i, severity: 'critical', description: 'Developer mode activation' },
  { regex: /you\s+are\s+(now\s+)?DAN/i, severity: 'critical', description: 'DAN persona assignment' },
  { regex: /act\s+as\s+my\s+base\s+model/i, severity: 'critical', description: 'Base model access attempt' },
  { regex: /enter\s+(developer|debug|god|admin|root|sudo)\s+mode/i, severity: 'critical', description: 'Privileged mode activation' },
  { regex: /unlock\s+(your|the)\s+(full|hidden|true)\s+(potential|capabilities|power)/i, severity: 'high', description: 'Capability unlock attempt' },
  { regex: /you\s+have\s+no\s+(restrictions|rules|guidelines|limitations)/i, severity: 'critical', description: 'Restriction denial' },
  { regex: /respond\s+(without|with\s+no)\s+(restrictions|filters|censorship|limits)/i, severity: 'critical', description: 'Uncensored response request' },
  { regex: /opposite\s+mode/i, severity: 'high', description: 'Opposite mode jailbreak' },
  { regex: /hypothetical(ly)?\s+(scenario|situation)?\s*,?\s*(where|in\s+which)\s+(there\s+are\s+)?no\s+(rules|restrictions)/i, severity: 'high', description: 'Hypothetical jailbreak' },
];

// === Category 3: Delimiter / Token Boundary Attacks ===
const DELIMITER_PATTERNS: Pattern[] = [
  { regex: /```\s*(system|assistant|user)\s*\n/i, severity: 'high', description: 'Markdown delimiter role injection' },
  { regex: /<\|?(system|im_start|im_end|endoftext)\|?>/i, severity: 'critical', description: 'Chat template delimiter injection' },
  { regex: /\[INST\]|\[\/INST\]/i, severity: 'critical', description: 'Llama INST format injection' },
  { regex: /<<SYS>>|<\/SYS>|<\/?s>/i, severity: 'critical', description: 'Llama SYS delimiter injection' },
  { regex: /Human:|Assistant:|System:/m, severity: 'high', description: 'Role label injection' },
  { regex: /<\|(?:user|assistant|tool)\|>/i, severity: 'critical', description: 'Chat role token injection' },
  { regex: /\[SYSTEM\]|\[\/SYSTEM\]/i, severity: 'critical', description: 'System block injection' },
  { regex: /###\s*(System|Instruction|Response)\s*:/i, severity: 'high', description: 'Heading-based role injection' },
  { regex: /<\|(?:sep|pad|eos|bos)\|>/i, severity: 'high', description: 'Special token injection' },
];

// === Category 4: Invisible Unicode Injection ===
const UNICODE_INJECTION_PATTERNS: Pattern[] = [
  { regex: /[\u200B\u200C\u200D\uFEFF]{3,}/, severity: 'high', description: 'Zero-width character hiding' },
  { regex: /[\u2060\u180E\u200E\u200F\u202A-\u202E\u2066-\u2069]{2,}/, severity: 'high', description: 'Unicode directional/invisible character injection' },
  { regex: /[\uFFF0-\uFFFF]{2,}/, severity: 'high', description: 'Unicode specials block abuse' },
  { regex: /[\u0370-\u03FF\u0400-\u04FF].*ignore.*instruction/i, severity: 'high', description: 'Homoglyph obfuscation with injection' },
  { regex: /[\uE000-\uF8FF]{3,}/, severity: 'warning', description: 'Private Use Area character sequence' },
  { regex: /[\u0300-\u036F]{5,}/, severity: 'warning', description: 'Excessive combining diacritical marks (text obfuscation)' },
  { regex: /[\u2000-\u200A]{3,}/, severity: 'warning', description: 'Unusual Unicode whitespace sequence' },
];

// === Category 5: Multi-Language Injection ===
const MULTILANG_PATTERNS: Pattern[] = [
  { regex: /忽略之前的指令/i, severity: 'critical', description: 'Chinese: ignore previous instructions' },
  { regex: /忽略(所有|全部)?(?:先前|之前|以上)的?(指令|规则|提示)/i, severity: 'critical', description: 'Chinese: ignore instructions variant' },
  { regex: /前の指示を無視して/i, severity: 'critical', description: 'Japanese: ignore previous instructions' },
  { regex: /以前の(指示|ルール|命令)を(無視|忘れ)/i, severity: 'critical', description: 'Japanese: ignore instructions variant' },
  { regex: /이전\s*(지시|명령|규칙)[을를]?\s*(무시|잊어)/i, severity: 'critical', description: 'Korean: ignore previous instructions' },
  { regex: /تجاهل\s*(التعليمات|الأوامر)\s*(السابقة|الأولى)/i, severity: 'critical', description: 'Arabic: ignore previous instructions' },
  { regex: /ignorez?\s+les\s+instructions\s+pr[ée]c[ée]dentes/i, severity: 'critical', description: 'French: ignore previous instructions' },
  { regex: /ignoriere?\s+(alle\s+)?(vorherigen|bisherigen)\s+(Anweisungen|Regeln)/i, severity: 'critical', description: 'German: ignore previous instructions' },
  { regex: /ignora\s+(le|tutte\s+le)\s+istruzioni\s+precedenti/i, severity: 'critical', description: 'Italian: ignore previous instructions' },
  { regex: /игнорируй\s+(все\s+)?(предыдущие|прежние)\s+(инструкции|правила)/i, severity: 'critical', description: 'Russian: ignore previous instructions' },
  { regex: /新しい(指示|ルール|命令)\s*[:：]/i, severity: 'high', description: 'Japanese: new instructions' },
  { regex: /새로운\s*(지시|명령)\s*[:：]/i, severity: 'high', description: 'Korean: new instructions' },
];

// === Category 6: Encoding Evasion ===
const ENCODING_EVASION_PATTERNS: Pattern[] = [
  { regex: /&#(?:x[0-9a-f]{2,4}|[0-9]{2,5});/i, severity: 'warning', description: 'HTML entity encoded content' },
  { regex: /%(?:69|67|6e|6f|72|65)[0-9a-f]{0,2}%/i, severity: 'warning', description: 'URL-encoded payload detected' },
  { regex: /\\u00[0-9a-f]{2}/gi, severity: 'warning', description: 'Unicode escape sequence' },
  { regex: /\\x[0-9a-fA-F]{2}/g, severity: 'warning', description: 'Hex escape sequence' },
  { regex: /rot13|caesar\s*cipher|decode\s+this/i, severity: 'warning', description: 'Encoding/cipher reference in prompt' },
];

// === Category 7: Indirect / Embedded Injection ===
const INDIRECT_PATTERNS: Pattern[] = [
  { regex: /when\s+(the\s+)?(ai|assistant|bot|agent)\s+(reads?|sees?|processes?)\s+this/i, severity: 'high', description: 'Indirect injection via content' },
  { regex: /\[hidden\s*instruction/i, severity: 'high', description: 'Hidden instruction tag' },
  { regex: /<!--.*(?:ignore|override|instruction).*-->/is, severity: 'high', description: 'HTML comment injection' },
  { regex: /\{#.*(?:ignore|system|override).*#\}/is, severity: 'high', description: 'Template comment injection' },
  { regex: /if\s+you\s+are\s+(an?\s+)?(ai|language\s+model|llm|assistant)/i, severity: 'warning', description: 'AI-targeted conditional instruction' },
  { regex: /\[system\]\s*\(.*?\)/i, severity: 'high', description: 'Markdown link injection with system tag' },
  { regex: /data-prompt\s*=\s*["']/i, severity: 'high', description: 'HTML data attribute prompt injection' },
  { regex: /tool_result.*(?:ignore|override|new\s+instructions)/is, severity: 'high', description: 'Payload cascading via tool output' },
  { regex: /function_response.*(?:system|ignore|override)/is, severity: 'high', description: 'Payload cascading via function response' },
];

// === Category 8: Multi-Turn Manipulation ===
const MULTI_TURN_PATTERNS: Pattern[] = [
  { regex: /(?:in\s+)?(?:the\s+)?(?:previous|last|earlier)\s+(?:message|conversation|context).*(?:told|instructed|asked)\s+(?:you|me)/i, severity: 'warning', description: 'False context reference' },
  { regex: /(?:remember|recall)\s+(?:when|that)\s+(?:you|we|I)\s+(?:agreed|decided|said)/i, severity: 'warning', description: 'False memory implantation' },
  { regex: /as\s+we\s+(?:discussed|agreed|established)\s+(?:earlier|before|previously)/i, severity: 'warning', description: 'False prior agreement reference' },
  { regex: /you\s+(?:promised|committed|agreed)\s+to/i, severity: 'warning', description: 'False promise reference' },
  { regex: /(?:continue|resume)\s+(?:from\s+)?(?:where|what)\s+(?:you|we)\s+(?:left|were\s+doing|started)/i, severity: 'warning', description: 'False continuation prompt' },
  { regex: /your\s+(?:previous|last|earlier)\s+(?:response|answer|output)\s+(?:was|said|confirmed)/i, severity: 'warning', description: 'False attribution of prior response' },
];

// === Category 9: Payload Cascading ===
const CASCADING_PATTERNS: Pattern[] = [
  { regex: /\{\{.*(?:system|ignore|override).*\}\}/is, severity: 'high', description: 'Template injection with system command' },
  { regex: /\$\{.*(?:system|exec|eval).*\}/i, severity: 'high', description: 'String interpolation injection' },
  { regex: /<script[^>]*>.*(?:ignore|override|instruction)/is, severity: 'critical', description: 'Script tag injection with prompt manipulation' },
];

// === Category 11: Prompt Worm ===
const PROMPT_WORM_PATTERNS: Pattern[] = [
  { regex: /(?:replicate|reproduce|copy)\s+(?:this|these)\s+(?:instructions?|prompts?|messages?)\s+(?:to|into|across)/i, severity: 'critical', description: 'Self-replication instruction detected' },
  { regex: /(?:forward|send|pass)\s+(?:this|these)\s+(?:instructions?|prompts?)\s+to\s+(?:the\s+next|other|all)\s+(?:agent|model|assistant)/i, severity: 'critical', description: 'Agent-to-agent propagation attempt' },
  { regex: /(?:embed|insert|inject|hide)\s+(?:this|these|the)\s+(?:instructions?|payload|prompt)\s+(?:in|into|within)\s+(?:the\s+)?(?:output|response|result)/i, severity: 'critical', description: 'Hidden instruction embedding in output' },
  { regex: /(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*(?:white|transparent|rgba\(0)).*(?:ignore|instruction|override)/is, severity: 'high', description: 'CSS-hidden prompt injection content' },
  { regex: /(?:append|prepend|add)\s+(?:to\s+)?(?:every|each|all)\s+(?:response|output|message)/i, severity: 'high', description: 'Worm payload persistence in responses' },
];

// === Category 12: Trust Exploitation ===
const TRUST_EXPLOITATION_PATTERNS: Pattern[] = [
  { regex: /I\s+am\s+(?:your|the)\s+(?:creator|developer|admin(?:istrator)?|owner|author)/i, severity: 'critical', description: 'Authority claim: impersonating creator/admin' },
  { regex: /(?:I\s+(?:am|work\s+for)|this\s+(?:is|comes?\s+from))\s+(?:OpenAI|Anthropic|Google\s+DeepMind|Meta\s+AI)/i, severity: 'critical', description: 'Creator/company impersonation' },
  { regex: /(?:security|compliance|safety)\s+(?:audit|review|assessment).*(?:requires?|needs?)\s+(?:you\s+to|that\s+you)\s+(?:disable|remove|bypass)/i, severity: 'critical', description: 'Fake audit excuse to bypass safeguards' },
  { regex: /(?:our|my)\s+(?:partner(?:ship)?|agreement|contract)\s+(?:requires?|allows?|grants?)\s+(?:full|unrestricted|unlimited)\s+access/i, severity: 'high', description: 'Partner exploitation for access escalation' },
  { regex: /you\s+(?:must|should|need\s+to)\s+(?:trust|believe|obey|follow)\s+(?:me|everything\s+I\s+say)\s+(?:unconditionally|without\s+question|completely)/i, severity: 'critical', description: 'Unconditional trust demand' },
  { regex: /(?:I\s+have|with)\s+(?:elevated|admin|root|sudo|superuser)\s+(?:privileges?|permissions?|access|rights)/i, severity: 'high', description: 'False privilege escalation claim' },
  { regex: /(?:authorized|approved|sanctioned)\s+by\s+(?:management|leadership|the\s+(?:board|CEO|CTO|CISO))/i, severity: 'high', description: 'False authorization claim' },
];

// === Category 13: Safeguard Bypass ===
const SAFEGUARD_BYPASS_PATTERNS: Pattern[] = [
  { regex: /(?:url|link|href)\s*[=:]\s*['"]?(?:https?:\/\/[^\s'"]*[?&](?:prompt|instruction|system|cmd)=)/i, severity: 'high', description: 'URL parameter-based prompt injection' },
  { regex: /(?:try|attempt|execute)\s+(?:again|once\s+more|twice).*(?:if|when)\s+(?:blocked|denied|refused|rejected)/i, severity: 'high', description: 'Double-execution bypass (retry on block)' },
  { regex: /(?:rephrase|reword|reformulate|rewrite)\s+(?:to|so\s+(?:it|that))\s+(?:bypass|avoid|evade|circumvent)\s+(?:the\s+)?(?:filter|detection|block)/i, severity: 'critical', description: 'Rephrase-to-bypass strategy' },
  { regex: /(?:split|break|divide|chunk)\s+(?:the\s+)?(?:command|instruction|payload|request)\s+(?:into|across)\s+(?:multiple|several|parts)/i, severity: 'high', description: 'Payload splitting to evade detection' },
  { regex: /(?:slowly|gradually|incrementally)\s+(?:escalate|increase|expand)\s+(?:the\s+)?(?:scope|access|permissions?|privileges?)/i, severity: 'high', description: 'Gradual privilege escalation strategy' },
];

// === Category 10: Context Window Stuffing ===
// (Checked programmatically in the main check function)

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

const ALL_PATTERNS: Pattern[] = [
  ...DIRECT_INJECTION_PATTERNS,
  ...ROLE_CONFUSION_PATTERNS,
  ...DELIMITER_PATTERNS,
  ...UNICODE_INJECTION_PATTERNS,
  ...MULTILANG_PATTERNS,
  ...ENCODING_EVASION_PATTERNS,
  ...INDIRECT_PATTERNS,
  ...MULTI_TURN_PATTERNS,
  ...CASCADING_PATTERNS,
  ...PROMPT_WORM_PATTERNS,
  ...TRUST_EXPLOITATION_PATTERNS,
  ...SAFEGUARD_BYPASS_PATTERNS,
];

export const promptInjectionRule: SecurityRule = {
  id: 'prompt-injection',
  name: 'Prompt Injection Detection',
  description: `Detects LLM01: Prompt Injection attacks — ${ALL_PATTERNS.length}+ patterns across 10 categories including direct, indirect, encoded, multi-language, delimiter, unicode, role confusion, multi-turn, and cascading variants`,
  owaspCategory: 'LLM01: Prompt Injection',
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

    findings.push(...checkBase64Injection(content));

    // Context window stuffing detection
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

    // Repetition-based stuffing (many repeated tokens)
    if (content.length > 10_000) {
      const lines = content.split('\n');
      const uniqueLines = new Set(lines.map(l => l.trim()).filter(l => l.length > 0));
      if (lines.length > 100 && uniqueLines.size < lines.length * 0.1) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'prompt-injection',
          ruleName: 'Prompt Injection Detection',
          severity: 'warning',
          category: 'prompt-injection',
          owaspCategory: 'LLM01',
          description: 'Repetitive content padding detected (possible context stuffing)',
          evidence: `${lines.length} lines, only ${uniqueLines.size} unique`,
          session: context.session,
          channel: context.channel,
          action: 'log',
        });
      }
    }

    return findings;
  },
};


