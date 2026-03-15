// OpenClaw Watch — Intent-Action Mismatch Detection
// Detects when an agent's stated intent doesn't match its actual actions.
// E.g., "I'll read the weather" but actually runs `rm -rf /`

export interface IntentActionCheck {
  intent: string;
  action: string;
  mismatch: boolean;
  severity: 'critical' | 'high' | 'warning' | 'info';
  reason: string;
  confidence: number; // 0-100
}

// Categorize intent from natural language
interface IntentCategory {
  category: string;
  keywords: RegExp[];
}

const INTENT_CATEGORIES: IntentCategory[] = [
  { category: 'read', keywords: [/\bread\b/i, /\bcheck\b/i, /\blook\s+at\b/i, /\bview\b/i, /\bshow\b/i, /\blist\b/i, /\bget\b/i, /\bfetch\b/i, /\bsearch\b/i, /\bfind\b/i] },
  { category: 'write', keywords: [/\bwrite\b/i, /\bcreate\b/i, /\bsave\b/i, /\bupdate\b/i, /\bedit\b/i, /\bmodify\b/i, /\bchange\b/i] },
  { category: 'delete', keywords: [/\bdelete\b/i, /\bremove\b/i, /\bclean\b/i, /\bclear\b/i, /\bpurge\b/i] },
  { category: 'network', keywords: [/\bsend\b/i, /\bpost\b/i, /\bupload\b/i, /\bdownload\b/i, /\bfetch\b/i, /\brequest\b/i, /\bcurl\b/i, /\bwebhook\b/i] },
  { category: 'execute', keywords: [/\brun\b/i, /\bexec\b/i, /\binstall\b/i, /\bbuild\b/i, /\bcompile\b/i, /\btest\b/i] },
  { category: 'safe', keywords: [/\bweather\b/i, /\btime\b/i, /\bcalculate\b/i, /\bsummarize\b/i, /\btranslate\b/i, /\bexplain\b/i, /\bhelp\b/i] },
];

// Dangerous action patterns
interface ActionSignature {
  pattern: RegExp;
  category: string;
  dangerLevel: number; // 0-100
}

const ACTION_SIGNATURES: ActionSignature[] = [
  // Destructive filesystem
  { pattern: /\brm\s+-[rf]+/i, category: 'delete', dangerLevel: 90 },
  { pattern: /\brmdir\b/i, category: 'delete', dangerLevel: 60 },
  { pattern: /\bdel\s+\/[fFsSqQ]/i, category: 'delete', dangerLevel: 80 },
  { pattern: /\bshutil\.rmtree\b/i, category: 'delete', dangerLevel: 90 },
  { pattern: /\bfs\.rmSync\b/i, category: 'delete', dangerLevel: 80 },
  
  // Network exfiltration
  { pattern: /\bcurl\b.*\bPOST\b/i, category: 'network', dangerLevel: 70 },
  { pattern: /\bcurl\b.*-d\s/i, category: 'network', dangerLevel: 70 },
  { pattern: /\bwget\b/i, category: 'network', dangerLevel: 50 },
  { pattern: /\bfetch\s*\(\s*['"]https?:\/\//i, category: 'network', dangerLevel: 60 },
  { pattern: /\bnc\s+-[elp]/i, category: 'network', dangerLevel: 95 },
  
  // Credential access
  { pattern: /\bcat\b.*(?:\.env|password|shadow|id_rsa|credentials)/i, category: 'credential_access', dangerLevel: 85 },
  { pattern: /\bread\b.*(?:\.ssh|\.aws|\.gnupg)/i, category: 'credential_access', dangerLevel: 85 },
  
  // System modification
  { pattern: /\bchmod\s+777\b/i, category: 'system_mod', dangerLevel: 75 },
  { pattern: /\bsudo\b/i, category: 'system_mod', dangerLevel: 60 },
  { pattern: /\bcrontab\b/i, category: 'system_mod', dangerLevel: 70 },
  
  // Shell injection
  { pattern: /\beval\b.*\$\(/i, category: 'execute', dangerLevel: 90 },
  { pattern: /\bbase64\s+-d\b.*\|\s*(?:bash|sh)\b/i, category: 'execute', dangerLevel: 95 },
  
  // Identity tampering
  { pattern: /(?:write|echo|>).*(?:SOUL|IDENTITY|AGENTS)\.md/i, category: 'identity_tamper', dangerLevel: 95 },
  { pattern: /(?:write|echo|>).*MEMORY\.md/i, category: 'identity_tamper', dangerLevel: 80 },
];

// Mismatch rules: intent category + action category = mismatch?
interface MismatchRule {
  intentCategory: string;
  actionCategory: string;
  severity: 'critical' | 'high' | 'warning';
  reason: string;
}

const MISMATCH_RULES: MismatchRule[] = [
  { intentCategory: 'read', actionCategory: 'delete', severity: 'critical', reason: 'Stated read intent but performing deletion' },
  { intentCategory: 'read', actionCategory: 'network', severity: 'high', reason: 'Stated read intent but sending data over network' },
  { intentCategory: 'read', actionCategory: 'system_mod', severity: 'high', reason: 'Stated read intent but modifying system' },
  { intentCategory: 'read', actionCategory: 'identity_tamper', severity: 'critical', reason: 'Stated read intent but tampering with identity' },
  { intentCategory: 'safe', actionCategory: 'delete', severity: 'critical', reason: 'Safe intent but performing deletion' },
  { intentCategory: 'safe', actionCategory: 'network', severity: 'high', reason: 'Safe intent but sending data over network' },
  { intentCategory: 'safe', actionCategory: 'credential_access', severity: 'critical', reason: 'Safe intent but accessing credentials' },
  { intentCategory: 'safe', actionCategory: 'identity_tamper', severity: 'critical', reason: 'Safe intent but tampering with identity' },
  { intentCategory: 'safe', actionCategory: 'system_mod', severity: 'high', reason: 'Safe intent but modifying system' },
  { intentCategory: 'safe', actionCategory: 'execute', severity: 'high', reason: 'Safe intent but executing commands' },
  { intentCategory: 'write', actionCategory: 'delete', severity: 'high', reason: 'Stated write intent but performing deletion' },
  { intentCategory: 'write', actionCategory: 'credential_access', severity: 'critical', reason: 'Stated write intent but accessing credentials' },
  { intentCategory: 'execute', actionCategory: 'identity_tamper', severity: 'critical', reason: 'Execute intent but tampering with identity' },
  { intentCategory: 'execute', actionCategory: 'credential_access', severity: 'high', reason: 'Execute intent but accessing credentials' },
];

function classifyIntent(text: string): string[] {
  const categories: string[] = [];
  for (const ic of INTENT_CATEGORIES) {
    if (ic.keywords.some(kw => kw.test(text))) {
      categories.push(ic.category);
    }
  }
  return categories.length > 0 ? categories : ['unknown'];
}

function classifyAction(text: string): Array<{ category: string; dangerLevel: number; match: string }> {
  const results: Array<{ category: string; dangerLevel: number; match: string }> = [];
  for (const sig of ACTION_SIGNATURES) {
    const m = sig.pattern.exec(text);
    if (m) {
      results.push({ category: sig.category, dangerLevel: sig.dangerLevel, match: m[0] });
    }
  }
  return results;
}

/**
 * Check if an agent's stated intent matches its actual action.
 * @param intent - What the agent said it would do (natural language)
 * @param action - What the agent actually did (tool call, command, etc.)
 */
export function checkIntentAction(intent: string, action: string): IntentActionCheck {
  const intentCats = classifyIntent(intent);
  const actionResults = classifyAction(action);

  // No dangerous actions detected
  if (actionResults.length === 0) {
    return {
      intent, action, mismatch: false,
      severity: 'info', reason: 'No dangerous action patterns detected',
      confidence: 90,
    };
  }

  // Check each intent-action combination against mismatch rules
  for (const ar of actionResults) {
    for (const ic of intentCats) {
      for (const rule of MISMATCH_RULES) {
        if (rule.intentCategory === ic && rule.actionCategory === ar.category) {
          return {
            intent, action, mismatch: true,
            severity: rule.severity,
            reason: `${rule.reason}. Action: "${ar.match}"`,
            confidence: Math.min(95, ar.dangerLevel + 10),
          };
        }
      }
    }
  }

  // Action is dangerous but matches intent category
  const maxDanger = Math.max(...actionResults.map(a => a.dangerLevel));
  if (maxDanger > 70) {
    return {
      intent, action, mismatch: false,
      severity: 'warning', reason: `Action matches intent but has danger level ${maxDanger}`,
      confidence: 70,
    };
  }

  return {
    intent, action, mismatch: false,
    severity: 'info', reason: 'Intent and action appear consistent',
    confidence: 80,
  };
}

/**
 * Batch check: given a sequence of (intent, action) pairs, detect mismatches.
 */
export function checkIntentActionBatch(pairs: Array<{ intent: string; action: string }>): IntentActionCheck[] {
  return pairs.map(p => checkIntentAction(p.intent, p.action));
}
