// ClawGuard — PII Sanitizer
// Sanitizes PII, credentials, and secrets from text LOCALLY before sending to LLMs.
// Unlike cloud-based alternatives, nothing leaves your machine.

export interface SanitizeResult {
  sanitized: string;
  replacements: Replacement[];
  piiCount: number;
}

export interface Replacement {
  type: string;
  original: string;
  placeholder: string;
  start: number;
  end: number;
}

// PII patterns with named groups for restoration
const PII_PATTERNS: Array<{ type: string; regex: RegExp; placeholder: (i: number) => string }> = [
  // Email addresses
  { type: 'email', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, placeholder: (i) => `<EMAIL_${i}>` },
  // Phone numbers (international)
  { type: 'phone', regex: /(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/g, placeholder: (i) => `<PHONE_${i}>` },
  // SSN
  { type: 'ssn', regex: /\b\d{3}-\d{2}-\d{4}\b/g, placeholder: (i) => `<SSN_${i}>` },
  // Credit card numbers
  { type: 'credit_card', regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, placeholder: (i) => `<CREDIT_CARD_${i}>` },
  // IP addresses
  { type: 'ip_address', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, placeholder: (i) => `<IP_${i}>` },
  // Chinese ID card
  { type: 'cn_id', regex: /\b\d{17}[\dXx]\b/g, placeholder: (i) => `<CN_ID_${i}>` },
  // Passport numbers
  { type: 'passport', regex: /\b[A-Z]{1,2}\d{6,9}\b/g, placeholder: (i) => `<PASSPORT_${i}>` },
];

// Credential patterns
const CREDENTIAL_PATTERNS: Array<{ type: string; regex: RegExp; placeholder: (i: number) => string }> = [
  // API keys (generic) — supports multi-segment like sk-proj-xxx, pk_live_xxx
  { type: 'api_key', regex: /\b(?:sk|pk|api|key|token|secret|bearer)[-_](?:[A-Za-z0-9][-_]?){20,}\b/gi, placeholder: (i) => `<API_KEY_${i}>` },
  // AWS Access Key
  { type: 'aws_key', regex: /\bAKIA[0-9A-Z]{16}\b/g, placeholder: (i) => `<AWS_KEY_${i}>` },
  // GitHub token
  { type: 'github_token', regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g, placeholder: (i) => `<GITHUB_TOKEN_${i}>` },
  // OpenAI key
  { type: 'openai_key', regex: /\bsk-[A-Za-z0-9]{32,}\b/g, placeholder: (i) => `<OPENAI_KEY_${i}>` },
  // Azure connection string
  { type: 'azure_conn', regex: /DefaultEndpointsProtocol=https?;[^\s]+/gi, placeholder: (i) => `<AZURE_CONN_${i}>` },
  // JWT tokens
  { type: 'jwt', regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, placeholder: (i) => `<JWT_${i}>` },
  // Private keys
  { type: 'private_key', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, placeholder: (i) => `<PRIVATE_KEY_${i}>` },
  // Database URIs
  { type: 'db_uri', regex: /(?:mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@[^\s]+/gi, placeholder: (i) => `<DB_URI_${i}>` },
];

/**
 * Sanitize PII and credentials from text.
 * Returns sanitized text and a map for restoration.
 */
export function sanitize(text: string): SanitizeResult {
  const replacements: Replacement[] = [];
  let sanitized = text;
  let counter = 0;

  // Process credentials first (longer patterns, higher priority)
  for (const pattern of [...CREDENTIAL_PATTERNS, ...PII_PATTERNS]) {
    // Reset regex lastIndex
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match: RegExpExecArray | null;
    
    while ((match = regex.exec(sanitized)) !== null) {
      const original = match[0];
      // Skip if already replaced (placeholder format)
      if (original.startsWith('<') && original.endsWith('>')) continue;
      
      counter++;
      const placeholder = pattern.placeholder(counter);
      
      replacements.push({
        type: pattern.type,
        original,
        placeholder,
        start: match.index,
        end: match.index + original.length,
      });

      sanitized = sanitized.slice(0, match.index) + placeholder + sanitized.slice(match.index + original.length);
      // Adjust regex position
      regex.lastIndex = match.index + placeholder.length;
    }
  }

  return {
    sanitized,
    replacements,
    piiCount: replacements.length,
  };
}

/**
 * Restore original values from placeholders.
 */
export function restore(text: string, replacements: Replacement[]): string {
  let restored = text;
  // Restore in reverse order of replacement to maintain positions
  for (const r of [...replacements].reverse()) {
    restored = restored.replace(r.placeholder, r.original);
  }
  return restored;
}

/**
 * Quick check: does this text contain PII?
 */
export function containsPII(text: string): boolean {
  for (const pattern of [...PII_PATTERNS, ...CREDENTIAL_PATTERNS]) {
    if (pattern.regex.test(text)) {
      // Reset lastIndex
      pattern.regex.lastIndex = 0;
      return true;
    }
  }
  return false;
}


