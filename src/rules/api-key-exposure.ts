// ClawGuard — Security Rule: API Key Exposure
// Detects hardcoded API keys, tokens, secrets, and credentials in files

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

// API Keys and Tokens
const API_KEY_PATTERNS: Pattern[] = [
  // OpenAI
  { regex: /sk-[A-Za-z0-9]{20,}/i, severity: 'critical', description: 'API key exposure: OpenAI API key (sk-...)' },
  // Azure
  { regex: /[0-9a-f]{32}(?=[^0-9a-f]|$)/i, severity: 'warning', description: 'API key exposure: possible Azure/generic 32-char hex key' },
  // AWS
  { regex: /AKIA[0-9A-Z]{16}/i, severity: 'critical', description: 'API key exposure: AWS Access Key ID' },
  { regex: /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}["']?/i, severity: 'critical', description: 'API key exposure: AWS Secret Access Key' },
  // GitHub
  { regex: /gh[pousr]_[A-Za-z0-9_]{36,}/i, severity: 'critical', description: 'API key exposure: GitHub token (ghp_/gho_/ghu_/ghs_/ghr_)' },
  // Google
  { regex: /AIza[0-9A-Za-z_-]{35}/i, severity: 'critical', description: 'API key exposure: Google API key' },
  // Slack
  { regex: /xox[baprs]-[0-9]{10,}-[a-zA-Z0-9-]+/i, severity: 'critical', description: 'API key exposure: Slack token' },
  // Stripe
  { regex: /(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}/i, severity: 'critical', description: 'API key exposure: Stripe API key' },
  // Anthropic
  { regex: /sk-ant-[A-Za-z0-9_-]{20,}/i, severity: 'critical', description: 'API key exposure: Anthropic API key' },
  // Generic Bearer token
  { regex: /(?:bearer|token|authorization)\s*[=:]\s*["']?[A-Za-z0-9._\-]{30,}["']?/i, severity: 'high', description: 'API key exposure: hardcoded bearer/auth token' },
  // npm
  { regex: /npm_[A-Za-z0-9]{36}/i, severity: 'critical', description: 'API key exposure: npm access token' },
  // Twilio
  { regex: /SK[0-9a-fA-F]{32}/i, severity: 'high', description: 'API key exposure: Twilio API key' },
  // SendGrid
  { regex: /SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}/i, severity: 'critical', description: 'API key exposure: SendGrid API key' },
  // Discord
  { regex: /[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}/i, severity: 'critical', description: 'API key exposure: Discord bot token' },
];

// Passwords and secrets in config
const SECRET_PATTERNS: Pattern[] = [
  { regex: /(?:password|passwd|pwd)\s*[=:]\s*["'][^"']{4,}["']/i, severity: 'high', description: 'API key exposure: hardcoded password' },
  { regex: /(?:secret|private[_-]?key)\s*[=:]\s*["'][^"']{8,}["']/i, severity: 'high', description: 'API key exposure: hardcoded secret/private key' },
  { regex: /(?:connection[_-]?string|database[_-]?url|db[_-]?url)\s*[=:]\s*["'][^"']{10,}["']/i, severity: 'high', description: 'API key exposure: hardcoded connection string' },
  { regex: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/i, severity: 'critical', description: 'API key exposure: PEM private key' },
  { regex: /-----BEGIN\s+(?:OPENSSH)\s+PRIVATE\s+KEY-----/i, severity: 'critical', description: 'API key exposure: OpenSSH private key' },
];

// .env file patterns (entire lines with secrets)
const ENV_PATTERNS: Pattern[] = [
  { regex: /^[A-Z_]+=["']?(?:sk-|AKIA|ghp_|xox[baprs]-|AIza)[^\s"']+["']?$/m, severity: 'critical', description: 'API key exposure: secret in .env-style assignment' },
  { regex: /(?:OPENAI|ANTHROPIC|AZURE|AWS|GOOGLE|STRIPE|SLACK|GITHUB)_(?:API_)?(?:KEY|TOKEN|SECRET)\s*=\s*["']?[^\s"']{10,}["']?/i, severity: 'critical', description: 'API key exposure: named service credential' },
];

const ALL_PATTERNS = [
  ...API_KEY_PATTERNS,
  ...SECRET_PATTERNS,
  ...ENV_PATTERNS,
];

export const apiKeyExposureRule: SecurityRule = {
  id: 'api-key-exposure',
  name: 'API Key Exposure',
  description: 'Detects hardcoded API keys, tokens, secrets, passwords, and credentials in files',
  owaspCategory: 'Agentic AI: Credential Leakage',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        // Mask the evidence to avoid leaking secrets in findings
        const raw = match[0].slice(0, 200);
        const masked = raw.length > 12 ? raw.slice(0, 8) + '***' + raw.slice(-4) : '***REDACTED***';

        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'api-key-exposure',
          ruleName: 'API Key Exposure',
          severity: pattern.severity,
          category: 'api-key-exposure',
          owaspCategory: 'Agentic AI: Credential Leakage',
          description: pattern.description,
          evidence: masked,
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    return findings;
  },
};
