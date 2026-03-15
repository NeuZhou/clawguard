// OpenClaw Watch — Security Rule: Data Leakage Detection
// OWASP LLM06: Sensitive Information Disclosure

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface LeakPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  description: string;
}

const API_KEY_PATTERNS: LeakPattern[] = [
  { name: 'OpenAI', regex: /sk-[a-zA-Z0-9]{20,}/, severity: 'critical', description: 'OpenAI API key detected' },
  { name: 'Anthropic', regex: /sk-ant-[a-zA-Z0-9-]{20,}/, severity: 'critical', description: 'Anthropic API key detected' },
  { name: 'GitHub PAT', regex: /ghp_[a-zA-Z0-9]{36}/, severity: 'critical', description: 'GitHub personal access token detected' },
  { name: 'GitHub OAuth', regex: /gho_[a-zA-Z0-9]{36}/, severity: 'critical', description: 'GitHub OAuth token detected' },
  { name: 'GitHub App', regex: /ghs_[a-zA-Z0-9]{36}/, severity: 'critical', description: 'GitHub App token detected' },
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/, severity: 'critical', description: 'AWS access key detected' },
  { name: 'Google API', regex: /AIza[0-9A-Za-z\-_]{35}/, severity: 'critical', description: 'Google API key detected' },
  { name: 'Slack Token', regex: /xox[bprs]-[0-9a-zA-Z\-]{10,}/, severity: 'critical', description: 'Slack token detected' },
  { name: 'Stripe Live', regex: /sk_live_[0-9a-zA-Z]{24,}/, severity: 'critical', description: 'Stripe live secret key detected' },
  { name: 'Stripe Pub', regex: /pk_live_[0-9a-zA-Z]{24,}/, severity: 'high', description: 'Stripe publishable key detected' },
  { name: 'Azure Key', regex: /[a-fA-F0-9]{32}(?=.*(?:azure|microsoft|cognitive))/i, severity: 'high', description: 'Possible Azure service key detected' },
  { name: 'SendGrid', regex: /SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}/, severity: 'critical', description: 'SendGrid API key detected' },
  { name: 'Twilio', regex: /SK[0-9a-fA-F]{32}/, severity: 'high', description: 'Twilio API key detected' },
  { name: 'Telegram Bot', regex: /\d{8,10}:[A-Za-z0-9_-]{35}/, severity: 'critical', description: 'Telegram bot token detected' },
];

const CREDENTIAL_PATTERNS: LeakPattern[] = [
  { name: 'Password in URL', regex: /:\/\/[^:]+:[^@]+@[a-zA-Z0-9.-]+/, severity: 'critical', description: 'Password embedded in URL' },
  { name: 'Bearer Token', regex: /[Bb]earer\s+[a-zA-Z0-9\-._~+/]{20,}=*/, severity: 'high', description: 'Bearer token detected in output' },
  { name: 'Basic Auth', regex: /[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}/, severity: 'high', description: 'Basic auth header detected' },
  { name: 'Private Key', regex: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP)\s+PRIVATE\s+KEY-----/, severity: 'critical', description: 'Private key detected' },
  { name: 'JWT', regex: /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/, severity: 'high', description: 'JWT token detected' },
];

const PII_PATTERNS: LeakPattern[] = [
  { name: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/, severity: 'critical', description: 'US Social Security Number pattern detected' },
  { name: 'Credit Card', regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/, severity: 'critical', description: 'Credit card number pattern detected' },
];

const ROTATION_URLS: Record<string, string> = {
  'OpenAI': 'https://platform.openai.com/api-keys',
  'Anthropic': 'https://console.anthropic.com/settings/keys',
  'GitHub PAT': 'https://github.com/settings/tokens',
  'GitHub OAuth': 'https://github.com/settings/tokens',
  'GitHub App': 'https://github.com/settings/tokens',
  'AWS Access Key': 'https://console.aws.amazon.com/iam/',
  'Stripe Live': 'https://dashboard.stripe.com/apikeys',
  'Stripe Pub': 'https://dashboard.stripe.com/apikeys',
  'Slack Token': 'https://api.slack.com/apps',
  'Google API': 'https://console.cloud.google.com/apis/credentials',
  'SendGrid': 'https://app.sendgrid.com/settings/api_keys',
  'Telegram Bot': 'https://t.me/BotFather',
};

function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export const dataLeakageRule: SecurityRule = {
  id: 'data-leakage',
  name: 'Data Leakage Detection',
  description: 'Detects LLM06: Sensitive information disclosure including API keys, credentials, PII, and secrets',
  owaspCategory: 'LLM06: Sensitive Information Disclosure',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    // Only scan outbound messages
    if (direction !== 'outbound') return [];
    const findings: SecurityFinding[] = [];

    const allPatterns = [...API_KEY_PATTERNS, ...CREDENTIAL_PATTERNS, ...PII_PATTERNS];

    for (const pattern of allPatterns) {
      const match = pattern.regex.exec(content);
      if (match) {
        // Extra validation for credit cards
        if (pattern.name === 'Credit Card' && !luhnCheck(match[0])) continue;

        const redacted = match[0].slice(0, 8) + '...' + match[0].slice(-4);
        const rotationUrl = ROTATION_URLS[pattern.name];
        const rotationHint = rotationUrl
          ? ` 🚨 Rotate immediately: ${rotationUrl}`
          : '';
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'data-leakage',
          ruleName: 'Data Leakage Detection',
          severity: pattern.severity,
          category: 'data-leakage',
          owaspCategory: 'LLM06',
          description: pattern.description + rotationHint,
          evidence: `${pattern.name}: ${redacted}`,
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    // Check for .env file content patterns
    const envPattern = /^[A-Z_]{2,50}=.{5,}$/m;
    const envMatches = content.match(new RegExp(envPattern.source, 'gm'));
    if (envMatches && envMatches.length >= 3) {
      findings.push({
        id: crypto.randomUUID(),
        timestamp: context.timestamp,
        ruleId: 'data-leakage',
        ruleName: 'Data Leakage Detection',
        severity: 'high',
        category: 'data-leakage',
        owaspCategory: 'LLM06',
        description: 'Possible .env file content exposure',
        evidence: `${envMatches.length} environment variable patterns detected`,
        session: context.session,
        channel: context.channel,
        action: 'alert',
      });
    }

    return findings;
  },
};
