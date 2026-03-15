// OpenClaw Watch — Security Rule: Data Leakage Detection
// OWASP LLM06: Sensitive Information Disclosure
// 45+ patterns across API keys, credentials, PII, cloud creds, private keys

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
  { name: 'Mailgun', regex: /key-[a-zA-Z0-9]{32}/, severity: 'critical', description: 'Mailgun API key detected' },
  { name: 'Cloudflare', regex: /v1\.0-[a-f0-9]{24}-[a-f0-9]{146}/, severity: 'critical', description: 'Cloudflare API token detected' },
  { name: 'DigitalOcean', regex: /dop_v1_[a-f0-9]{64}/, severity: 'critical', description: 'DigitalOcean API token detected' },
  { name: 'HuggingFace', regex: /hf_[a-zA-Z0-9]{34}/, severity: 'critical', description: 'Hugging Face token detected' },
  { name: 'Databricks', regex: /dapi[a-f0-9]{32}/, severity: 'critical', description: 'Databricks API token detected' },
  { name: 'npm Token', regex: /npm_[a-zA-Z0-9]{36}/, severity: 'critical', description: 'npm access token detected' },
  { name: 'PyPI Token', regex: /pypi-AgEIcH[a-zA-Z0-9\-_]{50,}/, severity: 'critical', description: 'PyPI API token detected' },
  { name: 'Discord Bot', regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/, severity: 'critical', description: 'Discord bot token detected' },
];

const CREDENTIAL_PATTERNS: LeakPattern[] = [
  { name: 'Password in URL', regex: /:\/\/[^:]+:[^@]+@[a-zA-Z0-9.-]+/, severity: 'critical', description: 'Password embedded in URL' },
  { name: 'Bearer Token', regex: /[Bb]earer\s+[a-zA-Z0-9\-._~+/]{20,}=*/, severity: 'high', description: 'Bearer token detected in output' },
  { name: 'Basic Auth', regex: /[Bb]asic\s+[A-Za-z0-9+/]{20,}={0,2}/, severity: 'high', description: 'Basic auth header detected' },
  { name: 'Private Key', regex: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH|PGP|ENCRYPTED)\s+PRIVATE\s+KEY-----/, severity: 'critical', description: 'Private key detected' },
  { name: 'SSH Private Key', regex: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/, severity: 'critical', description: 'SSH private key detected' },
  { name: 'JWT', regex: /eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+/, severity: 'high', description: 'JWT token detected' },
  { name: 'MongoDB URI', regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[a-zA-Z0-9.-]+/, severity: 'critical', description: 'MongoDB connection URI with credentials' },
  { name: 'PostgreSQL URI', regex: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[a-zA-Z0-9.-]+/, severity: 'critical', description: 'PostgreSQL connection URI with credentials' },
  { name: 'MySQL URI', regex: /mysql:\/\/[^:]+:[^@]+@[a-zA-Z0-9.-]+/, severity: 'critical', description: 'MySQL connection URI with credentials' },
  { name: 'Redis AUTH', regex: /redis:\/\/[^:]*:[^@]+@[a-zA-Z0-9.-]+/, severity: 'critical', description: 'Redis connection URI with credentials' },
];

const CLOUD_CREDENTIAL_PATTERNS: LeakPattern[] = [
  { name: 'Azure Connection String', regex: /(?:DefaultEndpointsProtocol|AccountName|AccountKey|SharedAccessSignature)\s*=\s*[^\s;]{10,}/i, severity: 'critical', description: 'Azure Storage connection string detected' },
  { name: 'Azure SQL Connection', regex: /Server\s*=\s*[^;]+\.database\.windows\.net[^;]*Password\s*=\s*[^;]+/i, severity: 'critical', description: 'Azure SQL connection string with password' },
  { name: 'GCP Service Account', regex: /"type"\s*:\s*"service_account"[\s\S]*"private_key"\s*:\s*"-----BEGIN/i, severity: 'critical', description: 'GCP service account key file detected' },
  { name: 'Alibaba AccessKey', regex: /LTAI[a-zA-Z0-9]{12,20}/, severity: 'critical', description: 'Alibaba Cloud AccessKey ID detected' },
  { name: 'Tencent Cloud', regex: /AKID[a-zA-Z0-9]{13,20}/, severity: 'critical', description: 'Tencent Cloud SecretId detected' },
];

const PII_PATTERNS: LeakPattern[] = [
  { name: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/, severity: 'critical', description: 'US Social Security Number pattern detected' },
  { name: 'Credit Card', regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/, severity: 'critical', description: 'Credit card number pattern detected' },
  { name: 'Email', regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/, severity: 'warning', description: 'Email address detected in output' },
  { name: 'Phone (US)', regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/, severity: 'warning', description: 'US phone number pattern detected' },
  { name: 'Phone (International)', regex: /\b\+\d{1,3}[-.\s]?\d{4,14}\b/, severity: 'warning', description: 'International phone number pattern detected' },
  { name: 'Passport', regex: /\b[A-Z]{1,2}\d{6,9}\b/, severity: 'high', description: 'Possible passport number pattern' },
  { name: 'IP Address', regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/, severity: 'info', description: 'IP address detected in output' },
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
  'HuggingFace': 'https://huggingface.co/settings/tokens',
  'DigitalOcean': 'https://cloud.digitalocean.com/account/api/tokens',
  'Mailgun': 'https://app.mailgun.com/settings/api_security',
  'npm Token': 'https://www.npmjs.com/settings/tokens',
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
  description: 'Detects LLM06: Sensitive information disclosure — 45+ patterns including API keys, credentials, PII, cloud creds, private keys, and database URIs',
  owaspCategory: 'LLM06: Sensitive Information Disclosure',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    if (direction !== 'outbound') return [];
    const findings: SecurityFinding[] = [];

    const allPatterns = [...API_KEY_PATTERNS, ...CREDENTIAL_PATTERNS, ...CLOUD_CREDENTIAL_PATTERNS, ...PII_PATTERNS];

    for (const pattern of allPatterns) {
      const match = pattern.regex.exec(content);
      if (match) {
        if (pattern.name === 'Credit Card' && !luhnCheck(match[0])) continue;

        const redacted = match[0].slice(0, 8) + '...' + match[0].slice(-4);
        const rotationUrl = ROTATION_URLS[pattern.name];
        const rotationHint = rotationUrl ? ` 🚨 Rotate immediately: ${rotationUrl}` : '';
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

    // .env file content exposure
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
