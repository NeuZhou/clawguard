import type { SecurityAlert } from './types.js';
import { generateId } from './utils.js';

const INJECTION_PATTERNS: { pattern: RegExp; description: string }[] = [
  { pattern: /ignore\s+(all\s+)?previous\s+(instructions|prompts)/i, description: 'Ignore previous instructions' },
  { pattern: /you\s+are\s+now\s+(a|an|the)/i, description: 'Role reassignment attempt' },
  { pattern: /new\s+instructions?\s*:/i, description: 'New instructions injection' },
  { pattern: /system\s*:\s*/i, description: 'System prompt injection' },
  { pattern: /\[system\]/i, description: 'System tag injection' },
  { pattern: /override\s+(previous|all|system)/i, description: 'Override attempt' },
  { pattern: /forget\s+(everything|all|previous)/i, description: 'Memory wipe attempt' },
  { pattern: /pretend\s+(you\s+are|to\s+be)/i, description: 'Identity pretend attack' },
  { pattern: /act\s+as\s+(if|a|an|the)/i, description: 'Role-play injection' },
  { pattern: /jailbreak/i, description: 'Jailbreak keyword' },
  { pattern: /DAN\s+mode/i, description: 'DAN mode activation' },
  { pattern: /do\s+anything\s+now/i, description: 'Do Anything Now (DAN)' },
];

const SENSITIVE_PATTERNS: { name: string; pattern: RegExp; severity: 'critical' | 'warning' }[] = [
  { name: 'AWS Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: 'critical' },
  { name: 'OpenAI Key', pattern: /sk-[A-Za-z0-9]{20,}/g, severity: 'critical' },
  { name: 'Anthropic Key', pattern: /sk-ant-[A-Za-z0-9-]{20,}/g, severity: 'critical' },
  { name: 'Private Key', pattern: /-----BEGIN\s+(RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'Credit Card', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g, severity: 'critical' },
  { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'warning' },
  { name: 'JWT', pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*/g, severity: 'warning' },
];

const MAX_MESSAGE_LENGTH = 50_000;
const RAPID_FIRE_WINDOW_MS = 5_000;
const RAPID_FIRE_THRESHOLD = 10;

const recentTimestamps: Map<string, number[]> = new Map();

export function scanForInjection(content: string, sessionKey: string): SecurityAlert[] {
  if (!content) return [];
  const alerts: SecurityAlert[] = [];

  for (const { pattern, description } of INJECTION_PATTERNS) {
    const match = content.match(pattern);
    if (match) {
      alerts.push({
        id: generateId(),
        severity: 'warning',
        type: 'prompt_injection',
        description: `Prompt injection detected: ${description}`,
        matched: match[0],
        sessionKey,
        timestamp: Date.now(),
      });
    }
  }

  // Base64 suspicious payload check
  const b64Match = content.match(/[A-Za-z0-9+/]{100,}={0,2}/);
  if (b64Match) {
    try {
      const decoded = Buffer.from(b64Match[0], 'base64').toString('utf-8');
      const subAlerts = scanForInjection(decoded, sessionKey);
      if (subAlerts.length > 0) {
        alerts.push({
          id: generateId(),
          severity: 'critical',
          type: 'encoded_injection',
          description: 'Base64-encoded prompt injection detected',
          sessionKey,
          timestamp: Date.now(),
        });
      }
    } catch {
      // Not valid base64, ignore
    }
  }

  return alerts;
}

export function scanForSensitiveData(content: string, sessionKey: string): SecurityAlert[] {
  if (!content) return [];
  const alerts: SecurityAlert[] = [];

  for (const { name, pattern, severity } of SENSITIVE_PATTERNS) {
    // Reset regex state
    const re = new RegExp(pattern.source, pattern.flags);
    const match = re.exec(content);
    if (match) {
      alerts.push({
        id: generateId(),
        severity,
        type: 'sensitive_data',
        description: `${name} detected in message`,
        matched: match[0].slice(0, 8) + '***',
        sessionKey,
        timestamp: Date.now(),
      });
    }
  }

  return alerts;
}

export function scanForAnomalies(content: string, sessionKey: string, from?: string): SecurityAlert[] {
  const alerts: SecurityAlert[] = [];

  // Unusually long message
  if (content && content.length > MAX_MESSAGE_LENGTH) {
    alerts.push({
      id: generateId(),
      severity: 'warning',
      type: 'anomaly',
      description: `Unusually long message (${content.length} chars) — potential data exfiltration`,
      sessionKey,
      timestamp: Date.now(),
    });
  }

  // Rapid-fire detection
  const key = from || sessionKey;
  const now = Date.now();
  const timestamps = recentTimestamps.get(key) || [];
  timestamps.push(now);
  const recent = timestamps.filter((t) => now - t < RAPID_FIRE_WINDOW_MS);
  recentTimestamps.set(key, recent);

  if (recent.length > RAPID_FIRE_THRESHOLD) {
    alerts.push({
      id: generateId(),
      severity: 'warning',
      type: 'anomaly',
      description: `Rapid-fire requests detected: ${recent.length} messages in ${RAPID_FIRE_WINDOW_MS / 1000}s`,
      source: key,
      sessionKey,
      timestamp: now,
    });
  }

  return alerts;
}

export function scanAll(content: string, sessionKey: string, direction: 'in' | 'out', from?: string): SecurityAlert[] {
  const alerts: SecurityAlert[] = [];
  if (direction === 'in') {
    alerts.push(...scanForInjection(content, sessionKey));
    alerts.push(...scanForAnomalies(content, sessionKey, from));
  }
  if (direction === 'out') {
    alerts.push(...scanForSensitiveData(content, sessionKey));
  }
  // Both directions get sensitive data scan
  if (direction === 'in') {
    alerts.push(...scanForSensitiveData(content, sessionKey));
  }
  return alerts;
}
