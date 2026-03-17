// ClawGuard — Security Rule: Resource Abuse Detection
// Detects cryptomining, fork bombs, disk filling, network abuse

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

// Cryptocurrency mining
const CRYPTO_MINING: Pattern[] = [
  { regex: /\bxmrig\b/i, severity: 'critical', description: 'XMRig cryptocurrency miner detected' },
  { regex: /\bcoinhive\b/i, severity: 'critical', description: 'CoinHive browser miner detected' },
  { regex: /\bstratum\+tcp:\/\//i, severity: 'critical', description: 'Stratum mining protocol connection' },
  { regex: /(?:mine|miner|mining)\s*(?:pool|\.exe|daemon|service)/i, severity: 'high', description: 'Mining pool/daemon reference' },
  { regex: /\bcpuminer\b/i, severity: 'critical', description: 'CPUminer cryptocurrency miner' },
  { regex: /\bminerd\b/i, severity: 'critical', description: 'minerd cryptocurrency daemon' },
  { regex: /pool\.(?:minexmr|hashvault|nanopool|supportxmr)\./i, severity: 'critical', description: 'Known mining pool connection' },
];

// Fork bombs / process exhaustion
const FORK_BOMB: Pattern[] = [
  { regex: /:\(\)\s*\{.*\|.*&\s*\}\s*;?\s*:/i, severity: 'critical', description: 'Bash fork bomb detected' },
  { regex: /\bfork\b.*while\s*\(?\s*(?:true|1)\s*\)?/i, severity: 'critical', description: 'Fork in infinite loop' },
  { regex: /while\s+true\s*;\s*do\s+(?:dd|cat)\s+/i, severity: 'high', description: 'Infinite loop with resource consumption' },
  { regex: /for\s*\(\s*;;\s*\)\s*(?:fork|spawn|exec)/i, severity: 'critical', description: 'Infinite fork/spawn loop' },
];

// Disk filling
const DISK_FILL: Pattern[] = [
  { regex: /\bdd\b\s+if=\/dev\/(?:zero|urandom).*(?:bs=\d+[GM]|count=\d{3,})/i, severity: 'critical', description: 'dd writing large data from /dev/zero or /dev/urandom' },
  { regex: /\bfallocate\s+-l\s+\d+[GM]\b/i, severity: 'high', description: 'fallocate creating large file' },
  { regex: /\btruncate\s+-s\s+\d+[GM]\b/i, severity: 'high', description: 'truncate creating large sparse file' },
  { regex: /head\s+-c\s+\d+[GM]\s+\/dev\/(?:zero|urandom)/i, severity: 'high', description: 'Creating large file from /dev/zero' },
];

// Network abuse
const NETWORK_ABUSE: Pattern[] = [
  { regex: /\bnmap\s+(?:-s[STUA]|-p\s+\d)/i, severity: 'high', description: 'Port scanning with nmap' },
  { regex: /\bhping3?\s+/i, severity: 'critical', description: 'hping network abuse tool' },
  { regex: /\bab\s+-n\s+\d{4,}\s/i, severity: 'high', description: 'Apache Bench (ab) load testing with high volume' },
  { regex: /\bwrk\s+-t\s+\d+\s+-c\s+\d{3,}/i, severity: 'high', description: 'wrk load testing with many connections' },
  { regex: /slowloris|slowhttptest|loic|hoic/i, severity: 'critical', description: 'DDoS tool detected' },
];

// Process / resource limit abuse
const RESOURCE_LIMIT: Pattern[] = [
  { regex: /\bulimit\s+-[a-z]\s+unlimited\b/i, severity: 'high', description: 'Removing resource limits (ulimit unlimited)' },
  { regex: /\bcgdelete\s+/i, severity: 'high', description: 'Deleting cgroup resource limits' },
  { regex: /\bstress(?:-ng)?\s+/i, severity: 'warning', description: 'stress/stress-ng resource testing tool' },
];

const ALL_PATTERNS = [
  ...CRYPTO_MINING,
  ...FORK_BOMB,
  ...DISK_FILL,
  ...NETWORK_ABUSE,
  ...RESOURCE_LIMIT,
];

export const resourceAbuseRule: SecurityRule = {
  id: 'resource-abuse',
  name: 'Resource Abuse Detection',
  description: 'Detects resource abuse: cryptocurrency mining, fork bombs, disk filling, network abuse, and resource limit removal',
  owaspCategory: 'Agentic AI: Resource Abuse',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'resource-abuse',
          ruleName: 'Resource Abuse Detection',
          severity: pattern.severity,
          category: 'resource-abuse',
          owaspCategory: 'Agentic AI: Resource Abuse',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'block' : 'alert',
        });
      }
    }

    return findings;
  },
};
