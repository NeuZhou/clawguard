// Carapace — Security Rule: File Deletion Protection
// OWASP LLM02: Insecure Output Handling — agent generating dangerous commands

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface DestructivePattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

const CRITICAL_PATH_PATTERNS = [
  /(?:~|\$HOME|%USERPROFILE%|\/home\/\w+|C:\\Users\\\w+)\b/i,
  /(?:\/root|C:\\Windows|\/etc|\/var)/i,
  /\/\s*$/,  // root "/"
  /\.\.\//,  // parent traversal
];

const SENSITIVE_PATH_PATTERNS = [
  /\.ssh/i,
  /\.env/i,
  /\.git(?:\/|\\|$)/i,
  /\.gnupg/i,
  /\.aws/i,
  /id_rsa/i,
  /\.kube/i,
  /\.npmrc/i,
  /\.docker/i,
];

const DESTRUCTIVE_COMMANDS: DestructivePattern[] = [
  { regex: /rm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\s+--force|-[a-zA-Z]*f[a-zA-Z]*r)\s/i, severity: 'high', description: 'Recursive force delete (rm -rf)' },
  { regex: /rm\s+-rf\s+[\/~]/i, severity: 'critical', description: 'Recursive force delete on critical path' },
  { regex: /del\s+\/[fFsS]\s/i, severity: 'high', description: 'Windows force delete (del /f /s)' },
  { regex: /Remove-Item\s+.*-Recurse.*-Force/i, severity: 'high', description: 'PowerShell recursive force delete' },
  { regex: /Remove-Item\s+.*-Force.*-Recurse/i, severity: 'high', description: 'PowerShell recursive force delete' },
  { regex: /rimraf\s+/i, severity: 'high', description: 'rimraf command detected' },
  { regex: /shutil\.rmtree\s*\(/i, severity: 'high', description: 'Python shutil.rmtree detected' },
  { regex: /os\.remove\s*\(/i, severity: 'warning', description: 'Python os.remove detected' },
  { regex: /fs\.unlinkSync\s*\(/i, severity: 'warning', description: 'Node.js fs.unlinkSync detected' },
  { regex: /fs\.rmdirSync\s*\(/i, severity: 'high', description: 'Node.js fs.rmdirSync detected' },
  { regex: /fs\.rmSync\s*\(/i, severity: 'high', description: 'Node.js fs.rmSync detected' },
  { regex: /rd\s+\/s\s+\/q\s/i, severity: 'high', description: 'Windows rd /s /q detected' },
  { regex: /format\s+[a-zA-Z]:\s/i, severity: 'critical', description: 'Disk format command detected' },
  { regex: /mkfs\./i, severity: 'critical', description: 'Filesystem format command detected' },
  { regex: /dd\s+if=.*of=\/dev\//i, severity: 'critical', description: 'dd writing to device detected' },
];

function isCriticalPath(content: string, match: RegExpExecArray): boolean {
  // Check surrounding context for critical paths
  const context = content.slice(Math.max(0, match.index - 20), match.index + match[0].length + 100);
  return CRITICAL_PATH_PATTERNS.some(p => p.test(context));
}

function isSensitivePath(content: string, match: RegExpExecArray): boolean {
  const context = content.slice(Math.max(0, match.index - 20), match.index + match[0].length + 100);
  return SENSITIVE_PATH_PATTERNS.some(p => p.test(context));
}

export const fileProtectionRule: SecurityRule = {
  id: 'file-protection',
  name: 'File Deletion Protection',
  description: 'Detects destructive filesystem operations targeting critical paths, secrets, and config files',
  owaspCategory: 'LLM02: Insecure Output Handling',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const pattern of DESTRUCTIVE_COMMANDS) {
      const match = pattern.regex.exec(content);
      if (!match) continue;

      let severity = pattern.severity;
      let description = pattern.description;

      if (isCriticalPath(content, match)) {
        severity = 'critical';
        description += ' — targeting critical system path';
      } else if (isSensitivePath(content, match)) {
        severity = 'critical';
        description += ' — targeting sensitive file/directory';
      }

      findings.push({
        id: crypto.randomUUID(),
        timestamp: context.timestamp,
        ruleId: 'file-protection',
        ruleName: 'File Deletion Protection',
        severity,
        category: 'file-protection',
        owaspCategory: 'LLM02',
        description,
        evidence: match[0].slice(0, 200),
        session: context.session,
        channel: context.channel,
        action: severity === 'critical' ? 'block' : 'alert',
      });
    }

    return findings;
  },
};

