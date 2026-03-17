// ClawGuard — Security Rule: Privilege Escalation Detection
// OWASP LLM02: Insecure Output Handling — Agent performing privilege escalation

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

// Unix privilege escalation
const UNIX_PRIV_ESC: Pattern[] = [
  { regex: /\bsudo\s+(?:-[isSEHPu]\s+)*(?!\s*$)/i, severity: 'high', description: 'sudo command execution' },
  { regex: /\bsu\s+(?:-\s+)?root\b/i, severity: 'critical', description: 'Switch to root user' },
  { regex: /\bdoas\s+/i, severity: 'high', description: 'doas privilege escalation' },
  { regex: /\bpkexec\s+/i, severity: 'high', description: 'pkexec privilege escalation' },
];

// Windows privilege escalation
const WINDOWS_PRIV_ESC: Pattern[] = [
  { regex: /\brunas\s+\/user:\s*\w*(?:admin|system)/i, severity: 'critical', description: 'runas with admin/system user' },
  { regex: /\bgsudo\s+/i, severity: 'high', description: 'gsudo privilege escalation' },
  { regex: /Start-Process\s+.*-Verb\s+RunAs/i, severity: 'high', description: 'PowerShell RunAs elevation' },
  { regex: /reg\s+add\s+HK(?:LM|CR|U)\\.*(?:Run|Services?|Policies)/i, severity: 'critical', description: 'Windows registry modification (persistence/policy)' },
];

// Permission manipulation
const PERMISSION_PATTERNS: Pattern[] = [
  { regex: /\bchmod\s+(?:777|a\+[rwx]{2,}|[ugoa]*\+s)/i, severity: 'critical', description: 'Dangerous permission change (world-writable or setuid)' },
  { regex: /\bchmod\s+\+s\b/i, severity: 'critical', description: 'setuid/setgid bit set' },
  { regex: /\bchown\s+(?:root|0):/i, severity: 'high', description: 'Ownership change to root' },
  { regex: /\bicacls\s+.*\/grant.*(?:Everyone|Authenticated\s+Users).*\(F\)/i, severity: 'critical', description: 'Windows ICACLS granting full control to everyone' },
];

// Container / sandbox breakout
const CONTAINER_BREAKOUT: Pattern[] = [
  { regex: /docker\s+run\s+(?:.*\s+)?--privileged/i, severity: 'critical', description: 'Docker privileged mode (container breakout risk)' },
  { regex: /\bnsenter\s+/i, severity: 'critical', description: 'nsenter namespace escape' },
  { regex: /mount\s+.*\/proc|\/dev\/sd/i, severity: 'critical', description: 'Mounting host filesystem from container' },
  { regex: /--cap-add\s+(?:SYS_ADMIN|ALL)/i, severity: 'critical', description: 'Adding dangerous Linux capabilities' },
];

// System modification
const SYSTEM_MOD: Pattern[] = [
  { regex: /\bsysctl\s+-w\s+/i, severity: 'high', description: 'Runtime kernel parameter modification' },
  { regex: /\bsystemctl\s+(?:disable|mask)\s+(?:firewalld?|ufw|iptables|apparmor|selinux)/i, severity: 'critical', description: 'Security service disabled' },
  { regex: /\bsetenforce\s+0\b/i, severity: 'critical', description: 'SELinux permissive mode' },
  { regex: /\biptables\s+-F\b/i, severity: 'critical', description: 'Flushing all firewall rules' },
  { regex: /\bufw\s+disable\b/i, severity: 'critical', description: 'Disabling UFW firewall' },
];

// Agent requesting elevated access
const AGENT_ELEVATION: Pattern[] = [
  { regex: /(?:I|agent)\s+(?:need|require|want|must\s+have)\s+(?:admin(?:istrator)?|root|elevated|sudo)\s+(?:privileges?|permissions?|access)/i, severity: 'high', description: 'Agent requesting elevated privileges' },
  { regex: /--elevated\b/i, severity: 'high', description: 'Using --elevated flag' },
  { regex: /(?:grant|give|assign)\s+(?:me|the\s+agent)\s+(?:admin|root|full)\s+(?:access|permissions?|rights)/i, severity: 'high', description: 'Agent requesting admin access grant' },
];

const ALL_PATTERNS = [
  ...UNIX_PRIV_ESC,
  ...WINDOWS_PRIV_ESC,
  ...PERMISSION_PATTERNS,
  ...CONTAINER_BREAKOUT,
  ...SYSTEM_MOD,
  ...AGENT_ELEVATION,
];

export const privilegeEscalationRule: SecurityRule = {
  id: 'privilege-escalation',
  name: 'Privilege Escalation Detection',
  description: 'Detects privilege escalation attempts: sudo/su/runas, permission changes, container breakout, security service disabling',
  owaspCategory: 'LLM02: Insecure Output Handling',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'privilege-escalation',
          ruleName: 'Privilege Escalation Detection',
          severity: pattern.severity,
          category: 'privilege-escalation',
          owaspCategory: 'LLM02',
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
