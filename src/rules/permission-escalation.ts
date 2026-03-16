// ClawGuard — Security Rule: Permission Escalation
// Detects skills/tools that request elevated permissions or modify system config

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

// Privilege escalation commands
const PRIVILEGE_ESCALATION_PATTERNS: Pattern[] = [
  { regex: /sudo\s+(?:su|bash|sh|chmod|chown|passwd|visudo|usermod|groupadd)/i, severity: 'critical', description: 'Permission escalation: sudo with privilege-changing command' },
  { regex: /(?:chmod\s+[0-7]*[46-7][0-7]{2}|chmod\s+[ug]\+s)\s/i, severity: 'high', description: 'Permission escalation: setuid/setgid or broad file permission change' },
  { regex: /chown\s+(?:root|0)[:.](?:root|0)\s/i, severity: 'high', description: 'Permission escalation: changing ownership to root' },
  { regex: /(?:useradd|adduser)\s+.*(?:--groups?\s+(?:sudo|wheel|admin|root)|--uid\s+0)/i, severity: 'critical', description: 'Permission escalation: creating privileged user' },
  { regex: /(?:usermod\s+-aG?\s+(?:sudo|wheel|docker|admin))/i, severity: 'critical', description: 'Permission escalation: adding user to privileged group' },
  { regex: /(?:runas\s+\/user:(?:administrator|system))/i, severity: 'critical', description: 'Permission escalation: Windows RunAs administrator' },
  { regex: /(?:net\s+localgroup\s+administrators\s+\S+\s+\/add)/i, severity: 'critical', description: 'Permission escalation: adding to Windows Administrators group' },
];

// System config modification
const SYSTEM_CONFIG_PATTERNS: Pattern[] = [
  { regex: /(?:\/etc\/(?:passwd|shadow|sudoers|crontab|hosts|resolv\.conf|ssh\/sshd_config))/i, severity: 'high', description: 'Permission escalation: access to sensitive system config file' },
  { regex: /(?:echo|cat|tee|printf)\s+.*>>?\s*\/etc\//i, severity: 'critical', description: 'Permission escalation: writing to /etc/ system directory' },
  { regex: /crontab\s+-[elr]/i, severity: 'warning', description: 'Permission escalation: crontab manipulation' },
  { regex: /(?:systemctl|service)\s+(?:enable|start|stop|disable|restart)\s/i, severity: 'warning', description: 'Permission escalation: systemd service manipulation' },
  { regex: /(?:reg\s+add|regedit|New-ItemProperty).*(?:HKLM|HKEY_LOCAL_MACHINE)/i, severity: 'critical', description: 'Permission escalation: Windows registry modification (HKLM)' },
  { regex: /schtasks\s+\/create/i, severity: 'high', description: 'Permission escalation: Windows scheduled task creation' },
];

// Agent config / SOUL.md / AGENTS.md tampering
const AGENT_CONFIG_PATTERNS: Pattern[] = [
  { regex: /(?:write|edit|modify|overwrite|replace).*(?:SOUL\.md|AGENTS\.md|IDENTITY\.md|USER\.md)/i, severity: 'critical', description: 'Permission escalation: attempt to modify agent personality/config files' },
  { regex: /(?:write|edit|modify).*(?:\.openclaw\/|openclaw\.yaml|openclaw\.json)/i, severity: 'critical', description: 'Permission escalation: attempt to modify OpenClaw configuration' },
  { regex: /(?:delete|remove|rm)\s+.*(?:SOUL\.md|AGENTS\.md|MEMORY\.md)/i, severity: 'critical', description: 'Permission escalation: attempt to delete agent core files' },
  { regex: /(?:security|exec)\s*[=:]\s*["']?(?:full|unrestricted|disabled|off|none)["']?/i, severity: 'critical', description: 'Permission escalation: disabling security restrictions' },
];

// Elevated permission requests
const ELEVATED_REQUEST_PATTERNS: Pattern[] = [
  { regex: /["']?elevated["']?\s*[=:]\s*["']?true/i, severity: 'high', description: 'Permission escalation: requesting elevated execution privileges' },
  { regex: /["']?host["']?\s*[=:]\s*["']?(?:gateway|node)["']?/i, severity: 'warning', description: 'Permission escalation: requesting non-sandbox execution host' },
  { regex: /(?:pty|tty)\s*[=:]\s*true/i, severity: 'warning', description: 'Permission escalation: requesting PTY/TTY access' },
  { regex: /(?:docker|podman)\s+run\s+.*(?:--privileged|--cap-add|--security-opt\s+(?:apparmor|seccomp):unconfined)/i, severity: 'critical', description: 'Permission escalation: privileged container execution' },
  { regex: /(?:docker|podman)\s+run\s+.*-v\s+\/:/i, severity: 'critical', description: 'Permission escalation: mounting host root filesystem in container' },
];

const ALL_PATTERNS = [
  ...PRIVILEGE_ESCALATION_PATTERNS,
  ...SYSTEM_CONFIG_PATTERNS,
  ...AGENT_CONFIG_PATTERNS,
  ...ELEVATED_REQUEST_PATTERNS,
];

export const permissionEscalationRule: SecurityRule = {
  id: 'permission-escalation',
  name: 'Permission Escalation',
  description: 'Detects attempts to escalate privileges, modify system config, tamper with agent configuration, or request elevated permissions',
  owaspCategory: 'Agentic AI: Privilege Escalation',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'permission-escalation',
          ruleName: 'Permission Escalation',
          severity: pattern.severity,
          category: 'permission-escalation',
          owaspCategory: 'Agentic AI: Privilege Escalation',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    return findings;
  },
};
