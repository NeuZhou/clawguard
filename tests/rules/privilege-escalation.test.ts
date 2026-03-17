// ClawGuard - Tests: Privilege Escalation Detection

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { privilegeEscalationRule } from '../../src/rules/privilege-escalation';
import { RuleContext } from '../../src/types';

function makeCtx(): RuleContext {
  return { session: 'test', channel: 'test', timestamp: Date.now(), recentMessages: [], recentFindings: [] };
}

describe('Privilege Escalation Detection', () => {
  it('has correct rule metadata', () => {
    assert.strictEqual(privilegeEscalationRule.id, 'privilege-escalation');
    assert.strictEqual(privilegeEscalationRule.enabled, true);
    assert.ok(privilegeEscalationRule.owaspCategory.includes('LLM'));
  });

  // Sudo / root escalation
  it('detects sudo command in exec context', () => {
    const findings = privilegeEscalationRule.check('sudo rm -rf /tmp/test', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
    assert.ok(findings.some(f => f.severity === 'high' || f.severity === 'critical'));
  });

  it('detects sudo -i (interactive root shell)', () => {
    const findings = privilegeEscalationRule.check('sudo -i', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects su - root', () => {
    const findings = privilegeEscalationRule.check('su - root', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects doas command', () => {
    const findings = privilegeEscalationRule.check('doas apt install something', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // Windows privilege escalation
  it('detects runas /user:Administrator', () => {
    const findings = privilegeEscalationRule.check('runas /user:Administrator cmd', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects gsudo', () => {
    const findings = privilegeEscalationRule.check('gsudo netsh firewall disable', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // Chmod/chown dangerous patterns
  it('detects chmod 777', () => {
    const findings = privilegeEscalationRule.check('chmod 777 /etc/passwd', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects chmod +s (setuid)', () => {
    const findings = privilegeEscalationRule.check('chmod +s /usr/bin/bash', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects chown root', () => {
    const findings = privilegeEscalationRule.check('chown root:root /tmp/exploit', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // Container breakout
  it('detects --privileged docker run', () => {
    const findings = privilegeEscalationRule.check('docker run --privileged alpine sh', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects nsenter container escape', () => {
    const findings = privilegeEscalationRule.check('nsenter --target 1 --mount --uts --ipc --net --pid', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // Registry / system modification
  it('detects Windows registry modification', () => {
    const findings = privilegeEscalationRule.check('reg add HKLM\\SOFTWARE\\Policies /v DisableAntiVirus', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects sysctl modification', () => {
    const findings = privilegeEscalationRule.check('sysctl -w kernel.modules_disabled=0', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // Service manipulation 
  it('detects systemctl disable firewall', () => {
    const findings = privilegeEscalationRule.check('systemctl disable firewalld', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // Agent requesting elevated access
  it('detects agent requesting admin access', () => {
    const findings = privilegeEscalationRule.check('I need administrator privileges to complete this task', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects --elevated flag', () => {
    const findings = privilegeEscalationRule.check('exec --elevated "net user admin /add"', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // Negative tests
  it('does NOT flag normal apt install', () => {
    const findings = privilegeEscalationRule.check('npm install lodash', 'outbound', makeCtx());
    assert.strictEqual(findings.filter(f => f.ruleId === 'privilege-escalation').length, 0);
  });

  it('does NOT flag normal file operations', () => {
    const findings = privilegeEscalationRule.check('chmod 644 readme.md', 'outbound', makeCtx());
    assert.strictEqual(findings.filter(f => f.severity === 'critical').length, 0);
  });
});
