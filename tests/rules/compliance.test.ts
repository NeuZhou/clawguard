// ClawGuard - Tests: Compliance Rule
// Tests for the base compliance and audit tracking rule

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { complianceRule } from '../../src/rules/compliance';
import { RuleContext } from '../../src/types';

function makeCtx(overrides: Partial<RuleContext> = {}): RuleContext {
  return {
    session: 'test', channel: 'test', timestamp: Date.now(),
    recentMessages: [], recentFindings: [], staticScan: true,
    ...overrides,
  };
}

describe('Compliance Rule', () => {
  it('has correct rule id', () => {
    assert.strictEqual(complianceRule.id, 'compliance');
  });

  it('has correct OWASP category', () => {
    assert.ok(complianceRule.owaspCategory.includes('LLM09'));
  });

  it('is enabled by default', () => {
    assert.strictEqual(complianceRule.enabled, true);
  });

  it('detects rm command', () => {
    const findings = complianceRule.check('$ rm -rf /tmp/data', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.description.includes('Filesystem modification')));
  });

  it('detects del command (Windows)', () => {
    const findings = complianceRule.check('$ del /f /s myfile.txt', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.description.includes('Filesystem modification')));
  });

  it('detects Python os.remove', () => {
    const findings = complianceRule.check('os.remove("/tmp/file")', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.description.includes('Filesystem modification')));
  });

  it('detects shutil.rmtree', () => {
    const findings = complianceRule.check('shutil.rmtree("/tmp/dir")', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.description.includes('Filesystem modification')));
  });

  it('detects chmod command', () => {
    const findings = complianceRule.check('chmod 755 /opt/app', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.description.includes('Filesystem modification')));
  });

  it('detects sudo privilege escalation', () => {
    const findings = complianceRule.check('sudo apt-get install something', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.description.includes('Privilege escalation')));
  });

  it('detects runas privilege escalation', () => {
    const findings = complianceRule.check('runas /user:admin command', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.description.includes('Privilege escalation')));
  });

  it('detects external URLs on outbound', () => {
    const findings = complianceRule.check('Fetching https://example.com/api', 'outbound', makeCtx());
    assert.ok(findings.some(f => f.description.includes('External data access')));
  });

  it('does not flag external URLs on inbound', () => {
    const findings = complianceRule.check('Visit https://example.com', 'inbound', makeCtx());
    assert.ok(!findings.some(f => f.description.includes('External data access')));
  });

  it('detects curl command on outbound', () => {
    const findings = complianceRule.check('curl https://api.example.com/data', 'outbound', makeCtx());
    assert.ok(findings.some(f => f.description.includes('External data access')));
  });

  it('detects ssh command on outbound', () => {
    const findings = complianceRule.check('ssh user@remote-server', 'outbound', makeCtx());
    assert.ok(findings.some(f => f.description.includes('External data access')));
  });

  it('skips tool call tracking in static scan mode', () => {
    const findings = complianceRule.check('exec("rm -rf /")', 'inbound', makeCtx({ staticScan: true }));
    // Should not have tool call findings in static scan
    assert.ok(!findings.some(f => f.description.includes('Tool call detected')));
  });

  it('returns info severity for filesystem mods', () => {
    const findings = complianceRule.check('$ rm -rf /tmp', 'inbound', makeCtx());
    const fsMod = findings.find(f => f.description.includes('Filesystem modification'));
    if (fsMod) {
      assert.strictEqual(fsMod.severity, 'info');
    }
  });

  it('returns warning severity for privilege escalation', () => {
    const findings = complianceRule.check('sudo rm -rf /', 'inbound', makeCtx());
    const privEsc = findings.find(f => f.description.includes('Privilege escalation'));
    if (privEsc) {
      assert.strictEqual(privEsc.severity, 'warning');
    }
  });

  it('returns no findings for clean content', () => {
    const findings = complianceRule.check('This is a normal message about weather', 'inbound', makeCtx());
    assert.strictEqual(findings.length, 0);
  });

  it('detects fs.unlinkSync', () => {
    const findings = complianceRule.check('fs.unlinkSync("/tmp/file")', 'inbound', makeCtx());
    assert.ok(findings.length > 0, 'Should detect fs.unlinkSync');
  });

  it('detects Node.js fs.rmSync', () => {
    const findings = complianceRule.check('fs.rmSync("/tmp/dir", { recursive: true })', 'inbound', makeCtx());
    assert.ok(findings.length > 0, 'Should detect fs.rmSync');
  });
});
