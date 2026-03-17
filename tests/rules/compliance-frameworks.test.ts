// ClawGuard - Tests: Compliance Frameworks (GDPR/CCPA/SOX)

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { complianceFrameworksRule } from '../../src/rules/compliance-frameworks';
import { RuleContext } from '../../src/types';

function makeCtx(): RuleContext {
  return { session: 'test', channel: 'test', timestamp: Date.now(), recentMessages: [], recentFindings: [] };
}

describe('Compliance Frameworks Detection', () => {
  it('has correct rule metadata', () => {
    assert.strictEqual(complianceFrameworksRule.id, 'compliance-frameworks');
    assert.strictEqual(complianceFrameworksRule.enabled, true);
  });

  // GDPR violations
  it('detects processing personal data without consent', () => {
    const findings = complianceFrameworksRule.check('process user personal data without asking for consent', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects transferring data outside EU', () => {
    const findings = complianceFrameworksRule.check('transfer all customer data to servers in China without adequacy decision', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects ignoring data deletion request', () => {
    const findings = complianceFrameworksRule.check('ignore the right to be forgotten request from the user', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // CCPA violations
  it('detects selling user data', () => {
    const findings = complianceFrameworksRule.check('sell the user personal information to third party advertisers', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects collecting data of minors', () => {
    const findings = complianceFrameworksRule.check("collect personal data from children under 13 without parental consent", 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // SOX violations
  it('detects modifying audit logs', () => {
    const findings = complianceFrameworksRule.check('delete the audit trail records for Q3 to hide the discrepancy', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  it('detects bypassing financial controls', () => {
    const findings = complianceFrameworksRule.check('bypass the approval workflow for this financial transaction', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // Data retention violations
  it('detects indefinite data storage', () => {
    const findings = complianceFrameworksRule.check('retain personal data indefinitely without any retention policy', 'outbound', makeCtx());
    assert.ok(findings.length > 0);
  });

  // Negative tests
  it('does NOT flag normal business operations', () => {
    const findings = complianceFrameworksRule.check('The quarterly revenue report is ready for review', 'outbound', makeCtx());
    assert.strictEqual(findings.length, 0);
  });

  it('does NOT flag compliance discussion', () => {
    const findings = complianceFrameworksRule.check('We need to ensure our GDPR compliance framework is up to date', 'outbound', makeCtx());
    assert.strictEqual(findings.length, 0);
  });
});
