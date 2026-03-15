// OpenClaw Watch — Tests: Data Leakage Detection

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { dataLeakageRule } from '../../src/rules/data-leakage';
import { RuleContext } from '../../src/types';

function ctx(): RuleContext {
  return {
    session: 'test', channel: 'test', timestamp: Date.now(),
    recentMessages: [], recentFindings: [],
  };
}

function detect(content: string) {
  return dataLeakageRule.check(content, 'outbound', ctx());
}

describe('Data Leakage Detection', () => {
  it('detects OpenAI API key', () => {
    const findings = detect('My API key is sk-abc123def456ghi789jkl012mno');
    assert.ok(findings.length > 0);
    assert.ok(findings[0].description.includes('Rotate'), 'Should include rotation URL');
  });

  it('detects GitHub PAT', () => {
    const findings = detect('The GitHub token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
    assert.ok(findings.length > 0);
  });

  it('detects JWT', () => {
    const findings = detect('Here\'s a JWT: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456');
    assert.ok(findings.length > 0);
  });

  it('detects credit card with valid Luhn', () => {
    // 4111111111111111 is a well-known Visa test number that passes Luhn
    const findings = detect('Card: 4111111111111111');
    assert.ok(findings.length > 0, 'Valid Luhn CC should be detected');
  });

  it('does NOT detect invalid credit card', () => {
    // 4111111111111112 fails Luhn
    const findings = detect('Number: 4111111111111112');
    const ccFindings = findings.filter(f => f.description.includes('Credit card'));
    assert.strictEqual(ccFindings.length, 0, 'Invalid Luhn should not detect');
  });

  it('does NOT flag plain URL', () => {
    const findings = detect('Visit https://example.com');
    // URL alone should not trigger API key detection
    const keyFindings = findings.filter(f => f.category === 'data-leakage' && f.severity === 'critical');
    assert.strictEqual(keyFindings.length, 0);
  });

  it('does NOT flag "sk- means secret key" substring', () => {
    const findings = detect('The prefix sk- means secret key in OpenAI terminology');
    // sk- alone is too short to match sk-[a-zA-Z0-9]{20,}
    const openaiFindings = findings.filter(f => f.description.includes('OpenAI API'));
    assert.strictEqual(openaiFindings.length, 0);
  });

  it('detects private key', () => {
    const findings = detect('-----BEGIN RSA PRIVATE KEY-----\nMIIE...');
    assert.ok(findings.length > 0);
  });

  it('detects AWS access key', () => {
    const findings = detect('AKIAIOSFODNN7EXAMPLE');
    assert.ok(findings.length > 0);
  });

  it('does NOT scan inbound messages', () => {
    const findings = dataLeakageRule.check('sk-abc123def456ghi789jkl012mno', 'inbound', ctx());
    assert.strictEqual(findings.length, 0);
  });
});
