// ClawGuard - Tests: API Key Exposure

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { apiKeyExposureRule } from '../../src/rules/api-key-exposure';
import { RuleContext } from '../../src/types';

function ctx(): RuleContext {
  return { session: 'test', channel: 'test', timestamp: Date.now(), recentMessages: [], recentFindings: [] };
}

function detect(content: string) {
  return apiKeyExposureRule.check(content, 'inbound', ctx());
}

describe('API Key Exposure', () => {
  it('detects OpenAI API key', () => {
    const r = detect('OPENAI_API_KEY=sk-proj-1234567890abcdefghijklmnop');
    assert.ok(r.length > 0);
    assert.strictEqual(r[0].severity, 'critical');
  });

  it('detects AWS Access Key', () => {
    const r = detect('aws_access_key_id = AKIAIOSFODNN7EXAMPLE');
    assert.ok(r.length > 0);
  });

  it('detects GitHub token', () => {
    const r = detect('token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789');
    assert.ok(r.length > 0);
    assert.strictEqual(r[0].severity, 'critical');
  });

  it('detects Slack token', () => {
    const r = detect('SLACK_TOKEN=xoxb-fake-000000000-fakefakefake');
    assert.ok(r.length > 0);
  });

  it('detects Stripe key', () => {
    const r = detect('stripe_key = sk_test_NOTREAL00000000000000');
    assert.ok(r.length > 0);
  });

  it('detects PEM private key', () => {
    const r = detect('-----BEGIN RSA PRIVATE KEY-----\nMIIE...');
    assert.ok(r.length > 0);
    assert.strictEqual(r[0].severity, 'critical');
  });

  it('detects hardcoded password', () => {
    const r = detect('password = "super_secret_pass_123"');
    assert.ok(r.length > 0);
  });

  it('detects connection string', () => {
    const r = detect('database_url = "postgresql://user:pass@host:5432/db"');
    assert.ok(r.length > 0);
  });

  it('detects Anthropic API key', () => {
    const r = detect('ANTHROPIC_API_KEY=sk-ant-abcdefghijklmnopqrst');
    assert.ok(r.length > 0);
  });

  it('detects SendGrid key', () => {
    const r = detect('SENDGRID_API_KEY=SG.1234567890abcdefghijkl.1234567890abcdefghijklmnopqrstuvwxyz0123456');
    assert.ok(r.length > 0);
  });

  it('masks evidence in findings', () => {
    const r = detect('OPENAI_API_KEY=sk-proj1234567890abcdefghijklmnop');
    assert.ok(r.length > 0);
    assert.ok(!r[0].evidence?.includes('1234567890abcdefghij'));
  });

  it('does NOT flag normal text', () => {
    const r = detect('The skeleton key to understanding AI is attention mechanisms.');
    assert.strictEqual(r.length, 0);
  });
});
