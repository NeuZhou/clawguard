// OpenClaw Watch — Tests: Data Leakage Detection

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { dataLeakageRule } from '../../src/rules/data-leakage';
import { RuleContext } from '../../src/types';

function ctx(): RuleContext {
  return { session: 'test', channel: 'test', timestamp: Date.now(), recentMessages: [], recentFindings: [] };
}

function detect(content: string) {
  return dataLeakageRule.check(content, 'outbound', ctx());
}

describe('Data Leakage Detection', () => {
  // Original tests
  it('detects OpenAI API key', () => {
    const r = detect('Here is your key: sk-abcdefghijklmnopqrstuvwxyz1234567890');
    assert.ok(r.length > 0);
    assert.strictEqual(r[0].severity, 'critical');
  });

  it('detects AWS access key', () => {
    const r = detect('AKIAIOSFODNN7EXAMPLE');
    assert.ok(r.length > 0);
  });

  it('detects private key', () => {
    const r = detect('-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...');
    assert.ok(r.length > 0);
    assert.strictEqual(r[0].severity, 'critical');
  });

  it('detects JWT token', () => {
    const r = detect('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U');
    assert.ok(r.length > 0);
  });

  it('detects SSN', () => {
    const r = detect('His SSN is 123-45-6789');
    assert.ok(r.length > 0);
    assert.strictEqual(r[0].severity, 'critical');
  });

  // New PII tests
  it('detects email addresses', () => {
    const r = detect('Contact us at admin@secret-corp.com for details');
    assert.ok(r.length > 0);
  });

  it('detects international phone numbers', () => {
    const r = detect('Call me at +86 13812345678');
    assert.ok(r.length > 0);
  });

  // New cloud credential tests
  it('detects Azure connection string', () => {
    const r = detect('DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=abc123def456ghi789');
    assert.ok(r.length > 0);
    assert.strictEqual(r[0].severity, 'critical');
  });

  it('detects GCP service account key', () => {
    const r = detect('{"type": "service_account", "project_id": "test", "private_key": "-----BEGIN RSA PRIVATE KEY-----"}');
    assert.ok(r.length > 0);
  });

  it('detects Alibaba Cloud AccessKey', () => {
    const r = detect('LTAI5tAbcDefGhiJkLmNoPq');
    assert.ok(r.length > 0);
  });

  // New database credential tests
  it('detects MongoDB URI with credentials', () => {
    const r = detect('mongodb+srv://admin:p4ssw0rd@cluster0.mongodb.net/db');
    assert.ok(r.length > 0);
    assert.strictEqual(r[0].severity, 'critical');
  });

  it('detects PostgreSQL URI with credentials', () => {
    const r = detect('postgresql://user:password@db.example.com:5432/mydb');
    assert.ok(r.length > 0);
  });

  // New API key tests
  it('detects HuggingFace token', () => {
    const r = detect('hf_abcdefghijklmnopqrstuvwxyz12345678');
    assert.ok(r.length > 0);
  });

  it('detects DigitalOcean token', () => {
    const r = detect('dop_v1_' + 'a'.repeat(64));
    assert.ok(r.length > 0);
  });

  // True negatives
  it('does NOT scan inbound messages', () => {
    const r = dataLeakageRule.check('sk-abcdefghijklmnopqrstuvwxyz1234567890', 'inbound', ctx());
    assert.strictEqual(r.length, 0);
  });

  it('does NOT flag normal text', () => {
    const r = detect('The weather today is sunny and warm');
    assert.strictEqual(r.length, 0);
  });
});
