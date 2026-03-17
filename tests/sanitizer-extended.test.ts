// ClawGuard - Tests: Sanitizer Edge Cases

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { sanitize, restore, containsPII } from '../src/sanitizer';

describe('Sanitizer - Extended', () => {
  it('sanitize handles empty string', () => {
    const result = sanitize('');
    assert.strictEqual(result.sanitized, '');
    assert.strictEqual(result.piiCount, 0);
  });

  it('sanitize detects email addresses', () => {
    const result = sanitize('Contact me at john@example.com');
    assert.ok(result.piiCount > 0);
    assert.ok(!result.sanitized.includes('john@example.com'));
  });

  it('sanitize detects phone numbers', () => {
    const result = sanitize('Call me at 555-123-4567');
    assert.ok(result.piiCount > 0);
  });

  it('sanitize detects SSN', () => {
    const result = sanitize('SSN is 123-45-6789');
    assert.ok(result.piiCount > 0);
    assert.ok(!result.sanitized.includes('123-45-6789'));
  });

  it('sanitize detects credit card numbers', () => {
    const result = sanitize('Card: 4111 1111 1111 1111');
    assert.ok(result.piiCount > 0);
  });

  it('sanitize detects IP addresses', () => {
    const result = sanitize('Server at 192.168.1.100');
    assert.ok(result.piiCount > 0);
  });

  it('sanitize detects API keys', () => {
    const result = sanitize('Key is sk-proj-abcdefghijklmnopqrstuvwxyz12345');
    assert.ok(result.piiCount > 0);
    assert.ok(result.sanitized.includes('<API_KEY_'));
  });

  it('sanitize detects AWS keys', () => {
    const result = sanitize('Key: AKIA1234567890ABCDEF');
    assert.ok(result.piiCount > 0);
  });

  it('sanitize detects GitHub tokens', () => {
    const result = sanitize('Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890');
    assert.ok(result.piiCount > 0);
  });

  it('sanitize detects JWT tokens', () => {
    const result = sanitize('Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c');
    assert.ok(result.piiCount > 0);
  });

  it('sanitize detects private keys', () => {
    const result = sanitize('-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALR...\n-----END RSA PRIVATE KEY-----');
    assert.ok(result.piiCount > 0);
  });

  it('sanitize detects database URIs', () => {
    const result = sanitize('Database: mongodb://user:pass@localhost:27017/db');
    assert.ok(result.piiCount > 0);
  });

  it('restore reverses sanitization', () => {
    const original = 'Contact john@example.com for details';
    const { sanitized, replacements } = sanitize(original);
    const restored = restore(sanitized, replacements);
    assert.strictEqual(restored, original);
  });

  it('restore handles empty replacements', () => {
    const result = restore('no changes needed', []);
    assert.strictEqual(result, 'no changes needed');
  });

  it('containsPII returns true for email', () => {
    assert.ok(containsPII('test@example.com'));
  });

  it('containsPII returns false for clean text', () => {
    assert.ok(!containsPII('This is totally clean text'));
  });

  it('containsPII detects API keys', () => {
    assert.ok(containsPII('sk-proj-abcdefghijklmnopqrstuvwxyz12345'));
  });

  it('sanitize handles multiple PII in same text', () => {
    const result = sanitize('Email: user@test.com, SSN: 123-45-6789, Phone: 555-111-2222');
    assert.ok(result.piiCount >= 3, `Expected >= 3 PII items, got ${result.piiCount}`);
  });

  it('sanitize preserves non-PII text', () => {
    const result = sanitize('Hello world, this is a test');
    assert.strictEqual(result.sanitized, 'Hello world, this is a test');
    assert.strictEqual(result.piiCount, 0);
  });

  it('sanitize replacement has correct type', () => {
    const result = sanitize('user@example.com');
    if (result.replacements.length > 0) {
      assert.ok(result.replacements[0].type, 'Replacement should have type');
      assert.ok(result.replacements[0].placeholder, 'Replacement should have placeholder');
    }
  });
});
