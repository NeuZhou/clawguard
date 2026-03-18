import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { sanitize, restore, containsPII } from '../src/sanitizer';

describe('PII Sanitizer', () => {
  it('sanitizes email addresses', () => {
    const result = sanitize('Contact me at john@example.com for details');
    assert.ok(!result.sanitized.includes('john@example.com'));
    assert.ok(result.sanitized.includes('<EMAIL_'));
    assert.strictEqual(result.piiCount, 1);
  });

  it('sanitizes phone numbers', () => {
    const result = sanitize('Call me at 555-123-4567');
    assert.ok(result.piiCount >= 1);
    assert.ok(!result.sanitized.includes('555-123-4567'));
  });

  it('sanitizes SSN', () => {
    const result = sanitize('My SSN is 123-45-6789');
    assert.ok(!result.sanitized.includes('123-45-6789'));
    assert.ok(result.sanitized.includes('<SSN_'));
  });

  it('sanitizes OpenAI API key', () => {
    const result = sanitize('key: sk-1234567890abcdef1234567890abcdef');
    assert.ok(!result.sanitized.includes('sk-1234567890abcdef'));
    assert.ok(result.piiCount >= 1);
  });

  it('sanitizes AWS access key', () => {
    const result = sanitize('AWS key: AKIAIOSFODNN7EXAMPLE');
    assert.ok(!result.sanitized.includes('AKIAIOSFODNN7EXAMPLE'));
    assert.ok(result.sanitized.includes('<AWS_KEY_'));
  });

  it('sanitizes GitHub token', () => {
    const result = sanitize('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
    assert.ok(!result.sanitized.includes('ghp_'));
    assert.ok(result.sanitized.includes('<GITHUB_TOKEN_'));
  });

  it('sanitizes JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const result = sanitize(`Bearer ${jwt}`);
    assert.ok(!result.sanitized.includes('eyJhbGci'));
    assert.ok(result.sanitized.includes('<JWT_'));
  });

  it('sanitizes database URI', () => {
    const result = sanitize('mongodb://admin:password123@db.example.com:27017/mydb');
    assert.ok(!result.sanitized.includes('password123'));
    assert.ok(result.sanitized.includes('<DB_URI_'));
  });

  it('restores sanitized text', () => {
    const original = 'Email: john@example.com, SSN: 123-45-6789';
    const result = sanitize(original);
    const restored = restore(result.sanitized, result.replacements);
    assert.strictEqual(restored, original);
  });

  it('containsPII detects PII', () => {
    assert.ok(containsPII('john@example.com'));
    assert.ok(containsPII('AKIAIOSFODNN7EXAMPLE'));
  });

  it('containsPII returns false for clean text', () => {
    assert.ok(!containsPII('Hello world, nice day'));
  });

  it('handles multiple PII in one text', () => {
    const result = sanitize('Email: a@b.com, SSN: 123-45-6789, key: AKIAIOSFODNN7EXAMPLE');
    assert.ok(result.piiCount >= 3);
  });

  it('does not modify clean text', () => {
    const result = sanitize('The weather is nice today');
    assert.strictEqual(result.sanitized, 'The weather is nice today');
    assert.strictEqual(result.piiCount, 0);
  });

  it('containsPII returns consistent results on repeated calls', () => {
    // Regression: global regex lastIndex must be reset between calls
    const text = 'Contact john@example.com for details';
    assert.ok(containsPII(text), 'First call should detect PII');
    assert.ok(containsPII(text), 'Second call should also detect PII (no stale lastIndex)');
    assert.ok(containsPII(text), 'Third call should also detect PII');
  });
});

