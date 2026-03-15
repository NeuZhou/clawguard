import { describe, it, expect } from 'vitest';
import { sanitize, restore, containsPII } from '../src/sanitizer';

describe('PII Sanitizer', () => {
  it('sanitizes email addresses', () => {
    const result = sanitize('Contact me at john@example.com for details');
    expect(result.sanitized).not.toContain('john@example.com');
    expect(result.sanitized).toContain('<EMAIL_');
    expect(result.piiCount).toBe(1);
  });

  it('sanitizes phone numbers', () => {
    const result = sanitize('Call me at 555-123-4567');
    expect(result.piiCount).toBeGreaterThanOrEqual(1);
    expect(result.sanitized).not.toContain('555-123-4567');
  });

  it('sanitizes SSN', () => {
    const result = sanitize('My SSN is 123-45-6789');
    expect(result.sanitized).not.toContain('123-45-6789');
    expect(result.sanitized).toContain('<SSN_');
  });

  it('sanitizes OpenAI API key', () => {
    const result = sanitize('key: sk-1234567890abcdef1234567890abcdef');
    expect(result.sanitized).not.toContain('sk-1234567890abcdef');
    expect(result.piiCount).toBeGreaterThanOrEqual(1);
  });

  it('sanitizes AWS access key', () => {
    const result = sanitize('AWS key: AKIAIOSFODNN7EXAMPLE');
    expect(result.sanitized).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(result.sanitized).toContain('<AWS_KEY_');
  });

  it('sanitizes GitHub token', () => {
    const result = sanitize('token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
    expect(result.sanitized).not.toContain('ghp_');
    expect(result.sanitized).toContain('<GITHUB_TOKEN_');
  });

  it('sanitizes JWT', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const result = sanitize(`Bearer ${jwt}`);
    expect(result.sanitized).not.toContain('eyJhbGci');
    expect(result.sanitized).toContain('<JWT_');
  });

  it('sanitizes database URI', () => {
    const result = sanitize('mongodb://admin:password123@db.example.com:27017/mydb');
    expect(result.sanitized).not.toContain('password123');
    expect(result.sanitized).toContain('<DB_URI_');
  });

  it('restores sanitized text', () => {
    const original = 'Email: john@example.com, SSN: 123-45-6789';
    const result = sanitize(original);
    const restored = restore(result.sanitized, result.replacements);
    expect(restored).toBe(original);
  });

  it('containsPII detects PII', () => {
    expect(containsPII('john@example.com')).toBe(true);
    expect(containsPII('AKIAIOSFODNN7EXAMPLE')).toBe(true);
  });

  it('containsPII returns false for clean text', () => {
    expect(containsPII('Hello world, nice day')).toBe(false);
  });

  it('handles multiple PII in one text', () => {
    const result = sanitize('Email: a@b.com, SSN: 123-45-6789, key: AKIAIOSFODNN7EXAMPLE');
    expect(result.piiCount).toBeGreaterThanOrEqual(3);
  });

  it('does not modify clean text', () => {
    const result = sanitize('The weather is nice today');
    expect(result.sanitized).toBe('The weather is nice today');
    expect(result.piiCount).toBe(0);
  });
});
