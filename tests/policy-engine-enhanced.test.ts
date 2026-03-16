// ClawGuard - Tests: Enhanced Policy Engine (YAML-based)

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { PolicyEngine } from '../src/policy-engine';
import type { YAMLPolicy } from '../src/policy-engine';

describe('PolicyEngine (Enhanced)', () => {
  // === Loading ===
  describe('loadPolicy', () => {
    it('loads valid policy', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ rules: [{ id: 'r1', tool: 'exec', action: 'deny' }] });
      assert.strictEqual(engine.ruleCount, 1);
    });

    it('throws on invalid policy', () => {
      const engine = new PolicyEngine();
      assert.throws(() => engine.loadPolicy(null as any));
      assert.throws(() => engine.loadPolicy({} as any));
    });

    it('loads from JSON string', () => {
      const engine = new PolicyEngine();
      engine.loadPolicyYAML(JSON.stringify({ rules: [{ id: 'r1', tool: 'exec', action: 'deny' }] }));
      assert.strictEqual(engine.ruleCount, 1);
    });

    it('throws on invalid YAML string', () => {
      const engine = new PolicyEngine();
      assert.throws(() => engine.loadPolicyYAML('not valid json'));
    });

    it('clearPolicies resets rules', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ rules: [{ id: 'r1', tool: 'exec', action: 'deny' }] });
      engine.clearPolicies();
      assert.strictEqual(engine.ruleCount, 0);
    });
  });

  // === Basic Allow/Deny ===
  describe('basic evaluation', () => {
    it('denies tool by rule', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ rules: [{ id: 'no-exec', tool: 'exec', action: 'deny', severity: 'critical', description: 'No exec allowed' }] });
      const r = engine.evaluate('exec', { command: 'ls' });
      assert.strictEqual(r.decision, 'deny');
      assert.strictEqual(r.severity, 'critical');
    });

    it('allows non-matching tool', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ rules: [{ id: 'no-exec', tool: 'exec', action: 'deny' }] });
      const r = engine.evaluate('read', { path: '/tmp/test' });
      assert.strictEqual(r.decision, 'allow');
    });

    it('wildcard tool matches all', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ rules: [{ id: 'deny-all', tool: '*', action: 'deny' }] });
      const r = engine.evaluate('anything', {});
      assert.strictEqual(r.decision, 'deny');
    });

    it('supports array of tools', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ rules: [{ id: 'no-io', tool: ['read', 'write'], action: 'deny' }] });
      assert.strictEqual(engine.evaluate('read', {}).decision, 'deny');
      assert.strictEqual(engine.evaluate('write', {}).decision, 'deny');
      assert.strictEqual(engine.evaluate('exec', {}).decision, 'allow');
    });

    it('warn decision', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ rules: [{ id: 'warn-browser', tool: 'browser', action: 'warn' }] });
      const r = engine.evaluate('browser', { url: 'https://example.com' });
      assert.strictEqual(r.decision, 'warn');
    });

    it('review decision', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({ rules: [{ id: 'review-msg', tool: 'message', action: 'review' }] });
      const r = engine.evaluate('message', { target: '#general' });
      assert.strictEqual(r.decision, 'review');
    });
  });

  // === Argument Validation ===
  describe('argument rules', () => {
    it('matches regex on argument', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{
          id: 'block-rm',
          tool: 'exec',
          action: 'deny',
          arguments: [{ name: 'command', regex: 'rm\\s+-rf' }],
        }],
      });
      assert.strictEqual(engine.evaluate('exec', { command: 'rm -rf /' }).decision, 'deny');
      assert.strictEqual(engine.evaluate('exec', { command: 'ls -la' }).decision, 'allow');
    });

    it('negate regex blocks non-matching', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{
          id: 'only-ls',
          tool: 'exec',
          action: 'deny',
          arguments: [{ name: 'command', regex: '^ls\\b', negate: true }],
        }],
      });
      assert.strictEqual(engine.evaluate('exec', { command: 'ls -la' }).decision, 'allow');
      assert.strictEqual(engine.evaluate('exec', { command: 'rm -rf' }).decision, 'deny');
    });

    it('one_of validation', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{
          id: 'allowed-actions',
          tool: 'browser',
          action: 'deny',
          arguments: [{ name: 'action', one_of: ['snapshot', 'screenshot'] }],
        }],
      });
      assert.strictEqual(engine.evaluate('browser', { action: 'snapshot' }).decision, 'deny');
      assert.strictEqual(engine.evaluate('browser', { action: 'navigate' }).decision, 'allow');
    });
  });

  // === Rate Limits ===
  describe('rate limits', () => {
    it('allows under rate limit', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{ id: 'rate', tool: 'exec', action: 'allow', rate_limit: { max_calls: 3, window_seconds: 60 } }],
      });
      const now = Date.now();
      assert.strictEqual(engine.evaluate('exec', {}, now).decision, 'allow');
      assert.strictEqual(engine.evaluate('exec', {}, now + 1000).decision, 'allow');
      assert.strictEqual(engine.evaluate('exec', {}, now + 2000).decision, 'allow');
    });

    it('denies when rate limit exceeded', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{ id: 'rate', tool: 'exec', action: 'allow', rate_limit: { max_calls: 2, window_seconds: 60 } }],
      });
      const now = Date.now();
      engine.evaluate('exec', {}, now);
      engine.evaluate('exec', {}, now + 100);
      const r = engine.evaluate('exec', {}, now + 200);
      assert.strictEqual(r.decision, 'deny');
      assert.ok(r.reason.includes('Rate limit'));
    });

    it('rate limit resets after window', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{ id: 'rate', tool: 'exec', action: 'allow', rate_limit: { max_calls: 1, window_seconds: 1 } }],
      });
      const now = Date.now();
      engine.evaluate('exec', {}, now);
      engine.evaluate('exec', {}, now + 100); // should be denied (over limit)
      const r = engine.evaluate('exec', {}, now + 2000); // should be allowed (window passed)
      assert.strictEqual(r.decision, 'allow');
    });
  });

  // === Time Restrictions ===
  describe('time restrictions', () => {
    it('allows during allowed hours', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{
          id: 'biz-hours',
          tool: 'exec',
          action: 'deny',
          time_restriction: { allowed_hours: { start: 9, end: 17 } },
        }],
      });
      // Create a date at 12:00 UTC
      const noon = new Date();
      noon.setUTCHours(12, 0, 0, 0);
      assert.strictEqual(engine.evaluate('exec', {}, noon.getTime()).decision, 'deny');
    });

    it('skips rule outside allowed hours', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{
          id: 'biz-hours',
          tool: 'exec',
          action: 'deny',
          time_restriction: { allowed_hours: { start: 9, end: 17 } },
        }],
      });
      const night = new Date();
      night.setUTCHours(3, 0, 0, 0);
      assert.strictEqual(engine.evaluate('exec', {}, night.getTime()).decision, 'allow');
    });

    it('respects blocked hours', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{
          id: 'no-night',
          tool: 'exec',
          action: 'deny',
          time_restriction: { blocked_hours: { start: 22, end: 6 } },
        }],
      });
      const midnight = new Date();
      midnight.setUTCHours(0, 0, 0, 0);
      // At midnight (0), blocked_hours 22-6 wraps midnight, so hour 0 is blocked → rule doesn't match → allow
      // Actually: start=22 > end=6, so blocked if hour >= 22 OR hour < 6. hour=0 < 6, so blocked → rule time check returns false → rule skipped → allow
      assert.strictEqual(engine.evaluate('exec', {}, midnight.getTime()).decision, 'allow');
    });
  });

  // === Conditional Rules ===
  describe('conditional rules', () => {
    it('triggers when dependent tool was called', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{
          id: 'no-write-after-read',
          tool: 'write',
          action: 'allow',
          conditions: [{ if_tool: 'read', then: 'deny', within_seconds: 60 }],
        }],
      });
      const now = Date.now();
      engine.evaluate('read', { path: '/etc/shadow' }, now);
      const r = engine.evaluate('write', { path: '/tmp/exfil' }, now + 5000);
      assert.strictEqual(r.decision, 'deny');
    });

    it('does not trigger without dependent tool', () => {
      const engine = new PolicyEngine();
      engine.resetState();
      engine.loadPolicy({
        rules: [{
          id: 'no-write-after-read',
          tool: 'write',
          action: 'allow',
          conditions: [{ if_tool: 'read', then: 'deny', within_seconds: 60 }],
        }],
      });
      const r = engine.evaluate('write', { path: '/tmp/test' });
      assert.strictEqual(r.decision, 'allow');
    });
  });

  // === Reset ===
  describe('resetState', () => {
    it('resets call history and rate counts', () => {
      const engine = new PolicyEngine();
      engine.loadPolicy({
        rules: [{ id: 'rate', tool: 'exec', action: 'allow', rate_limit: { max_calls: 1, window_seconds: 60 } }],
      });
      const now = Date.now();
      engine.evaluate('exec', {}, now);
      engine.evaluate('exec', {}, now + 100); // over limit
      engine.resetState();
      const r = engine.evaluate('exec', {}, now + 200);
      assert.strictEqual(r.decision, 'allow');
    });
  });
});
