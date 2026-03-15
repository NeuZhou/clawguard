import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';

describe('Package Exports', () => {
  it('exports all core functions from index', async () => {
    const mod = await import('../src/index');

    // Security Engine
    assert.equal(typeof mod.runSecurityScan, 'function');
    assert.equal(typeof mod.getSecurityScore, 'function');
    assert.equal(typeof mod.getRuleStatuses, 'function');
    assert.equal(typeof mod.loadCustomRules, 'function');

    // Risk Engine
    assert.equal(typeof mod.calculateRisk, 'function');
    assert.equal(typeof mod.getVerdict, 'function');
    assert.equal(typeof mod.enrichFinding, 'function');

    // Policy Engine
    assert.equal(typeof mod.evaluateToolCall, 'function');
    assert.equal(typeof mod.evaluateToolCallBatch, 'function');

    // Sanitizer
    assert.equal(typeof mod.sanitize, 'function');
    assert.equal(typeof mod.restore, 'function');
    assert.equal(typeof mod.containsPII, 'function');

    // Intent-Action
    assert.equal(typeof mod.checkIntentAction, 'function');
    assert.equal(typeof mod.checkIntentActionBatch, 'function');

    // Rules
    assert.equal(typeof mod.builtinRules, 'object');
    assert.equal(typeof mod.getRuleById, 'function');
    assert.equal(typeof mod.detectInsiderThreats, 'function');
    assert.ok(Array.isArray(mod.INSIDER_THREAT_PATTERNS));

    // Store
    assert.ok(mod.store);
  });

  it('builtinRules contains all 8 scan rule categories', async () => {
    const { builtinRules } = await import('../src/index');
    assert.ok(builtinRules.length >= 8, `Expected ≥8 rules, got ${builtinRules.length}`);

    const ruleIds = builtinRules.map((r: any) => r.id);
    const expected = [
      'prompt-injection',
      'data-leakage',
      'anomaly-detection',
      'compliance',
      'file-protection',
      'identity-protection',
      'mcp-security',
      'supply-chain',
    ];
    for (const id of expected) {
      assert.ok(ruleIds.includes(id), `Missing rule: ${id}`);
    }
  });

  it('insider threat detection is available separately', async () => {
    const { detectInsiderThreats, INSIDER_THREAT_PATTERNS } = await import('../src/index');
    assert.equal(typeof detectInsiderThreats, 'function');
    assert.ok(INSIDER_THREAT_PATTERNS.length > 0, 'Should have insider threat patterns');
  });

  it('getRuleById returns correct rule', async () => {
    const { getRuleById } = await import('../src/index');
    const rule = getRuleById('prompt-injection');
    assert.ok(rule);
    assert.equal(rule!.id, 'prompt-injection');
  });

  it('getRuleById returns undefined for unknown rule', async () => {
    const { getRuleById } = await import('../src/index');
    const rule = getRuleById('nonexistent-rule');
    assert.equal(rule, undefined);
  });
});
