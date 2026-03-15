// Carapace — Tests: Cost Engine

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { estimateTokens, getModelPricing, calculateCost, getAllModelPricing } from '../src/cost-engine';

describe('Cost Engine', () => {
  it('estimates tokens from text length', () => {
    assert.strictEqual(estimateTokens(''), 0);
    assert.strictEqual(estimateTokens('abcd'), 1);
    assert.strictEqual(estimateTokens('a'.repeat(100)), 25);
  });

  it('returns known model pricing', () => {
    const p = getModelPricing('gpt-4o');
    assert.strictEqual(p.input, 2.50);
    assert.strictEqual(p.output, 10.00);
  });

  it('matches partial model names', () => {
    const p = getModelPricing('gpt-4o-2024-08-06');
    assert.strictEqual(p.input, 2.50);
  });

  it('returns default for unknown model', () => {
    const p = getModelPricing('unknown-model-xyz');
    assert.strictEqual(p.input, 1.00);
    assert.strictEqual(p.output, 3.00);
  });

  it('calculates inbound cost correctly', () => {
    // 1M tokens of gpt-4o input = $2.50
    const cost = calculateCost(1_000_000, 'inbound', 'gpt-4o');
    assert.strictEqual(cost, 2.50);
  });

  it('calculates outbound cost correctly', () => {
    const cost = calculateCost(1_000_000, 'outbound', 'gpt-4o');
    assert.strictEqual(cost, 10.00);
  });

  it('GitHub Copilot models are free', () => {
    const cost = calculateCost(1_000_000, 'outbound', 'github-copilot/claude-opus-4');
    assert.strictEqual(cost, 0);
  });

  it('getAllModelPricing returns all models', () => {
    const all = getAllModelPricing();
    assert.ok(Object.keys(all).length > 20);
    assert.ok('gpt-4o' in all);
    assert.ok('claude-opus-4' in all);
  });
});

