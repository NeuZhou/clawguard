// ClawGuard - Tests: Cost Engine Edge Cases

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { estimateTokens, getModelPricing, calculateCost, getAllModelPricing } from '../src/cost-engine';

describe('Cost Engine - Edge Cases', () => {
  it('estimateTokens handles empty string', () => {
    assert.strictEqual(estimateTokens(''), 0);
  });

  it('estimateTokens handles very long string', () => {
    const tokens = estimateTokens('a'.repeat(100000));
    assert.strictEqual(tokens, 25000);
  });

  it('estimateTokens returns integer', () => {
    const tokens = estimateTokens('Hello world!');
    assert.ok(Number.isInteger(tokens));
  });

  it('getModelPricing returns default for unknown model', () => {
    const pricing = getModelPricing('unknown-model-xyz');
    assert.ok(pricing.input > 0);
    assert.ok(pricing.output > 0);
  });

  it('getModelPricing matches exact model names', () => {
    const pricing = getModelPricing('gpt-4o');
    assert.strictEqual(pricing.input, 2.50);
    assert.strictEqual(pricing.output, 10.00);
  });

  it('getModelPricing matches partial model names', () => {
    const pricing = getModelPricing('gpt-4o-2024-08-06');
    assert.strictEqual(pricing.input, 2.50);
  });

  it('calculateCost returns 0 for zero tokens', () => {
    const cost = calculateCost(0, 'inbound', 'gpt-4o');
    assert.strictEqual(cost, 0);
  });

  it('calculateCost uses different rates for inbound/outbound', () => {
    const inCost = calculateCost(1000000, 'inbound', 'gpt-4o');
    const outCost = calculateCost(1000000, 'outbound', 'gpt-4o');
    assert.ok(outCost > inCost, 'Output cost should be higher than input');
  });

  it('calculateCost handles missing model gracefully', () => {
    const cost = calculateCost(1000, 'inbound');
    assert.ok(cost >= 0);
  });

  it('getAllModelPricing returns a non-empty object', () => {
    const all = getAllModelPricing();
    assert.ok(Object.keys(all).length > 10, 'Should have many models');
  });

  it('getModelPricing returns zero cost for included copilot models', () => {
    const pricing = getModelPricing('github-copilot/gpt-4o');
    assert.strictEqual(pricing.input, 0);
    assert.strictEqual(pricing.output, 0);
  });

  it('getModelPricing handles claude models', () => {
    const pricing = getModelPricing('claude-opus-4');
    assert.ok(pricing.input > 0);
    assert.ok(pricing.output > 0);
  });

  it('getModelPricing handles deepseek models', () => {
    const pricing = getModelPricing('deepseek-r1');
    assert.ok(pricing.input > 0);
    assert.ok(pricing.output > 0);
  });
});
