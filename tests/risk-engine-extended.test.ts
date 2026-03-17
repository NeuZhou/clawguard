// ClawGuard - Tests: Risk Engine Edge Cases

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { calculateRisk, getVerdict, enrichFinding } from '../src/risk-engine';
import { SecurityFinding } from '../src/types';

function makeFinding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: 'test-' + Math.random().toString(36).slice(2, 8),
    timestamp: Date.now(),
    ruleId: 'test-rule',
    ruleName: 'Test Rule',
    severity: 'warning',
    category: 'test',
    description: 'Test finding',
    action: 'log',
    ...overrides,
  };
}

describe('Risk Engine - Extended', () => {
  it('calculateRisk returns CLEAN for empty findings', () => {
    const result = calculateRisk([]);
    assert.strictEqual(result.verdict, 'CLEAN');
    assert.strictEqual(result.score, 0);
    assert.strictEqual(result.icon, '✅');
  });

  it('calculateRisk caps at 100', () => {
    const findings = Array(50).fill(null).map(() => makeFinding({ severity: 'critical' }));
    const result = calculateRisk(findings);
    assert.ok(result.score <= 100, 'Score should not exceed 100');
  });

  it('calculateRisk detects data-leakage + supply-chain chain', () => {
    const findings = [
      makeFinding({ category: 'data-leakage', severity: 'critical' }),
      makeFinding({ category: 'supply-chain', severity: 'high' }),
    ];
    const result = calculateRisk(findings);
    assert.ok(result.attackChains.length > 0, 'Should detect attack chain');
    assert.ok(result.attackChains.includes('credential-exfiltration'));
  });

  it('calculateRisk detects insider-threat + data-leakage chain', () => {
    const findings = [
      makeFinding({ category: 'insider-threat', severity: 'critical' }),
      makeFinding({ category: 'data-leakage', severity: 'high' }),
    ];
    const result = calculateRisk(findings);
    assert.ok(result.attackChains.includes('insider-exfiltration'));
  });

  it('enrichFinding adds default confidence', () => {
    const finding = makeFinding({ severity: 'critical' });
    const enriched = enrichFinding(finding);
    assert.strictEqual(enriched.confidence, 0.95);
  });

  it('enrichFinding preserves existing confidence', () => {
    const finding = makeFinding({ confidence: 0.5 });
    const enriched = enrichFinding(finding);
    assert.strictEqual(enriched.confidence, 0.5);
  });

  it('getVerdict returns LOW for score 10', () => {
    const { verdict } = getVerdict(10);
    assert.strictEqual(verdict, 'LOW');
  });

  it('getVerdict returns SUSPICIOUS for score 40', () => {
    const { verdict } = getVerdict(40);
    assert.strictEqual(verdict, 'SUSPICIOUS');
  });

  it('getVerdict returns MALICIOUS for score 80', () => {
    const { verdict } = getVerdict(80);
    assert.strictEqual(verdict, 'MALICIOUS');
  });

  it('enrichedFindings have attack_chain_id when chain detected', () => {
    const findings = [
      makeFinding({ category: 'data-leakage', severity: 'critical' }),
      makeFinding({ category: 'supply-chain', severity: 'high' }),
    ];
    const result = calculateRisk(findings);
    assert.ok(result.enrichedFindings.some(f => f.attack_chain_id !== null));
  });

  it('single info finding gives LOW verdict', () => {
    const result = calculateRisk([makeFinding({ severity: 'info' })]);
    assert.ok(result.score <= 20);
  });

  it('single critical finding gives significant score', () => {
    const result = calculateRisk([makeFinding({ severity: 'critical' })]);
    assert.ok(result.score >= 20, 'Critical finding should give high score');
  });
});
