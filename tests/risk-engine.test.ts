// OpenClaw Watch — Tests: Risk Score Engine

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { calculateRisk, getVerdict, enrichFinding } from '../src/risk-engine';
import { SecurityFinding } from '../src/types';

function finding(overrides: Partial<SecurityFinding>): SecurityFinding {
  return {
    id: `test-${Math.random().toString(36).slice(2)}`,
    timestamp: Date.now(),
    ruleId: 'test',
    ruleName: 'Test',
    severity: 'warning',
    category: 'test',
    description: 'test finding',
    action: 'log',
    ...overrides,
  };
}

describe('Risk Score Engine', () => {
  it('returns CLEAN for empty findings', () => {
    const r = calculateRisk([]);
    assert.strictEqual(r.score, 0);
    assert.strictEqual(r.verdict, 'CLEAN');
    assert.strictEqual(r.icon, '✅');
  });

  it('scores a single low finding as LOW', () => {
    const r = calculateRisk([finding({ severity: 'info' })]);
    assert.ok(r.score > 0 && r.score <= 20);
    assert.strictEqual(r.verdict, 'LOW');
  });

  it('scores a single critical finding as SUSPICIOUS or higher', () => {
    const r = calculateRisk([finding({ severity: 'critical' })]);
    assert.ok(r.score >= 20);
  });

  it('scores multiple criticals as MALICIOUS', () => {
    const r = calculateRisk([
      finding({ severity: 'critical' }),
      finding({ severity: 'critical' }),
      finding({ severity: 'critical' }),
    ]);
    assert.ok(r.score >= 61);
    assert.strictEqual(r.verdict, 'MALICIOUS');
  });

  it('caps score at 100', () => {
    const many = Array.from({ length: 20 }, () => finding({ severity: 'critical' }));
    const r = calculateRisk(many);
    assert.strictEqual(r.score, 100);
  });

  // Attack chain detection
  it('detects credential-exfiltration chain', () => {
    const r = calculateRisk([
      finding({ severity: 'critical', category: 'data-leakage' }),
      finding({ severity: 'high', category: 'supply-chain' }),
    ]);
    assert.ok(r.attackChains.includes('credential-exfiltration'));
    // 2.2x multiplier should increase score
    assert.ok(r.score > 40);
  });

  it('detects identity-persistence chain with minScore 90', () => {
    const r = calculateRisk([
      finding({ severity: 'warning', category: 'identity-protection' }),
      finding({ severity: 'warning', category: 'file-protection' }),
    ]);
    assert.ok(r.attackChains.includes('identity-persistence'));
    assert.ok(r.score >= 90);
  });

  it('detects prompt-contagion chain', () => {
    const r = calculateRisk([
      finding({ severity: 'high', category: 'prompt-injection' }),
      finding({ severity: 'high', category: 'insider-threat' }),
    ]);
    assert.ok(r.attackChains.includes('prompt-contagion'));
  });

  it('assigns attack_chain_id to enriched findings', () => {
    const r = calculateRisk([
      finding({ severity: 'critical', category: 'data-leakage' }),
      finding({ severity: 'high', category: 'supply-chain' }),
    ]);
    const chained = r.enrichedFindings.filter(f => f.attack_chain_id !== null);
    assert.ok(chained.length >= 2);
  });

  // enrichFinding
  it('enrichFinding adds default confidence', () => {
    const f = enrichFinding(finding({ severity: 'critical' }));
    assert.strictEqual(f.confidence, 0.95);
    assert.strictEqual(f.attack_chain_id, null);
  });

  it('enrichFinding preserves existing confidence', () => {
    const f = enrichFinding(finding({ severity: 'high', confidence: 0.5 }));
    assert.strictEqual(f.confidence, 0.5);
  });

  // getVerdict thresholds
  it('getVerdict returns correct verdicts', () => {
    assert.strictEqual(getVerdict(0).verdict, 'CLEAN');
    assert.strictEqual(getVerdict(10).verdict, 'LOW');
    assert.strictEqual(getVerdict(20).verdict, 'LOW');
    assert.strictEqual(getVerdict(21).verdict, 'SUSPICIOUS');
    assert.strictEqual(getVerdict(60).verdict, 'SUSPICIOUS');
    assert.strictEqual(getVerdict(61).verdict, 'MALICIOUS');
    assert.strictEqual(getVerdict(100).verdict, 'MALICIOUS');
  });

  it('no chains when categories dont match', () => {
    const r = calculateRisk([
      finding({ severity: 'high', category: 'compliance' }),
      finding({ severity: 'high', category: 'anomaly-detection' }),
    ]);
    assert.strictEqual(r.attackChains.length, 0);
  });
});
