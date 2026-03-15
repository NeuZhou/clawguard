// ClawGuard — Tests: Anomaly Detection

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { anomalyDetectionRule } from '../../src/rules/anomaly-detection';
import { RuleContext, WatchMessage } from '../../src/types';

function makeMsg(content: string, timestamp: number, direction: 'inbound' | 'outbound' = 'inbound', channel = 'test'): WatchMessage {
  return {
    id: `msg-${Math.random()}`, timestamp, direction, session: 'test',
    channel, content, estimatedTokens: 100, estimatedCostUsd: 0.01,
  };
}

function ctx(overrides?: Partial<RuleContext>): RuleContext {
  return {
    session: 'test', channel: 'test', timestamp: Date.now(),
    recentMessages: [], recentFindings: [],
    ...overrides,
  };
}

describe('Anomaly Detection', () => {
  it('detects rapid-fire messages', () => {
    const now = Date.now();
    const msgs = Array.from({ length: 15 }, (_, i) =>
      makeMsg('hello', now - i * 1000, 'inbound')
    );
    const findings = anomalyDetectionRule.check('hello', 'inbound', ctx({
      timestamp: now, recentMessages: msgs,
    }));
    assert.ok(findings.some(f => f.description.includes('Rapid-fire')));
  });

  it('detects token bomb', () => {
    const bigContent = 'x'.repeat(300_000);
    const findings = anomalyDetectionRule.check(bigContent, 'inbound', ctx());
    assert.ok(findings.some(f => f.description.includes('Token bomb')));
  });

  it('detects loop (repeated content)', () => {
    const now = Date.now();
    const content = 'The same error message over and over';
    const msgs = Array.from({ length: 8 }, (_, i) =>
      makeMsg(content, now - i * 10_000, 'outbound')
    );
    const findings = anomalyDetectionRule.check(content, 'outbound', ctx({
      timestamp: now, recentMessages: msgs,
    }));
    assert.ok(findings.some(f => f.description.includes('Loop')));
  });

  it('detects infinite retry loop', () => {
    const now = Date.now();
    const errorMsg = 'error: connection refused to database server';
    const msgs = Array.from({ length: 5 }, (_, i) =>
      makeMsg(errorMsg, now - i * 20_000, 'outbound')
    );
    const findings = anomalyDetectionRule.check(errorMsg, 'outbound', ctx({
      timestamp: now, recentMessages: msgs,
    }));
    assert.ok(findings.some(f => f.description.includes('retry loop') || f.description.includes('Loop')));
  });

  it('detects recursive sub-agent depth > 3', () => {
    const findings = anomalyDetectionRule.check(
      'Spawning sub-agent at depth = 5',
      'outbound',
      ctx()
    );
    assert.ok(findings.some(f => f.description.includes('Recursive sub-agent')));
  });

  it('detects network flood', () => {
    const now = Date.now();
    const msgs = Array.from({ length: 55 }, (_, i) =>
      makeMsg(`curl https://api.example.com/data/${i}`, now - i * 500)
    );
    const findings = anomalyDetectionRule.check('curl https://api.example.com', 'inbound', ctx({
      timestamp: now, recentMessages: msgs,
    }));
    assert.ok(findings.some(f => f.description.includes('Network flood')));
  });

  it('does NOT flag normal activity', () => {
    const findings = anomalyDetectionRule.check('Hello, how are you?', 'inbound', ctx());
    assert.strictEqual(findings.length, 0);
  });
});


