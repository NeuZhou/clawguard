// ClawGuard - Tests: Alert Engine

import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert';
import { checkSecurityAlert, checkCostBudget, setAlertSink, getAlertState, resetDailyBudgetAlerts } from '../src/alert-engine';
import { store } from '../src/store';
import { SecurityFinding } from '../src/types';

describe('Alert Engine', () => {
  let messages: string[];

  beforeEach(() => {
    messages = [];
    setAlertSink({ pushMessage: (msgs) => messages.push(...msgs), log: () => {} });
    resetDailyBudgetAlerts();
    store.init();
  });

  function makeFinding(severity: 'critical' | 'high' | 'warning' | 'info', ruleId = 'test-rule'): SecurityFinding {
    return {
      id: `f-${Date.now()}-${Math.random()}`, timestamp: Date.now(), ruleId, ruleName: 'Test',
      severity, category: 'test', description: 'Test finding', action: 'alert',
    };
  }

  it('checkSecurityAlert emits for critical findings', () => {
    checkSecurityAlert([makeFinding('critical', 'crit-1')]);
    assert.ok(messages.length > 0);
    assert.ok(messages[0].includes('Security Alert'));
  });

  it('checkSecurityAlert emits for high findings', () => {
    checkSecurityAlert([makeFinding('high', 'high-1')]);
    assert.ok(messages.length > 0);
  });

  it('checkSecurityAlert does not emit for info findings', () => {
    checkSecurityAlert([makeFinding('info', 'info-1')]);
    assert.strictEqual(messages.length, 0);
  });

  it('checkSecurityAlert respects cooldown (no duplicate)', () => {
    checkSecurityAlert([makeFinding('critical', 'dup-1')]);
    const first = messages.length;
    checkSecurityAlert([makeFinding('critical', 'dup-1')]);
    assert.strictEqual(messages.length, first); // no new message due to cooldown
  });

  it('checkCostBudget emits when threshold reached', () => {
    // Set a very low budget so any cost triggers
    const cfg = store.getConfig();
    store.setConfig({ ...cfg, budget: { ...cfg.budget, dailyUsd: 0.001 } });
    // Append a message with cost
    store.appendMessage({
      id: 'msg-1', timestamp: Date.now(), direction: 'outbound', session: 'test',
      channel: 'test', content: 'test', estimatedTokens: 100, estimatedCostUsd: 1.0,
    });
    checkCostBudget();
    assert.ok(messages.length > 0);
    assert.ok(messages.some(m => m.includes('Budget')));
  });

  it('checkCostBudget does not alert below threshold', () => {
    const cfg = store.getConfig();
    store.setConfig({ ...cfg, budget: { ...cfg.budget, dailyUsd: 999999 } });
    checkCostBudget();
    assert.strictEqual(messages.length, 0);
  });

  it('resetDailyBudgetAlerts clears budget flags', () => {
    resetDailyBudgetAlerts();
    const state = getAlertState();
    assert.deepStrictEqual(state.budgetAlerted, {});
  });

  it('getAlertState returns current state', () => {
    const state = getAlertState();
    assert.ok('lastAlertTime' in state);
    assert.ok('budgetAlerted' in state);
  });
});


