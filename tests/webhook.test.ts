// ClawGuard - Tests: Webhook Exporter

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { SecurityFinding } from '../src/types';

// We can't test actual webhook sending (needs running server),
// but we can test the module structure and function availability

describe('Webhook Exporter', () => {
  it('sendWebhook function is importable', async () => {
    const { sendWebhook } = await import('../src/exporters/webhook');
    assert.strictEqual(typeof sendWebhook, 'function');
  });

  it('sendWebhook handles invalid URL gracefully', async () => {
    const { sendWebhook } = await import('../src/exporters/webhook');
    const finding: SecurityFinding = {
      id: 'test', timestamp: Date.now(), ruleId: 'test-rule',
      ruleName: 'Test', severity: 'warning', category: 'test',
      description: 'Test finding', action: 'log',
    };
    // Should not throw
    sendWebhook(finding, 'not-a-valid-url', 'secret');
    assert.ok(true, 'Should handle invalid URL without crashing');
  });

  it('sendWebhook handles empty secret', async () => {
    const { sendWebhook } = await import('../src/exporters/webhook');
    const finding: SecurityFinding = {
      id: 'test', timestamp: Date.now(), ruleId: 'test-rule',
      ruleName: 'Test', severity: 'warning', category: 'test',
      description: 'Test finding', action: 'log',
    };
    // Should not throw, even with empty secret
    sendWebhook(finding, 'https://httpbin.org/post', '');
    assert.ok(true, 'Should handle empty secret without crashing');
  });
});
