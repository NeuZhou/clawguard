// Carapace - Tests: Store (extended)

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { store } from '../src/store';
import { DEFAULT_CONFIG } from '../src/types';

describe('Store - Extended', () => {
  it('getConfig returns default config shape', () => {
    store.init();
    const cfg = store.getConfig();
    assert.ok(cfg.dashboard);
    assert.ok(cfg.budget);
    assert.ok(cfg.alerts);
    assert.ok(cfg.security);
    assert.strictEqual(typeof cfg.dashboard.port, 'number');
  });

  it('appendFinding + getFindings round-trip', () => {
    store.init();
    const uniqueId = `rt-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const finding = {
      id: uniqueId, timestamp: Date.now(), ruleId: 'test', ruleName: 'Test',
      severity: 'warning' as const, category: 'test', description: 'roundtrip test', action: 'log' as const,
    };
    store.appendFinding(finding);
    const findings = store.getFindings(1000);
    assert.ok(findings.some(f => f.id === uniqueId), `Expected to find ${uniqueId} in ${findings.length} findings`);
  });

  it('getAllSessions returns array', () => {
    store.init();
    const sessions = store.getAllSessions();
    assert.ok(Array.isArray(sessions));
  });

  it('upsertSession + getSession round-trip', () => {
    store.init();
    const session = {
      id: 'sess-test', channel: 'test', startedAt: Date.now(), lastActivityAt: Date.now(),
      messageCount: 5, estimatedTokens: 1000, estimatedCostUsd: 0.01, securityFindings: 0,
    };
    store.upsertSession(session);
    const got = store.getSession('sess-test');
    assert.ok(got);
    assert.strictEqual(got!.id, 'sess-test');
  });

  it('getFindings returns empty array when no data', () => {
    // Just check it doesn't throw
    const findings = store.getFindings(10);
    assert.ok(Array.isArray(findings));
  });

  it('getDataDir returns a string path', () => {
    const dir = store.getDataDir();
    assert.ok(typeof dir === 'string');
    assert.ok(dir.includes('carapace'));
  });
});

