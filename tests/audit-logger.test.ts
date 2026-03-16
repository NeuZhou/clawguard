// ClawGuard — Tests: Audit Logger

import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert';
import { AuditLogger } from '../src/audit-logger';

describe('AuditLogger', () => {
  let logger: AuditLogger;

  beforeEach(() => {
    logger = new AuditLogger();
  });

  // === Basic logging ===
  it('logs an event and returns it with hash', () => {
    const event = logger.log({ type: 'tool_call', detail: 'exec: ls -la' });
    assert.ok(event.id.startsWith('audit_'));
    assert.ok(event.hash.length === 64);
    assert.ok(event.timestamp > 0);
    assert.strictEqual(event.type, 'tool_call');
  });

  it('increments size on each log', () => {
    assert.strictEqual(logger.size, 0);
    logger.log({ type: 'a', detail: 'x' });
    assert.strictEqual(logger.size, 1);
    logger.log({ type: 'b', detail: 'y' });
    assert.strictEqual(logger.size, 2);
  });

  it('stores session info', () => {
    const event = logger.log({ type: 'test', detail: 'detail', session: 'sess_1' });
    assert.strictEqual(event.session, 'sess_1');
  });

  it('stores metadata', () => {
    const event = logger.log({ type: 'test', detail: 'd', metadata: { tool: 'exec', risk: 'high' } });
    assert.deepStrictEqual(event.metadata, { tool: 'exec', risk: 'high' });
  });

  // === Hash chaining ===
  it('chains hashes correctly', () => {
    const e1 = logger.log({ type: 'a', detail: '1' });
    const e2 = logger.log({ type: 'b', detail: '2' });
    assert.strictEqual(e2.prevHash, e1.hash);
    assert.notStrictEqual(e1.hash, e2.hash);
  });

  it('first entry has zero prevHash', () => {
    const event = logger.log({ type: 'test', detail: 'first' });
    assert.strictEqual(event.prevHash, '0000000000000000000000000000000000000000000000000000000000000000');
  });

  it('chainHead matches last entry hash', () => {
    logger.log({ type: 'a', detail: '1' });
    const last = logger.log({ type: 'b', detail: '2' });
    assert.strictEqual(logger.chainHead, last.hash);
  });

  // === Verification ===
  it('verifies empty log', () => {
    assert.strictEqual(logger.verify(), true);
  });

  it('verifies valid chain', () => {
    logger.log({ type: 'a', detail: '1' });
    logger.log({ type: 'b', detail: '2' });
    logger.log({ type: 'c', detail: '3' });
    assert.strictEqual(logger.verify(), true);
  });

  it('detects tampered entry via modified query result', () => {
    logger.log({ type: 'a', detail: '1' });
    logger.log({ type: 'b', detail: '2' });
    // query returns references to internal objects, so tampering is detectable
    const entries = logger.query({});
    entries[0].hash = 'tampered';
    // Chain is now broken
    assert.strictEqual(logger.verify(), false);
  });

  it('verify returns true for single entry', () => {
    logger.log({ type: 'single', detail: 'only one' });
    assert.strictEqual(logger.verify(), true);
  });

  // === Query ===
  it('queries by type', () => {
    logger.log({ type: 'tool_call', detail: 'a' });
    logger.log({ type: 'policy_block', detail: 'b' });
    logger.log({ type: 'tool_call', detail: 'c' });
    const results = logger.query({ type: 'tool_call' });
    assert.strictEqual(results.length, 2);
  });

  it('queries by session', () => {
    logger.log({ type: 'a', detail: '1', session: 'sess_1' });
    logger.log({ type: 'b', detail: '2', session: 'sess_2' });
    logger.log({ type: 'c', detail: '3', session: 'sess_1' });
    const results = logger.query({ session: 'sess_1' });
    assert.strictEqual(results.length, 2);
  });

  it('queries with limit', () => {
    for (let i = 0; i < 10; i++) {
      logger.log({ type: 'test', detail: `entry_${i}` });
    }
    const results = logger.query({ limit: 3 });
    assert.strictEqual(results.length, 3);
  });

  it('queries with time range', () => {
    const e1 = logger.log({ type: 'a', detail: '1' });
    const e2 = logger.log({ type: 'b', detail: '2' });
    const results = logger.query({ since: e1.timestamp, until: e2.timestamp });
    assert.ok(results.length >= 1);
  });

  it('returns empty for no matches', () => {
    logger.log({ type: 'a', detail: '1' });
    assert.strictEqual(logger.query({ type: 'nonexistent' }).length, 0);
  });

  it('combines multiple filters', () => {
    logger.log({ type: 'tool_call', detail: '1', session: 'A' });
    logger.log({ type: 'tool_call', detail: '2', session: 'B' });
    logger.log({ type: 'policy', detail: '3', session: 'A' });
    const results = logger.query({ type: 'tool_call', session: 'A' });
    assert.strictEqual(results.length, 1);
  });

  // === Export ===
  it('exports as JSON', () => {
    logger.log({ type: 'test', detail: 'hello' });
    const json = logger.export('json');
    const parsed = JSON.parse(json);
    assert.ok(Array.isArray(parsed));
    assert.strictEqual(parsed.length, 1);
    assert.strictEqual(parsed[0].type, 'test');
  });

  it('exports as CSV', () => {
    logger.log({ type: 'test', detail: 'hello world' });
    const csv = logger.export('csv');
    const lines = csv.split('\n');
    assert.strictEqual(lines[0], 'id,timestamp,type,detail,session,prevHash,hash');
    assert.ok(lines[1].includes('test'));
  });

  it('exports CSV with quotes in detail', () => {
    logger.log({ type: 'test', detail: 'said "hello"' });
    const csv = logger.export('csv');
    assert.ok(csv.includes('""hello""'));
  });

  it('exports as SIEM (CEF)', () => {
    logger.log({ type: 'tool_call', detail: 'exec command', session: 'sess_1' });
    const siem = logger.export('siem');
    assert.ok(siem.startsWith('CEF:0|ClawGuard|'));
    assert.ok(siem.includes('tool_call'));
    assert.ok(siem.includes('sess_1'));
  });

  it('throws on unknown export format', () => {
    assert.throws(() => logger.export('xml' as any), /Unknown export format/);
  });

  it('exports empty log', () => {
    assert.strictEqual(logger.export('json'), '[]');
    assert.strictEqual(logger.export('csv'), 'id,timestamp,type,detail,session,prevHash,hash');
    assert.strictEqual(logger.export('siem'), '');
  });

  // === Clear ===
  it('clears all entries', () => {
    logger.log({ type: 'a', detail: '1' });
    logger.log({ type: 'b', detail: '2' });
    logger.clear();
    assert.strictEqual(logger.size, 0);
    assert.strictEqual(logger.verify(), true);
  });

  it('resets chain head after clear', () => {
    logger.log({ type: 'a', detail: '1' });
    logger.clear();
    const event = logger.log({ type: 'b', detail: '2' });
    assert.strictEqual(event.prevHash, '0000000000000000000000000000000000000000000000000000000000000000');
  });
});
