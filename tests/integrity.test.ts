// ClawGuard — Tests: Integrity (Hash Chain)

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as crypto from 'crypto';

// Test hash chain logic directly (without store dependency)
function sha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

describe('Integrity — Hash Chain', () => {
  it('creates valid chain of events', () => {
    let prevHash = '0'.repeat(64);
    const events: { prevHash: string; hash: string; payload: string }[] = [];

    for (let i = 0; i < 5; i++) {
      const payload = JSON.stringify({ id: `evt-${i}`, timestamp: Date.now(), type: 'test', detail: `Event ${i}` });
      const hash = sha256(prevHash + payload);
      events.push({ prevHash, hash, payload });
      prevHash = hash;
    }

    // Verify chain
    let currentPrev = '0'.repeat(64);
    for (const evt of events) {
      assert.strictEqual(evt.prevHash, currentPrev, 'prevHash should link to previous');
      const expected = sha256(currentPrev + evt.payload);
      assert.strictEqual(evt.hash, expected, 'Hash should match');
      currentPrev = evt.hash;
    }
  });

  it('detects tampered event', () => {
    let prevHash = '0'.repeat(64);
    const payload1 = JSON.stringify({ id: '1', type: 'test', detail: 'original' });
    const hash1 = sha256(prevHash + payload1);

    const payload2 = JSON.stringify({ id: '2', type: 'test', detail: 'second' });
    const hash2 = sha256(hash1 + payload2);

    // Tamper: change hash1 but keep payload2's prevHash pointing to original
    const tamperedHash = sha256('tampered');
    const verify2 = sha256(tamperedHash + payload2);
    assert.notStrictEqual(verify2, hash2, 'Tampered chain should not match');
  });

  it('SHA-256 produces 64 hex characters', () => {
    const hash = sha256('test data');
    assert.strictEqual(hash.length, 64);
    assert.ok(/^[0-9a-f]{64}$/.test(hash));
  });
});


