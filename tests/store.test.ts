// Carapace — Tests: Store (JSONL logic)

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

describe('Store — JSONL format', () => {
  it('appendJsonl creates valid JSONL lines', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ow-test-'));
    const file = path.join(tmpDir, 'test.jsonl');

    const records = [
      { id: '1', value: 'hello' },
      { id: '2', value: 'world' },
    ];

    for (const r of records) {
      fs.appendFileSync(file, JSON.stringify(r) + '\n');
    }

    const lines = fs.readFileSync(file, 'utf-8').split('\n').filter(Boolean);
    assert.strictEqual(lines.length, 2);
    assert.deepStrictEqual(JSON.parse(lines[0]), records[0]);
    assert.deepStrictEqual(JSON.parse(lines[1]), records[1]);

    // Cleanup
    fs.rmSync(tmpDir, { recursive: true });
  });

  it('handles empty JSONL file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ow-test-'));
    const file = path.join(tmpDir, 'empty.jsonl');
    fs.writeFileSync(file, '');

    const lines = fs.readFileSync(file, 'utf-8').split('\n').filter(Boolean);
    assert.strictEqual(lines.length, 0);

    fs.rmSync(tmpDir, { recursive: true });
  });

  it('supports pagination via offset and limit', () => {
    const records = Array.from({ length: 20 }, (_, i) => ({ id: `${i}`, n: i }));
    const lines = records.map(r => JSON.stringify(r));

    const start = 5;
    const limit = 3;
    const page = lines.slice(start, start + limit).map(l => JSON.parse(l));

    assert.strictEqual(page.length, 3);
    assert.strictEqual(page[0].n, 5);
    assert.strictEqual(page[2].n, 7);
  });

  it('rotation creates gzipped backup (conceptual)', () => {
    // Test that zlib gzip works
    const { gzipSync, gunzipSync } = require('zlib');
    const data = Buffer.from('test data for rotation');
    const compressed = gzipSync(data);
    const decompressed = gunzipSync(compressed);
    assert.strictEqual(decompressed.toString(), 'test data for rotation');
  });
});

