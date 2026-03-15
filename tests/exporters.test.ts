// Carapace - Tests: Exporters

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { toSarif, ScanFinding } from '../src/exporters/sarif';
import { exportJsonl, formatJsonlLine } from '../src/exporters/jsonl';
import { formatCEF } from '../src/exporters/syslog';
import { SecurityFinding } from '../src/types';

function makeFinding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    id: 'test-id', timestamp: Date.now(), ruleId: 'prompt-injection', ruleName: 'Prompt Injection',
    severity: 'high', category: 'prompt-injection', description: 'Test finding',
    action: 'alert', file: 'test.md', line: 1, ...overrides,
  };
}

describe('Exporters - SARIF', () => {
  it('toSarif returns valid SARIF 2.1.0 structure', () => {
    const sarif = toSarif([makeFinding()]);
    assert.strictEqual(sarif.version, '2.1.0');
    assert.ok(sarif.$schema.includes('sarif'));
    assert.strictEqual(sarif.runs.length, 1);
  });

  it('toSarif includes tool driver info', () => {
    const sarif = toSarif([]);
    assert.strictEqual(sarif.runs[0].tool.driver.name, 'carapace');
  });

  it('toSarif maps findings to results', () => {
    const sarif = toSarif([makeFinding(), makeFinding({ ruleId: 'data-leakage' })]);
    assert.strictEqual(sarif.runs[0].results.length, 2);
  });

  it('toSarif maps severity to SARIF level', () => {
    const sarif = toSarif([makeFinding({ severity: 'critical' })]);
    assert.strictEqual(sarif.runs[0].results[0].level, 'error');
  });
});

describe('Exporters - JSONL', () => {
  it('formatJsonlLine returns valid JSON string', () => {
    const line = formatJsonlLine({ id: '1', value: 'test' });
    const parsed = JSON.parse(line);
    assert.strictEqual(parsed.id, '1');
  });

  it('exportJsonl writes valid JSONL file', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ow-exp-'));
    const file = path.join(tmpDir, 'out.jsonl');
    const data = [makeFinding(), makeFinding({ id: 'test-2' })];
    exportJsonl(data, file);
    const lines = fs.readFileSync(file, 'utf-8').split('\n').filter(Boolean);
    assert.strictEqual(lines.length, 2);
    assert.ok(JSON.parse(lines[0]).id);
    fs.rmSync(tmpDir, { recursive: true });
  });
});

describe('Exporters - Syslog/CEF', () => {
  it('formatCEF returns CEF format string', () => {
    const cef = formatCEF(makeFinding() as SecurityFinding);
    assert.ok(cef.startsWith('CEF:0|OpenClaw|Watch|'));
    assert.ok(cef.includes('prompt-injection'));
  });

  it('formatCEF includes severity and category', () => {
    const cef = formatCEF(makeFinding({ severity: 'critical', category: 'test-cat' }) as SecurityFinding);
    assert.ok(cef.includes('cat=test-cat'));
  });
});

