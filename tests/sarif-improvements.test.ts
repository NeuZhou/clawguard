// ClawGuard - Tests: SARIF Output Improvements (Issue #7)

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import { toSarif, ScanFinding } from '../src/exporters/sarif';
import { SecurityFinding } from '../src/types';

function makeFinding(overrides: Partial<ScanFinding> = {}): ScanFinding {
  return {
    id: 'test-id', timestamp: Date.now(), ruleId: 'prompt-injection', ruleName: 'Prompt Injection',
    severity: 'high', category: 'prompt-injection', description: 'Test finding',
    owaspCategory: 'LLM01', action: 'alert', file: 'test.md', line: 1, ...overrides,
  };
}

describe('SARIF Output Improvements', () => {
  it('includes $schema URL', () => {
    const sarif = toSarif([]);
    assert.ok(sarif.$schema.includes('sarif-schema-2.1.0'));
  });

  it('includes version as 2.1.0', () => {
    const sarif = toSarif([]);
    assert.strictEqual(sarif.version, '2.1.0');
  });

  it('includes informationUri in tool driver', () => {
    const sarif = toSarif([]);
    assert.ok(sarif.runs[0].tool.driver.informationUri.includes('ClawGuard'));
  });

  it('maps critical severity to error level', () => {
    const sarif = toSarif([makeFinding({ severity: 'critical' })]);
    assert.strictEqual(sarif.runs[0].results[0].level, 'error');
  });

  it('maps high severity to error level', () => {
    const sarif = toSarif([makeFinding({ severity: 'high' })]);
    assert.strictEqual(sarif.runs[0].results[0].level, 'error');
  });

  it('maps warning severity to warning level', () => {
    const sarif = toSarif([makeFinding({ severity: 'warning' })]);
    assert.strictEqual(sarif.runs[0].results[0].level, 'warning');
  });

  it('maps info severity to note level', () => {
    const sarif = toSarif([makeFinding({ severity: 'info' })]);
    assert.strictEqual(sarif.runs[0].results[0].level, 'note');
  });

  it('includes file location in results', () => {
    const sarif = toSarif([makeFinding({ file: 'src/bad.ts', line: 42 })]);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.strictEqual(loc.artifactLocation.uri, 'src/bad.ts');
    assert.strictEqual(loc.region?.startLine, 42);
  });

  it('includes evidence in message text', () => {
    const sarif = toSarif([makeFinding({ evidence: 'evil payload here' })]);
    assert.ok(sarif.runs[0].results[0].message.text.includes('evil payload here'));
  });

  it('includes OWASP category in properties', () => {
    const sarif = toSarif([makeFinding({ owaspCategory: 'LLM01' })]);
    assert.strictEqual((sarif.runs[0].results[0].properties as any).owaspCategory, 'LLM01');
  });

  it('includes severity in result properties', () => {
    const sarif = toSarif([makeFinding({ severity: 'critical' })]);
    assert.strictEqual((sarif.runs[0].results[0].properties as any).severity, 'critical');
  });

  it('includes rules for all built-in rules', () => {
    const sarif = toSarif([]);
    assert.ok(sarif.runs[0].tool.driver.rules.length >= 8);
  });

  it('each rule has tags including security', () => {
    const sarif = toSarif([]);
    for (const rule of sarif.runs[0].tool.driver.rules) {
      assert.ok(rule.properties.tags.includes('security'));
    }
  });

  it('handles finding without file gracefully', () => {
    const sarif = toSarif([makeFinding({ file: undefined })]);
    assert.strictEqual(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'unknown');
  });

  it('handles finding without line gracefully', () => {
    const sarif = toSarif([makeFinding({ line: undefined })]);
    const loc = sarif.runs[0].results[0].locations[0].physicalLocation;
    assert.strictEqual(loc.region, undefined);
  });

  it('supports custom version string', () => {
    const sarif = toSarif([], '3.0.0');
    assert.strictEqual(sarif.runs[0].tool.driver.version, '3.0.0');
  });

  it('default version matches package.json version', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf-8'));
    const sarif = toSarif([]);
    assert.strictEqual(sarif.runs[0].tool.driver.version, pkg.version);
  });

  it('generates valid JSON', () => {
    const sarif = toSarif([makeFinding(), makeFinding({ ruleId: 'data-leakage', severity: 'critical' })]);
    const json = JSON.stringify(sarif);
    const parsed = JSON.parse(json);
    assert.strictEqual(parsed.version, '2.1.0');
  });
});
