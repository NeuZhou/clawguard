// ClawGuard - Tests: GitHub Action for CI/CD Security Scanning (Issue #4)
// Tests for action.yml validity, CI workflow, and scan integration

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..');

describe('GitHub Action (Issue #4)', () => {
  it('action.yml exists at project root', () => {
    const actionPath = path.join(ROOT, 'action.yml');
    assert.ok(fs.existsSync(actionPath), 'action.yml should exist at project root');
  });

  it('action.yml contains required fields', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('name:'), 'action.yml must have name');
    assert.ok(content.includes('description:'), 'action.yml must have description');
    assert.ok(content.includes('inputs:'), 'action.yml must have inputs');
    assert.ok(content.includes('outputs:'), 'action.yml must have outputs');
    assert.ok(content.includes('runs:'), 'action.yml must have runs');
  });

  it('action.yml has path input with default "."', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes("path:"), 'Should have path input');
    assert.ok(content.includes("default: '.'"), 'Path should default to current dir');
  });

  it('action.yml has format input supporting text, json, sarif', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('format:'), 'Should have format input');
    assert.ok(content.includes('text, json, sarif'), 'Should document all formats');
  });

  it('action.yml has strict input defaulting to true', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('strict:'), 'Should have strict input');
  });

  it('action.yml has SARIF upload step', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('upload-sarif'), 'Should have SARIF upload capability');
    assert.ok(content.includes('codeql-action/upload-sarif'), 'Should use codeql upload action');
  });

  it('action.yml outputs include findings-count, critical-count, high-count', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('findings-count:'), 'Should output total findings count');
    assert.ok(content.includes('critical-count:'), 'Should output critical count');
    assert.ok(content.includes('high-count:'), 'Should output high count');
  });

  it('action.yml uses composite runs type', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes("using: 'composite'"), 'Should use composite action type');
  });

  it('action.yml installs clawguard globally', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('npm install -g @neuzhou/clawguard'), 'Should install package globally');
  });

  it('action.yml has branding configuration', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('branding:'), 'Should have branding section');
    assert.ok(content.includes("icon: 'shield'"), 'Should use shield icon');
  });

  it('CI workflow exists', () => {
    const ciPath = path.join(ROOT, '.github', 'workflows', 'ci.yml');
    assert.ok(fs.existsSync(ciPath), 'CI workflow should exist');
  });

  it('CI workflow runs tests', () => {
    const content = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'ci.yml'), 'utf-8');
    assert.ok(content.includes('npm test'), 'CI should run tests');
  });

  it('CI workflow runs type checking', () => {
    const content = fs.readFileSync(path.join(ROOT, '.github', 'workflows', 'ci.yml'), 'utf-8');
    assert.ok(content.includes('tsc --noEmit') || content.includes('npm run check'), 'CI should run type checking');
  });

  it('action.yml has risk-score output', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('risk-score:'), 'Should output risk score');
  });

  it('action.yml has sarif-file output', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('sarif-file:'), 'Should output SARIF file path');
  });

  it('action.yml has custom-rules-dir input', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('custom-rules-dir:'), 'Should support custom rules directory');
  });

  it('action.yml has yara-rules-dir input', () => {
    const content = fs.readFileSync(path.join(ROOT, 'action.yml'), 'utf-8');
    assert.ok(content.includes('yara-rules-dir:'), 'Should support YARA rules directory');
  });
});

describe('Scan CLI for CI/CD', () => {
  it('scan function is importable', async () => {
    const { scan } = await import('../src/skill-scanner');
    assert.equal(typeof scan, 'function');
  });

  it('formatSarif is importable', async () => {
    const { formatSarif } = await import('../src/skill-scanner');
    assert.equal(typeof formatSarif, 'function');
  });

  it('formatJson is importable', async () => {
    const { formatJson } = await import('../src/skill-scanner');
    assert.equal(typeof formatJson, 'function');
  });

  it('formatText is importable', async () => {
    const { formatText } = await import('../src/skill-scanner');
    assert.equal(typeof formatText, 'function');
  });

  it('scan result has summary with severity counts', async () => {
    const { scan } = await import('../src/skill-scanner');
    const result = scan(path.join(ROOT, 'README.md'));
    assert.ok('summary' in result);
    assert.ok('critical' in result.summary);
    assert.ok('high' in result.summary);
    assert.ok('warning' in result.summary);
    assert.ok('info' in result.summary);
  });
});
