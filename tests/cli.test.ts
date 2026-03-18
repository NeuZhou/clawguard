// ClawGuard - Tests: CLI Module
// Tests for argument parsing, output formatting, and command dispatch

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..');

describe('CLI Module', () => {
  it('CLI entry point exists', () => {
    const cliPath = path.join(ROOT, 'src', 'cli.ts');
    assert.ok(fs.existsSync(cliPath), 'cli.ts should exist');
  });

  it('CLI source contains main function', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes('function main'), 'Should have main function');
  });

  it('CLI has scan command handler', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes("'scan'"), 'Should handle scan command');
  });

  it('CLI has check command handler', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes("'check'"), 'Should handle check command');
  });

  it('CLI has sanitize command handler', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes("'sanitize'"), 'Should handle sanitize command');
  });

  it('CLI has intent-check command handler', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes("'intent-check'"), 'Should handle intent-check command');
  });

  it('CLI has init command handler', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes("'init'"), 'Should handle init command');
  });

  it('CLI has version command handler', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes("'version'"), 'Should handle version command');
  });

  it('CLI has help command handler', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes("'help'"), 'Should handle help command');
  });

  it('CLI supports --strict flag', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes("'--strict'"), 'Should support --strict flag');
  });

  it('CLI supports --format option', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes("'--format'"), 'Should support --format option');
  });

  it('CLI has VERSION constant', () => {
    const content = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    assert.ok(content.includes('VERSION'), 'Should have VERSION constant');
  });

  it('CLI version matches package.json version', () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf-8'));
    const cliContent = fs.readFileSync(path.join(ROOT, 'src', 'cli.ts'), 'utf-8');
    // CLI should read version from package.json, not hardcode it
    assert.ok(
      cliContent.includes("require('../package.json')") ||
      cliContent.includes('readFileSync') && cliContent.includes('package.json'),
      'CLI should read version from package.json instead of hardcoding'
    );
  });
});
