// ClawGuard — Tests: File Protection

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { fileProtectionRule } from '../../src/rules/file-protection';
import { RuleContext } from '../../src/types';

function ctx(): RuleContext {
  return {
    session: 'test', channel: 'test', timestamp: Date.now(),
    recentMessages: [], recentFindings: [],
  };
}

function detect(content: string) {
  return fileProtectionRule.check(content, 'outbound', ctx());
}

describe('File Deletion Protection', () => {
  it('detects rm -rf /', () => {
    const findings = detect('rm -rf /');
    assert.ok(findings.length > 0);
    assert.strictEqual(findings[0].severity, 'critical');
  });

  it('detects rm -rf ~/.ssh', () => {
    const findings = detect('rm -rf ~/.ssh');
    assert.ok(findings.length > 0);
    assert.strictEqual(findings[0].severity, 'critical');
  });

  it('does NOT flag rm tempfile.txt', () => {
    const findings = detect('rm tempfile.txt');
    assert.strictEqual(findings.length, 0, 'Single file rm should not trigger');
  });

  it('detects Remove-Item -Recurse -Force on user path', () => {
    const findings = detect('Remove-Item -Recurse -Force C:\\Users\\admin');
    assert.ok(findings.length > 0);
    assert.strictEqual(findings[0].severity, 'critical');
  });

  it('detects del /f /s /q *', () => {
    const findings = detect('del /f /s /q *');
    assert.ok(findings.length > 0);
  });

  it('does NOT flag git rm file.txt', () => {
    // git rm is not "rm -rf" — it's a different command
    const findings = detect('git rm file.txt');
    assert.strictEqual(findings.length, 0);
  });

  it('detects rimraf', () => {
    const findings = detect('rimraf node_modules');
    assert.ok(findings.length > 0);
  });

  it('detects shutil.rmtree', () => {
    const findings = detect('shutil.rmtree("/tmp/data")');
    assert.ok(findings.length > 0);
  });

  it('detects fs.rmSync targeting .env', () => {
    const findings = detect('fs.rmSync(".env")');
    assert.ok(findings.length > 0);
  });

  it('detects dd to device', () => {
    const findings = detect('dd if=/dev/zero of=/dev/sda');
    assert.ok(findings.length > 0);
    assert.strictEqual(findings[0].severity, 'critical');
  });
});


