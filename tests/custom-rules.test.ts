// Carapace - Tests: Custom Rules

import { describe, it, afterEach } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { loadCustomRules, runSecurityScan } from '../src/security-engine';
import { store } from '../src/store';
import { RuleContext } from '../src/types';

let tmpDirs: string[] = [];

function makeCtx(): RuleContext {
  return { session: 'test', channel: 'test', timestamp: Date.now(), recentMessages: [], recentFindings: [] };
}

function makeTmpDir(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ow-custom-'));
  tmpDirs.push(d);
  return d;
}

afterEach(() => {
  for (const d of tmpDirs) {
    try { fs.rmSync(d, { recursive: true }); } catch {}
  }
  tmpDirs = [];
  loadCustomRules('/nonexistent'); // reset custom rules
});

describe('Custom Rules', () => {
  it('loads YAML file with regex pattern', () => {
    store.init();
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'rules.yaml'), `name: test
version: "1.0"
rules:
  - id: regex-test
    description: "Regex rule"
    severity: high
    patterns:
      - regex: "secret_token_[a-z]+"
    action: alert
`);
    loadCustomRules(dir);
    const findings = runSecurityScan('found secret_token_abc here', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.ruleId === 'regex-test'));
  });

  it('loads YAML file with keyword pattern', () => {
    store.init();
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'rules.yaml'), `name: test
version: "1.0"
rules:
  - id: keyword-test
    description: "Keyword rule"
    severity: warning
    patterns:
      - keyword: dangerousword
    action: log
`);
    loadCustomRules(dir);
    const findings = runSecurityScan('this has dangerousword in it', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.ruleId === 'keyword-test'));
  });

  it('loads multiple rules from one file', () => {
    store.init();
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'multi.yaml'), `name: multi
version: "1.0"
rules:
  - id: rule-a
    description: "Rule A"
    severity: warning
    patterns:
      - keyword: alpha
    action: alert
  - id: rule-b
    description: "Rule B"
    severity: high
    patterns:
      - keyword: beta
    action: alert
`);
    loadCustomRules(dir);
    const f1 = runSecurityScan('alpha content', 'inbound', makeCtx());
    assert.ok(f1.some(f => f.ruleId === 'rule-a'));
    const f2 = runSecurityScan('beta content', 'inbound', makeCtx());
    assert.ok(f2.some(f => f.ruleId === 'rule-b'));
  });

  it('skips invalid YAML files', () => {
    store.init();
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'bad.yaml'), '{{{{not valid yaml at all}}}}');
    loadCustomRules(dir); // should not throw
    assert.ok(true);
  });

  it('handles YAML with comments', () => {
    store.init();
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'commented.yaml'), `# This is a comment
name: commented
version: "1.0"
# Another comment
rules:
  - id: comment-test
    description: "Commented rule"
    severity: warning
    patterns:
      - keyword: commentword
    action: alert
`);
    loadCustomRules(dir);
    const findings = runSecurityScan('commentword found', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.ruleId === 'comment-test'));
  });

  it('handles YAML with quoted values containing colons', () => {
    store.init();
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'quoted.yaml'), `name: "test: rules"
version: "1.0"
rules:
  - id: quoted-test
    description: "Rule with: colon"
    severity: warning
    patterns:
      - keyword: testpattern
    action: alert
`);
    loadCustomRules(dir);
    const findings = runSecurityScan('testpattern here', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.ruleId === 'quoted-test'));
  });

  it('custom rule in runSecurityScan produces finding with correct category', () => {
    store.init();
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'cat.yaml'), `name: cat-test
version: "1.0"
rules:
  - id: cat-rule
    description: "Category test"
    severity: high
    patterns:
      - keyword: catword
    action: alert
`);
    loadCustomRules(dir);
    const findings = runSecurityScan('catword', 'inbound', makeCtx());
    const f = findings.find(f => f.ruleId === 'cat-rule');
    assert.ok(f);
    assert.strictEqual(f!.category, 'custom');
  });

  it('empty rules dir loads no custom rules', () => {
    store.init();
    const dir = makeTmpDir();
    loadCustomRules(dir);
    // No crash, no custom rules
    const findings = runSecurityScan('safe content', 'inbound', makeCtx());
    assert.ok(!findings.some(f => f.category === 'custom'));
  });
});

