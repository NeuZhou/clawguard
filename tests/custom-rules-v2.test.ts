// ClawGuard - Tests: Custom Security Rules Support (Issue #8)
// Tests for JSON-based custom rules and programmatic rule registration

import { describe, it, afterEach, beforeEach } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { loadCustomRules, runSecurityScan, registerCustomRule, clearCustomRules } from '../src/security-engine';
import { store } from '../src/store';
import { RuleContext, SecurityRule, SecurityFinding, Direction } from '../src/types';

let tmpDirs: string[] = [];

function makeCtx(): RuleContext {
  return { session: 'test', channel: 'test', timestamp: Date.now(), recentMessages: [], recentFindings: [] };
}

function makeTmpDir(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-custom-'));
  tmpDirs.push(d);
  return d;
}

afterEach(() => {
  for (const d of tmpDirs) {
    try { fs.rmSync(d, { recursive: true }); } catch {}
  }
  tmpDirs = [];
  clearCustomRules();
});

beforeEach(() => {
  store.init();
});

describe('Custom Security Rules - Programmatic API', () => {
  it('registerCustomRule adds a custom rule', () => {
    const rule: SecurityRule = {
      id: 'custom-api-test',
      name: 'Custom API Test',
      description: 'Test rule registered via API',
      owaspCategory: 'Custom',
      enabled: true,
      check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
        if (content.includes('api-test-trigger')) {
          return [{
            id: 'test', timestamp: context.timestamp, ruleId: 'custom-api-test',
            ruleName: 'Custom API Test', severity: 'high', category: 'custom',
            description: 'Triggered', action: 'alert',
          }];
        }
        return [];
      }
    };
    registerCustomRule(rule);
    const findings = runSecurityScan('api-test-trigger found', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.ruleId === 'custom-api-test'));
  });

  it('clearCustomRules removes all custom rules', () => {
    registerCustomRule({
      id: 'temp-rule', name: 'Temp', description: 'Temp', owaspCategory: 'Custom',
      enabled: true,
      check: (c) => c.includes('temp-trigger') ? [{ id: 't', timestamp: Date.now(), ruleId: 'temp-rule', ruleName: 'T', severity: 'warning', category: 'custom', description: 'T', action: 'log' }] : [],
    });
    clearCustomRules();
    const findings = runSecurityScan('temp-trigger', 'inbound', makeCtx());
    assert.ok(!findings.some(f => f.ruleId === 'temp-rule'));
  });
});

describe('Custom Security Rules - JSON Format', () => {
  it('loads JSON rule files', () => {
    const dir = makeTmpDir();
    const json = JSON.stringify({
      name: 'json-test',
      version: '1.0',
      rules: [{
        id: 'json-rule-1',
        description: 'JSON format rule',
        severity: 'warning',
        patterns: [{ keyword: 'json-trigger' }],
        action: 'alert',
      }]
    });
    fs.writeFileSync(path.join(dir, 'rules.json'), json);
    loadCustomRules(dir);
    const findings = runSecurityScan('json-trigger found', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.ruleId === 'json-rule-1'));
  });

  it('loads both YAML and JSON rules from same directory', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'yaml-rules.yaml'), `name: yaml
version: "1.0"
rules:
  - id: yaml-coexist
    description: "YAML rule"
    severity: warning
    patterns:
      - keyword: yamltrigger
    action: alert
`);
    const json = JSON.stringify({
      name: 'json-coexist',
      version: '1.0',
      rules: [{ id: 'json-coexist', description: 'JSON rule', severity: 'high', patterns: [{ keyword: 'jsontrigger' }], action: 'alert' }]
    });
    fs.writeFileSync(path.join(dir, 'json-rules.json'), json);
    loadCustomRules(dir);

    const f1 = runSecurityScan('yamltrigger', 'inbound', makeCtx());
    assert.ok(f1.some(f => f.ruleId === 'yaml-coexist'));

    const f2 = runSecurityScan('jsontrigger', 'inbound', makeCtx());
    assert.ok(f2.some(f => f.ruleId === 'json-coexist'));
  });

  it('JSON rules with regex patterns', () => {
    const dir = makeTmpDir();
    const json = JSON.stringify({
      name: 'json-regex',
      version: '1.0',
      rules: [{
        id: 'json-regex-rule',
        description: 'JSON regex',
        severity: 'high',
        patterns: [{ regex: 'secret_[0-9]{4}' }],
        action: 'alert',
      }]
    });
    fs.writeFileSync(path.join(dir, 'regex.json'), json);
    loadCustomRules(dir);
    const findings = runSecurityScan('found secret_1234 here', 'inbound', makeCtx());
    assert.ok(findings.some(f => f.ruleId === 'json-regex-rule'));
  });

  it('skips invalid JSON files gracefully', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'bad.json'), '{{{invalid json}}}');
    loadCustomRules(dir); // Should not throw
    assert.ok(true);
  });
});
