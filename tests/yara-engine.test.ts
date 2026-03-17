// ClawGuard - Tests: YARA Rule Support (Issue #2)

import { describe, it, afterEach } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { loadYaraRules, matchYaraRules, YaraMatch } from '../src/yara-engine';

let tmpDirs: string[] = [];

function makeTmpDir(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-yara-'));
  tmpDirs.push(d);
  return d;
}

afterEach(() => {
  for (const d of tmpDirs) {
    try { fs.rmSync(d, { recursive: true }); } catch {}
  }
  tmpDirs = [];
});

describe('YARA Engine', () => {
  it('loads a simple YARA rule file', () => {
    const dir = makeTmpDir();
    const yara = `rule test_rule {
  meta:
    description = "Test YARA rule"
    severity = "high"
  strings:
    $a = "malicious_payload"
  condition:
    $a
}`;
    fs.writeFileSync(path.join(dir, 'test.yar'), yara);
    const rules = loadYaraRules(dir);
    assert.ok(rules.length > 0);
    assert.strictEqual(rules[0].id, 'test_rule');
  });

  it('matches a YARA rule against text', () => {
    const dir = makeTmpDir();
    const yara = `rule detect_evil {
  meta:
    description = "Detect evil string"
    severity = "critical"
  strings:
    $evil = "evil_command_here"
  condition:
    $evil
}`;
    fs.writeFileSync(path.join(dir, 'evil.yar'), yara);
    const rules = loadYaraRules(dir);
    const matches = matchYaraRules(rules, 'this contains evil_command_here in the content');
    assert.ok(matches.length > 0);
    assert.strictEqual(matches[0].ruleId, 'detect_evil');
  });

  it('supports multiple strings in one rule', () => {
    const dir = makeTmpDir();
    const yara = `rule multi_string {
  meta:
    description = "Multiple strings"
    severity = "warning"
  strings:
    $a = "bad_thing_one"
    $b = "bad_thing_two"
  condition:
    any of them
}`;
    fs.writeFileSync(path.join(dir, 'multi.yar'), yara);
    const rules = loadYaraRules(dir);
    
    const m1 = matchYaraRules(rules, 'found bad_thing_one');
    assert.ok(m1.length > 0);
    
    const m2 = matchYaraRules(rules, 'found bad_thing_two');
    assert.ok(m2.length > 0);
  });

  it('supports "all of them" condition', () => {
    const dir = makeTmpDir();
    const yara = `rule all_required {
  meta:
    description = "All strings required"
    severity = "high"
  strings:
    $a = "alpha"
    $b = "beta"
  condition:
    all of them
}`;
    fs.writeFileSync(path.join(dir, 'all.yar'), yara);
    const rules = loadYaraRules(dir);
    
    const m1 = matchYaraRules(rules, 'only alpha here');
    assert.strictEqual(m1.length, 0);
    
    const m2 = matchYaraRules(rules, 'both alpha and beta here');
    assert.ok(m2.length > 0);
  });

  it('supports regex strings with /pattern/', () => {
    const dir = makeTmpDir();
    const yara = `rule regex_rule {
  meta:
    description = "Regex pattern"
    severity = "high"
  strings:
    $r = /secret_[a-z]{3,10}_key/
  condition:
    $r
}`;
    fs.writeFileSync(path.join(dir, 'regex.yar'), yara);
    const rules = loadYaraRules(dir);
    const matches = matchYaraRules(rules, 'found secret_abcde_key in config');
    assert.ok(matches.length > 0);
  });

  it('supports case-insensitive string matching', () => {
    const dir = makeTmpDir();
    const yara = `rule nocase_rule {
  meta:
    description = "Case insensitive"
    severity = "warning"
  strings:
    $a = "MaLiCiOuS" nocase
  condition:
    $a
}`;
    fs.writeFileSync(path.join(dir, 'nocase.yar'), yara);
    const rules = loadYaraRules(dir);
    const matches = matchYaraRules(rules, 'this is malicious content');
    assert.ok(matches.length > 0);
  });

  it('supports hex strings', () => {
    const dir = makeTmpDir();
    const yara = `rule hex_rule {
  meta:
    description = "Hex pattern"
    severity = "critical"
  strings:
    $hex = { 48 65 6C 6C 6F }
  condition:
    $hex
}`;
    fs.writeFileSync(path.join(dir, 'hex.yar'), yara);
    const rules = loadYaraRules(dir);
    const matches = matchYaraRules(rules, 'Hello World');
    assert.ok(matches.length > 0);
  });

  it('does NOT match when content is clean', () => {
    const dir = makeTmpDir();
    const yara = `rule no_match {
  meta:
    description = "Should not match"
    severity = "critical"
  strings:
    $a = "very_specific_evil_string_12345"
  condition:
    $a
}`;
    fs.writeFileSync(path.join(dir, 'nomatch.yar'), yara);
    const rules = loadYaraRules(dir);
    const matches = matchYaraRules(rules, 'perfectly safe content');
    assert.strictEqual(matches.length, 0);
  });

  it('loads multiple rules from one file', () => {
    const dir = makeTmpDir();
    const yara = `rule rule_one {
  meta:
    description = "First rule"
    severity = "warning"
  strings:
    $a = "pattern_one"
  condition:
    $a
}

rule rule_two {
  meta:
    description = "Second rule"
    severity = "high"
  strings:
    $b = "pattern_two"
  condition:
    $b
}`;
    fs.writeFileSync(path.join(dir, 'multi.yar'), yara);
    const rules = loadYaraRules(dir);
    assert.ok(rules.length >= 2);
  });

  it('loads .yar and .yara file extensions', () => {
    const dir = makeTmpDir();
    const yara = `rule ext_test {
  meta:
    description = "Extension test"
    severity = "info"
  strings:
    $a = "testpattern"
  condition:
    $a
}`;
    fs.writeFileSync(path.join(dir, 'test.yara'), yara);
    const rules = loadYaraRules(dir);
    assert.ok(rules.length > 0);
  });

  it('handles non-existent directory gracefully', () => {
    const rules = loadYaraRules('/nonexistent/path/xyz');
    assert.strictEqual(rules.length, 0);
  });

  it('skips invalid YARA files without crashing', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'bad.yar'), '{{{{ NOT VALID YARA }}}}');
    const rules = loadYaraRules(dir);
    // Should not throw, may return 0 or skip invalid
    assert.ok(true);
  });

  it('returns match metadata including severity', () => {
    const dir = makeTmpDir();
    const yara = `rule meta_test {
  meta:
    description = "Metadata test"
    severity = "critical"
    author = "test"
  strings:
    $a = "trigger_this"
  condition:
    $a
}`;
    fs.writeFileSync(path.join(dir, 'meta.yar'), yara);
    const rules = loadYaraRules(dir);
    const matches = matchYaraRules(rules, 'trigger_this content');
    assert.ok(matches.length > 0);
    assert.strictEqual(matches[0].severity, 'critical');
    assert.ok(matches[0].description.length > 0);
  });

  it('supports numeric condition like "2 of them"', () => {
    const dir = makeTmpDir();
    const yara = `rule count_rule {
  meta:
    description = "Count condition"
    severity = "high"
  strings:
    $a = "one"
    $b = "two"
    $c = "three"
  condition:
    2 of them
}`;
    fs.writeFileSync(path.join(dir, 'count.yar'), yara);
    const rules = loadYaraRules(dir);
    
    const m1 = matchYaraRules(rules, 'only one here');
    assert.strictEqual(m1.length, 0);
    
    const m2 = matchYaraRules(rules, 'one and two here');
    assert.ok(m2.length > 0);
  });
});
