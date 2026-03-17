// ClawGuard — Semgrep YAML Rule Adapter
// Converts Semgrep rule format to ClawGuard SecurityRule instances
// Reference: https://semgrep.dev/docs/writing-rules/rule-syntax

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { SecurityRule, SecurityFinding, Direction, RuleContext, Severity } from '../types';

/** Semgrep rule YAML structure (subset we support) */
export interface SemgrepRule {
  id: string;
  message: string;
  severity: 'ERROR' | 'WARNING' | 'INFO';
  languages?: string[];
  metadata?: {
    category?: string;
    cwe?: string | string[];
    owasp?: string | string[];
    confidence?: string;
    technology?: string[];
    references?: string[];
    [key: string]: unknown;
  };
  patterns?: SemgrepPattern[];
  pattern?: string;
  'pattern-either'?: SemgrepPattern[];
  'pattern-regex'?: string;
  'pattern-not'?: string;
  'pattern-not-regex'?: string;
  fix?: string;
}

export interface SemgrepPattern {
  pattern?: string;
  'pattern-regex'?: string;
  'pattern-either'?: SemgrepPattern[];
  'pattern-not'?: string;
  'pattern-not-regex'?: string;
  'metavariable-regex'?: { metavariable: string; regex: string };
}

export interface SemgrepRuleFile {
  rules: SemgrepRule[];
}

/** Map Semgrep severity to ClawGuard severity */
function mapSeverity(s: string): Severity {
  switch (s?.toUpperCase()) {
    case 'ERROR': return 'high';
    case 'WARNING': return 'warning';
    case 'INFO': return 'info';
    default: return 'warning';
  }
}

/** Extract OWASP category from metadata */
function extractOwasp(meta?: SemgrepRule['metadata']): string {
  if (!meta?.owasp) return 'Custom (Semgrep)';
  const owasp = Array.isArray(meta.owasp) ? meta.owasp[0] : meta.owasp;
  return String(owasp);
}

/** Extract category from metadata */
function extractCategory(meta?: SemgrepRule['metadata']): string {
  return meta?.category || 'semgrep';
}

/**
 * Collect all regex and literal patterns from a Semgrep rule into a flat list.
 * Literal patterns are escaped and converted to regex.
 */
function collectPatterns(rule: SemgrepRule): { positive: RegExp[]; negative: RegExp[] } {
  const positive: RegExp[] = [];
  const negative: RegExp[] = [];

  const addPattern = (p: string | undefined, target: RegExp[]) => {
    if (!p) return;
    try {
      // Semgrep patterns use `...` as ellipsis wildcard and $VAR as metavars
      // Convert to regex: `...` → `[\s\S]*?`, `$VAR` → `\S+`
      const escaped = p
        .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')  // escape regex chars
        .replace(/\\\.\\\.\\\./g, '[\\s\\S]*?')    // restore ... → wildcard
        .replace(/\\\$[A-Z_][A-Z0-9_]*/g, '\\S+'); // $VAR → word match
      target.push(new RegExp(escaped, 'i'));
    } catch { /* skip invalid */ }
  };

  const addRegex = (r: string | undefined, target: RegExp[]) => {
    if (!r) return;
    try { target.push(new RegExp(r, 'im')); } catch { /* skip */ }
  };

  const processPatternList = (patterns: SemgrepPattern[] | undefined) => {
    if (!patterns) return;
    for (const p of patterns) {
      addPattern(p.pattern, positive);
      addRegex(p['pattern-regex'], positive);
      addPattern(p['pattern-not'], negative);
      addRegex(p['pattern-not-regex'], negative);
      if (p['pattern-either']) processPatternList(p['pattern-either']);
      if (p['metavariable-regex']) {
        addRegex(p['metavariable-regex'].regex, positive);
      }
    }
  };

  // Top-level patterns
  addPattern(rule.pattern, positive);
  addRegex(rule['pattern-regex'], positive);
  addPattern(rule['pattern-not'], negative);
  addRegex(rule['pattern-not-regex'], negative);
  processPatternList(rule.patterns);
  processPatternList(rule['pattern-either']);

  return { positive, negative };
}

/** Convert a single Semgrep rule to a ClawGuard SecurityRule */
export function convertSemgrepRule(rule: SemgrepRule): SecurityRule | null {
  const { positive, negative } = collectPatterns(rule);
  if (positive.length === 0) return null; // No patterns we can use

  const severity = mapSeverity(rule.severity);
  const category = extractCategory(rule.metadata);
  const owasp = extractOwasp(rule.metadata);

  return {
    id: `semgrep/${rule.id}`,
    name: rule.id,
    description: rule.message || rule.id,
    owaspCategory: owasp,
    enabled: true,
    check(content: string, _direction: Direction, context: RuleContext): SecurityFinding[] {
      // Check negative patterns first (exclusions)
      for (const neg of negative) {
        neg.lastIndex = 0;
        if (neg.test(content)) return [];
      }

      // Check positive patterns
      for (const pos of positive) {
        pos.lastIndex = 0;
        const match = pos.exec(content);
        if (match) {
          return [{
            id: crypto.randomUUID(),
            timestamp: context.timestamp,
            ruleId: `semgrep/${rule.id}`,
            ruleName: rule.id,
            severity,
            category,
            owaspCategory: owasp,
            description: rule.message || rule.id,
            evidence: match[0].slice(0, 200),
            session: context.session,
            channel: context.channel,
            action: severity === 'high' || severity === 'critical' ? 'block' : 'alert',
          }];
        }
      }
      return [];
    },
  };
}

/** Minimal YAML parser for Semgrep rule files (no dependency) */
function parseSimpleSemgrepYaml(raw: string): SemgrepRuleFile | null {
  try {
    // We support the common subset: rules array with pattern/pattern-regex/message/severity/id
    const result: SemgrepRuleFile = { rules: [] };
    const lines = raw.split('\n');
    let current: Record<string, any> | null = null;
    let inMetadata = false;
    let inPatterns = false;
    let inPatternEither = false;
    let currentSubPattern: Record<string, any> | null = null;

    const val = (line: string, key: string): string => {
      const after = line.slice(line.indexOf(key) + key.length).trim();
      // Strip quotes
      if ((after.startsWith('"') && after.endsWith('"')) || (after.startsWith("'") && after.endsWith("'"))) {
        return after.slice(1, -1);
      }
      return after;
    };

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trimEnd();
      const stripped = trimmed.trim();

      if (!stripped || stripped.startsWith('#')) continue;

      // Detect indentation level
      const indent = trimmed.length - stripped.length;

      // New rule
      if (stripped.startsWith('- id:')) {
        if (current) result.rules.push(current as any);
        current = { id: val(stripped, '- id:') };
        inMetadata = false;
        inPatterns = false;
        inPatternEither = false;
        currentSubPattern = null;
        continue;
      }

      if (!current) continue;

      // Top-level rule fields (indent typically 4 or 6)
      if (stripped.startsWith('message:')) {
        // Handle multi-line: check if value is on same line
        const v = val(stripped, 'message:');
        if (v.startsWith('>') || v.startsWith('|') || v === '') {
          // Collect following indented lines
          const msgLines: string[] = [];
          while (i + 1 < lines.length) {
            const next = lines[i + 1];
            const nextStripped = next.trim();
            const nextIndent = next.length - next.trimStart().length;
            if (nextIndent > indent && nextStripped) {
              msgLines.push(nextStripped);
              i++;
            } else break;
          }
          current.message = msgLines.join(' ');
        } else {
          current.message = v;
        }
        inMetadata = false; inPatterns = false; inPatternEither = false;
      } else if (stripped.startsWith('severity:')) {
        current.severity = val(stripped, 'severity:').toUpperCase();
        inMetadata = false;
      } else if (stripped.startsWith('languages:')) {
        // Could be inline array or block
        const v = val(stripped, 'languages:');
        if (v.startsWith('[')) {
          current.languages = v.replace(/[\[\]]/g, '').split(',').map((s: string) => s.trim());
        } else {
          current.languages = [];
        }
        inMetadata = false;
      } else if (stripped === 'metadata:') {
        current.metadata = current.metadata || {};
        inMetadata = true; inPatterns = false; inPatternEither = false;
      } else if (stripped === 'patterns:') {
        current.patterns = current.patterns || [];
        inPatterns = true; inPatternEither = false; inMetadata = false;
      } else if (stripped === 'pattern-either:') {
        current['pattern-either'] = current['pattern-either'] || [];
        inPatternEither = true; inPatterns = false; inMetadata = false;
      } else if (stripped.startsWith('pattern-regex:')) {
        current['pattern-regex'] = val(stripped, 'pattern-regex:');
        inMetadata = false; inPatterns = false; inPatternEither = false;
      } else if (stripped.startsWith('pattern-not-regex:')) {
        current['pattern-not-regex'] = val(stripped, 'pattern-not-regex:');
      } else if (stripped.startsWith('pattern-not:')) {
        current['pattern-not'] = val(stripped, 'pattern-not:');
      } else if (stripped.startsWith('pattern:') && !inPatterns && !inPatternEither) {
        current.pattern = val(stripped, 'pattern:');
        inMetadata = false;
      } else if (stripped.startsWith('fix:')) {
        current.fix = val(stripped, 'fix:');
      } else if (inMetadata) {
        // Parse metadata key-value
        const colonIdx = stripped.indexOf(':');
        if (colonIdx > 0) {
          const k = stripped.slice(0, colonIdx).trim();
          const v = stripped.slice(colonIdx + 1).trim();
          current.metadata![k] = v.replace(/^["']|["']$/g, '');
        }
      } else if (inPatterns || inPatternEither) {
        const target = inPatternEither ? (current['pattern-either'] || []) : (current.patterns || []);
        if (stripped.startsWith('- pattern-regex:')) {
          target.push({ 'pattern-regex': val(stripped, '- pattern-regex:') });
        } else if (stripped.startsWith('- pattern-not-regex:')) {
          target.push({ 'pattern-not-regex': val(stripped, '- pattern-not-regex:') });
        } else if (stripped.startsWith('- pattern-not:')) {
          target.push({ 'pattern-not': val(stripped, '- pattern-not:') });
        } else if (stripped.startsWith('- pattern:')) {
          target.push({ pattern: val(stripped, '- pattern:') });
        }
        if (inPatternEither) current['pattern-either'] = target;
        else current.patterns = target;
      }
    }
    if (current) result.rules.push(current as any);
    return result.rules.length > 0 ? result : null;
  } catch {
    return null;
  }
}

/** Load Semgrep rules from a YAML file or directory */
export function loadSemgrepRules(filePath: string): SecurityRule[] {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) return [];

  const stat = fs.statSync(abs);
  if (stat.isDirectory()) {
    const rules: SecurityRule[] = [];
    const files = fs.readdirSync(abs).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
    for (const file of files) {
      rules.push(...loadSemgrepRulesFromFile(path.join(abs, file)));
    }
    return rules;
  }

  return loadSemgrepRulesFromFile(abs);
}

/** Load Semgrep rules from a single YAML file */
export function loadSemgrepRulesFromFile(filePath: string): SecurityRule[] {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    return parseSemgrepYaml(raw);
  } catch {
    return [];
  }
}

/** Parse Semgrep YAML string into SecurityRule[] */
export function parseSemgrepYaml(yaml: string): SecurityRule[] {
  const parsed = parseSimpleSemgrepYaml(yaml);
  if (!parsed) return [];
  const rules: SecurityRule[] = [];
  for (const rule of parsed.rules) {
    const converted = convertSemgrepRule(rule);
    if (converted) rules.push(converted);
  }
  return rules;
}

/** Create a ClawGuardPlugin from Semgrep rule files */
export function semgrepPlugin(name: string, paths: string[]): { name: string; version: string; rules: SecurityRule[]; meta: { description: string } } {
  const rules: SecurityRule[] = [];
  for (const p of paths) {
    rules.push(...loadSemgrepRules(p));
  }
  return {
    name: `semgrep/${name}`,
    version: '1.0.0',
    rules,
    meta: { description: `Semgrep rules adapter: ${name} (${rules.length} rules)` },
  };
}
