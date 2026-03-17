// ClawGuard — YARA Rule Adapter
// Parses YARA rule files (.yar/.yara) and converts to ClawGuard SecurityRule instances
// YARA is the industry standard for malware pattern matching

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { SecurityRule, SecurityFinding, Direction, RuleContext, Severity } from '../types';

/** Parsed YARA rule structure */
export interface YaraRule {
  name: string;
  tags: string[];
  meta: Record<string, string>;
  strings: YaraString[];
  condition: string;
}

export interface YaraString {
  identifier: string;
  type: 'text' | 'hex' | 'regex';
  value: string;
  modifiers: string[]; // nocase, wide, ascii, fullword, etc.
}

/** Parse a YARA rule file into structured rules */
export function parseYaraFile(content: string): YaraRule[] {
  const rules: YaraRule[] = [];
  // Match: rule <name> [: <tags>] { ... }
  const ruleRegex = /rule\s+(\w+)\s*(?::\s*([\w\s]+))?\s*\{([\s\S]*?)\n\}/g;
  let match: RegExpExecArray | null;

  while ((match = ruleRegex.exec(content)) !== null) {
    const name = match[1];
    const tags = match[2] ? match[2].trim().split(/\s+/) : [];
    const body = match[3];

    const meta = parseMeta(body);
    const strings = parseStrings(body);
    const condition = parseCondition(body);

    rules.push({ name, tags, meta, strings, condition });
  }
  return rules;
}

function parseMeta(body: string): Record<string, string> {
  const meta: Record<string, string> = {};
  const metaMatch = body.match(/meta\s*:\s*([\s\S]*?)(?=strings\s*:|condition\s*:|$)/);
  if (!metaMatch) return meta;
  const lines = metaMatch[1].split('\n');
  for (const line of lines) {
    const kv = line.trim().match(/^(\w+)\s*=\s*"?([^"]*)"?\s*$/);
    if (kv) meta[kv[1]] = kv[2];
  }
  return meta;
}

function parseStrings(body: string): YaraString[] {
  const strings: YaraString[] = [];
  const stringsMatch = body.match(/strings\s*:\s*([\s\S]*?)(?=condition\s*:|$)/);
  if (!stringsMatch) return strings;

  const lines = stringsMatch[1].split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;

    // Text string: $name = "value" [modifiers]
    const textMatch = trimmed.match(/^(\$\w+)\s*=\s*"((?:[^"\\]|\\.)*)"\s*(.*)?$/);
    if (textMatch) {
      const modifiers = textMatch[3] ? textMatch[3].trim().split(/\s+/) : [];
      strings.push({
        identifier: textMatch[1],
        type: 'text',
        value: textMatch[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\'),
        modifiers,
      });
      continue;
    }

    // Regex string: $name = /pattern/ [modifiers]
    const regexMatch = trimmed.match(/^(\$\w+)\s*=\s*\/((?:[^/\\]|\\.)*)\/\s*(.*)?$/);
    if (regexMatch) {
      const modifiers = regexMatch[3] ? regexMatch[3].trim().split(/\s+/) : [];
      strings.push({
        identifier: regexMatch[1],
        type: 'regex',
        value: regexMatch[2],
        modifiers,
      });
      continue;
    }

    // Hex string: $name = { AA BB CC ?? DD }
    const hexMatch = trimmed.match(/^(\$\w+)\s*=\s*\{([^}]*)\}\s*(.*)?$/);
    if (hexMatch) {
      strings.push({
        identifier: hexMatch[1],
        type: 'hex',
        value: hexMatch[2].trim(),
        modifiers: [],
      });
    }
  }
  return strings;
}

function parseCondition(body: string): string {
  const condMatch = body.match(/condition\s*:\s*([\s\S]*?)$/);
  return condMatch ? condMatch[1].trim() : 'any of them';
}

/** Convert a YARA string to a RegExp */
function yaraStringToRegex(s: YaraString): RegExp | null {
  try {
    const flags = s.modifiers.includes('nocase') ? 'gi' : 'g';
    switch (s.type) {
      case 'text': {
        let escaped = s.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        if (s.modifiers.includes('fullword')) {
          escaped = `\\b${escaped}\\b`;
        }
        return new RegExp(escaped, flags);
      }
      case 'regex':
        return new RegExp(s.value, flags.includes('i') ? 'gi' : 'g');
      case 'hex': {
        // Convert hex pattern: "AA BB ?? CC" → regex on raw content
        // ?? = wildcard byte. For text scanning, we convert hex to char-class patterns.
        const hexParts = s.value.split(/\s+/).filter(Boolean);
        let pattern = '';
        for (const part of hexParts) {
          if (part === '??' || part === '?') {
            pattern += '.';
          } else if (part.includes('?')) {
            // Nibble wildcard like A? or ?B
            pattern += '.';
          } else {
            const byte = parseInt(part, 16);
            if (isNaN(byte)) continue;
            if (byte >= 32 && byte < 127) {
              const ch = String.fromCharCode(byte);
              pattern += ch.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            } else {
              pattern += '.';
            }
          }
        }
        return pattern ? new RegExp(pattern, 'g') : null;
      }
    }
  } catch {
    return null;
  }
}

/** Determine severity from YARA rule metadata/tags */
function yaraToSeverity(rule: YaraRule): Severity {
  const tags = rule.tags.map(t => t.toLowerCase());
  const desc = (rule.meta.description || '').toLowerCase();
  if (tags.includes('critical') || desc.includes('critical')) return 'critical';
  if (tags.includes('malware') || tags.includes('exploit') || tags.includes('apt')) return 'critical';
  if (tags.includes('suspicious') || tags.includes('high')) return 'high';
  if (tags.includes('info') || tags.includes('informational')) return 'info';
  // Default based on meta severity field
  const sev = (rule.meta.severity || '').toLowerCase();
  if (sev === 'critical') return 'critical';
  if (sev === 'high') return 'high';
  if (sev === 'low' || sev === 'info') return 'info';
  return 'warning';
}

/** Evaluate a simple YARA condition against match results */
function evaluateCondition(condition: string, matches: Map<string, boolean>, totalStrings: number): boolean {
  const cond = condition.trim().toLowerCase();
  if (cond === 'any of them' || cond.includes('any of them')) {
    return Array.from(matches.values()).some(v => v);
  }
  if (cond === 'all of them' || cond.includes('all of them')) {
    return matches.size >= totalStrings && Array.from(matches.values()).every(v => v);
  }
  // "N of them" pattern
  const nOf = cond.match(/(\d+)\s+of\s+them/);
  if (nOf) {
    const n = parseInt(nOf[1]);
    return Array.from(matches.values()).filter(v => v).length >= n;
  }
  // "$a and $b" / "$a or $b" — basic boolean
  if (cond.includes(' and ')) {
    const parts = cond.split(/\s+and\s+/);
    return parts.every(p => {
      const id = p.trim();
      return id.startsWith('$') ? matches.get(id) === true : true;
    });
  }
  if (cond.includes(' or ')) {
    const parts = cond.split(/\s+or\s+/);
    return parts.some(p => {
      const id = p.trim();
      return id.startsWith('$') ? matches.get(id) === true : true;
    });
  }
  // Single variable
  if (cond.startsWith('$')) {
    return matches.get(cond) === true;
  }
  // Default: any match
  return Array.from(matches.values()).some(v => v);
}

/** Convert a YARA rule to a ClawGuard SecurityRule */
export function convertYaraRule(rule: YaraRule): SecurityRule | null {
  const regexes: { id: string; re: RegExp }[] = [];
  for (const s of rule.strings) {
    const re = yaraStringToRegex(s);
    if (re) regexes.push({ id: s.identifier, re });
  }
  if (regexes.length === 0) return null;

  const severity = yaraToSeverity(rule);
  const description = rule.meta.description || `YARA rule: ${rule.name}`;

  return {
    id: `yara/${rule.name}`,
    name: rule.name,
    description,
    owaspCategory: rule.meta.owasp || 'Custom (YARA)',
    enabled: true,
    check(content: string, _direction: Direction, context: RuleContext): SecurityFinding[] {
      const matches = new Map<string, boolean>();
      let evidence = '';
      for (const { id, re } of regexes) {
        re.lastIndex = 0;
        const m = re.exec(content);
        matches.set(id, !!m);
        if (m && !evidence) evidence = m[0].slice(0, 200);
      }

      if (!evaluateCondition(rule.condition, matches, rule.strings.length)) return [];

      return [{
        id: crypto.randomUUID(),
        timestamp: context.timestamp,
        ruleId: `yara/${rule.name}`,
        ruleName: rule.name,
        severity,
        category: rule.tags[0] || 'yara',
        owaspCategory: rule.meta.owasp || 'Custom (YARA)',
        description,
        evidence,
        session: context.session,
        channel: context.channel,
        action: severity === 'critical' || severity === 'high' ? 'block' : 'alert',
      }];
    },
  };
}

/** Load YARA rules from a .yar/.yara file or directory */
export function loadYaraRules(filePath: string): SecurityRule[] {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) return [];

  const stat = fs.statSync(abs);
  if (stat.isDirectory()) {
    const rules: SecurityRule[] = [];
    const files = fs.readdirSync(abs).filter(f => f.endsWith('.yar') || f.endsWith('.yara'));
    for (const file of files) {
      rules.push(...loadYaraRulesFromFile(path.join(abs, file)));
    }
    return rules;
  }
  return loadYaraRulesFromFile(abs);
}

/** Load YARA rules from a single file */
export function loadYaraRulesFromFile(filePath: string): SecurityRule[] {
  try {
    const raw = fs.readFileSync(filePath, 'utf-8');
    return parseYaraContent(raw);
  } catch {
    return [];
  }
}

/** Parse YARA content string into SecurityRule[] */
export function parseYaraContent(content: string): SecurityRule[] {
  const parsed = parseYaraFile(content);
  const rules: SecurityRule[] = [];
  for (const rule of parsed) {
    const converted = convertYaraRule(rule);
    if (converted) rules.push(converted);
  }
  return rules;
}

/** Create a ClawGuardPlugin from YARA rule files */
export function yaraPlugin(name: string, paths: string[]): { name: string; version: string; rules: SecurityRule[]; meta: { description: string } } {
  const rules: SecurityRule[] = [];
  for (const p of paths) {
    rules.push(...loadYaraRules(p));
  }
  return {
    name: `yara/${name}`,
    version: '1.0.0',
    rules,
    meta: { description: `YARA rules adapter: ${name} (${rules.length} rules)` },
  };
}
