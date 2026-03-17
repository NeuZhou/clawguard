// ClawGuard — YARA Rule Engine
// Lightweight YARA rule parser and matcher (no native deps)
// Supports: plain strings, regex strings (/pattern/), hex strings ({ XX XX }),
//           nocase modifier, conditions: any of them, all of them, N of them, $var

import * as fs from 'fs';
import * as path from 'path';
import { Severity } from './types';

export interface YaraRule {
  id: string;
  meta: Record<string, string>;
  strings: YaraString[];
  condition: string;
}

export interface YaraString {
  name: string;
  value: string;
  type: 'text' | 'regex' | 'hex';
  nocase: boolean;
}

export interface YaraMatch {
  ruleId: string;
  description: string;
  severity: Severity;
  matchedStrings: string[];
}

/** Parse a YARA rule file and return parsed rules */
function parseYaraFile(content: string): YaraRule[] {
  const rules: YaraRule[] = [];
  // Match rule blocks: rule <name> { ... }
  const ruleRegex = /rule\s+(\w+)\s*\{([\s\S]*?)\n\}/g;
  let match;

  while ((match = ruleRegex.exec(content)) !== null) {
    const ruleId = match[1];
    const body = match[2];
    const rule: YaraRule = { id: ruleId, meta: {}, strings: [], condition: '' };

    // Parse meta section
    const metaMatch = body.match(/meta\s*:([\s\S]*?)(?=strings\s*:|condition\s*:|$)/);
    if (metaMatch) {
      const metaLines = metaMatch[1].split('\n');
      for (const line of metaLines) {
        const kv = line.match(/^\s*(\w+)\s*=\s*"([^"]*)"$/);
        if (kv) {
          rule.meta[kv[1]] = kv[2];
        }
      }
    }

    // Parse strings section
    const stringsMatch = body.match(/strings\s*:([\s\S]*?)(?=condition\s*:|$)/);
    if (stringsMatch) {
      const stringsLines = stringsMatch[1].split('\n');
      for (const line of stringsLines) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith('$')) continue;

        // Text string: $name = "value" [nocase]
        const textMatch = trimmed.match(/^(\$\w+)\s*=\s*"([^"]*)"(\s+nocase)?$/);
        if (textMatch) {
          rule.strings.push({
            name: textMatch[1],
            value: textMatch[2],
            type: 'text',
            nocase: !!textMatch[3],
          });
          continue;
        }

        // Regex string: $name = /pattern/
        const regexMatch = trimmed.match(/^(\$\w+)\s*=\s*\/(.*)\/([i]?)$/);
        if (regexMatch) {
          rule.strings.push({
            name: regexMatch[1],
            value: regexMatch[2],
            type: 'regex',
            nocase: regexMatch[3] === 'i',
          });
          continue;
        }

        // Hex string: $name = { XX XX XX }
        const hexMatch = trimmed.match(/^(\$\w+)\s*=\s*\{\s*([0-9A-Fa-f\s]+)\s*\}$/);
        if (hexMatch) {
          rule.strings.push({
            name: hexMatch[1],
            value: hexMatch[2].replace(/\s+/g, ''),
            type: 'hex',
            nocase: false,
          });
          continue;
        }
      }
    }

    // Parse condition section
    const condMatch = body.match(/condition\s*:\s*([\s\S]*?)$/);
    if (condMatch) {
      rule.condition = condMatch[1].trim();
    }

    rules.push(rule);
  }

  return rules;
}

/** Check if a single YARA string matches the content */
function matchString(yaraStr: YaraString, content: string): boolean {
  switch (yaraStr.type) {
    case 'text': {
      if (yaraStr.nocase) {
        return content.toLowerCase().includes(yaraStr.value.toLowerCase());
      }
      return content.includes(yaraStr.value);
    }
    case 'regex': {
      try {
        const flags = yaraStr.nocase ? 'i' : '';
        return new RegExp(yaraStr.value, flags).test(content);
      } catch {
        return false;
      }
    }
    case 'hex': {
      // Convert hex string to actual bytes and check against content buffer
      const hexBytes = yaraStr.value.match(/.{2}/g);
      if (!hexBytes) return false;
      const target = Buffer.from(hexBytes.map(h => parseInt(h, 16)));
      const buf = Buffer.from(content, 'utf-8');
      // Simple substring search in buffer
      for (let i = 0; i <= buf.length - target.length; i++) {
        if (buf.subarray(i, i + target.length).equals(target)) {
          return true;
        }
      }
      return false;
    }
    default:
      return false;
  }
}

/** Evaluate a YARA condition against matched strings */
function evaluateCondition(condition: string, strings: YaraString[], content: string): { matched: boolean; matchedStrings: string[] } {
  const stringMatches = new Map<string, boolean>();
  for (const s of strings) {
    stringMatches.set(s.name, matchString(s, content));
  }

  const matchedStrings = Array.from(stringMatches.entries())
    .filter(([_, v]) => v)
    .map(([k, _]) => k);

  const cond = condition.trim();

  // "any of them"
  if (/^any\s+of\s+them$/i.test(cond)) {
    return { matched: matchedStrings.length > 0, matchedStrings };
  }

  // "all of them"
  if (/^all\s+of\s+them$/i.test(cond)) {
    return { matched: matchedStrings.length === strings.length && strings.length > 0, matchedStrings };
  }

  // "N of them"
  const nOfMatch = cond.match(/^(\d+)\s+of\s+them$/i);
  if (nOfMatch) {
    const n = parseInt(nOfMatch[1], 10);
    return { matched: matchedStrings.length >= n, matchedStrings };
  }

  // Single variable reference: "$var"
  const varMatch = cond.match(/^\$\w+$/);
  if (varMatch) {
    const isMatch = stringMatches.get(cond) ?? false;
    return { matched: isMatch, matchedStrings: isMatch ? [cond] : [] };
  }

  // Boolean combinations with "and" / "or"
  if (/\band\b/.test(cond)) {
    const parts = cond.split(/\s+and\s+/i).map(p => p.trim());
    const allMatch = parts.every(p => {
      if (p.startsWith('$')) return stringMatches.get(p) ?? false;
      return false;
    });
    return { matched: allMatch, matchedStrings: allMatch ? matchedStrings : [] };
  }

  if (/\bor\b/.test(cond)) {
    const parts = cond.split(/\s+or\s+/i).map(p => p.trim());
    const anyMatch = parts.some(p => {
      if (p.startsWith('$')) return stringMatches.get(p) ?? false;
      return false;
    });
    return { matched: anyMatch, matchedStrings: anyMatch ? matchedStrings : [] };
  }

  // Fallback: treat as "any of them" if we have strings
  if (strings.length > 0 && matchedStrings.length > 0) {
    return { matched: true, matchedStrings };
  }

  return { matched: false, matchedStrings: [] };
}

/** Load YARA rules from a directory */
export function loadYaraRules(dir: string): YaraRule[] {
  const resolvedDir = dir.replace(/^~/, process.env.HOME || process.env.USERPROFILE || '');
  if (!fs.existsSync(resolvedDir)) return [];

  const rules: YaraRule[] = [];
  try {
    const files = fs.readdirSync(resolvedDir).filter(f => f.endsWith('.yar') || f.endsWith('.yara'));
    for (const file of files) {
      try {
        const content = fs.readFileSync(path.join(resolvedDir, file), 'utf-8');
        rules.push(...parseYaraFile(content));
      } catch { /* skip invalid files */ }
    }
  } catch { /* skip unreadable dir */ }

  return rules;
}

/** Match loaded YARA rules against text content */
export function matchYaraRules(rules: YaraRule[], content: string): YaraMatch[] {
  const matches: YaraMatch[] = [];

  for (const rule of rules) {
    const { matched, matchedStrings } = evaluateCondition(rule.condition, rule.strings, content);
    if (matched) {
      matches.push({
        ruleId: rule.id,
        description: rule.meta.description || rule.id,
        severity: (rule.meta.severity as Severity) || 'warning',
        matchedStrings,
      });
    }
  }

  return matches;
}
