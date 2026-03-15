// OpenClaw Watch — Security Engine
// OWASP LLM Top 10 aligned rule pipeline

import * as fs from 'fs';
import * as path from 'path';
import { SecurityFinding, SecurityRule, Direction, RuleContext, CustomRuleDefinition, Severity } from './types';
import { builtinRules } from './rules';
import { store } from './store';
import * as crypto from 'crypto';

let customRulesLoaded: { id: string; check: SecurityRule['check'] }[] = [];

export function loadCustomRules(dir: string): void {
  customRulesLoaded = [];
  const resolvedDir = dir.replace(/^~/, process.env.HOME || process.env.USERPROFILE || '');
  if (!fs.existsSync(resolvedDir)) return;

  const files = fs.readdirSync(resolvedDir).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
  for (const file of files) {
    try {
      const raw = fs.readFileSync(path.join(resolvedDir, file), 'utf-8');
      // Simple YAML parser for our schema (no external dep)
      const def = parseSimpleYaml(raw);
      if (def && def.rules) {
        for (const rule of def.rules) {
          customRulesLoaded.push({
            id: rule.id,
            check: createCustomRuleCheck(rule),
          });
        }
      }
    } catch { /* skip invalid rule files */ }
  }
}

function parseSimpleYaml(raw: string): CustomRuleDefinition | null {
  try {
    // Very basic YAML-like parser for our specific schema
    const lines = raw.split('\n');
    const def: CustomRuleDefinition = { name: '', version: '', rules: [] };
    let currentRule: Record<string, unknown> | null = null;
    let currentPatterns: { regex?: string; keyword?: string }[] = [];
    let currentConditions: { metric: string; operator: string; value: number }[] = [];
    let inPatterns = false;
    let inConditions = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (trimmed.startsWith('name:')) def.name = trimmed.slice(5).trim().replace(/^["']|["']$/g, '');
      else if (trimmed.startsWith('version:')) def.version = trimmed.slice(8).trim().replace(/^["']|["']$/g, '');
      else if (trimmed === '- id:' || trimmed.startsWith('- id:')) {
        if (currentRule) {
          def.rules.push({
            id: currentRule.id as string,
            description: (currentRule.description as string) || '',
            event: (currentRule.event as string) || 'message:received',
            severity: (currentRule.severity as Severity) || 'warning',
            patterns: currentPatterns.length > 0 ? currentPatterns : undefined,
            conditions: currentConditions.length > 0 ? currentConditions : undefined,
            action: (currentRule.action as 'alert' | 'log' | 'block') || 'alert',
          });
        }
        currentRule = { id: trimmed.replace('- id:', '').trim().replace(/^["']|["']$/g, '') };
        currentPatterns = [];
        currentConditions = [];
        inPatterns = false;
        inConditions = false;
      } else if (currentRule) {
        if (trimmed.startsWith('description:')) currentRule.description = trimmed.slice(12).trim().replace(/^["']|["']$/g, '');
        else if (trimmed.startsWith('event:')) currentRule.event = trimmed.slice(6).trim();
        else if (trimmed.startsWith('severity:')) currentRule.severity = trimmed.slice(9).trim();
        else if (trimmed.startsWith('action:')) currentRule.action = trimmed.slice(7).trim();
        else if (trimmed === 'patterns:') { inPatterns = true; inConditions = false; }
        else if (trimmed === 'conditions:') { inConditions = true; inPatterns = false; }
        else if (inPatterns && trimmed.startsWith('- regex:')) {
          currentPatterns.push({ regex: trimmed.slice(8).trim().replace(/^["']|["']$/g, '') });
        } else if (inPatterns && trimmed.startsWith('- keyword:')) {
          currentPatterns.push({ keyword: trimmed.slice(10).trim().replace(/^["']|["']$/g, '') });
        } else if (inConditions && trimmed.startsWith('- metric:')) {
          currentConditions.push({
            metric: trimmed.slice(9).trim(),
            operator: '', value: 0,
          });
        } else if (inConditions && trimmed.startsWith('operator:') && currentConditions.length > 0) {
          currentConditions[currentConditions.length - 1].operator = trimmed.slice(9).trim().replace(/^["']|["']$/g, '');
        } else if (inConditions && trimmed.startsWith('value:') && currentConditions.length > 0) {
          currentConditions[currentConditions.length - 1].value = parseFloat(trimmed.slice(6).trim());
        }
      }
    }
    // Push last rule
    if (currentRule) {
      def.rules.push({
        id: currentRule.id as string,
        description: (currentRule.description as string) || '',
        event: (currentRule.event as string) || 'message:received',
        severity: (currentRule.severity as Severity) || 'warning',
        patterns: currentPatterns.length > 0 ? currentPatterns : undefined,
        conditions: currentConditions.length > 0 ? currentConditions : undefined,
        action: (currentRule.action as 'alert' | 'log' | 'block') || 'alert',
      });
    }
    return def;
  } catch {
    return null;
  }
}

function createCustomRuleCheck(rule: { id: string; description: string; severity: Severity; patterns?: { regex?: string; keyword?: string }[]; action: string }): SecurityRule['check'] {
  return (content: string, _direction: Direction, context: RuleContext): SecurityFinding[] => {
    const findings: SecurityFinding[] = [];
    if (!rule.patterns) return findings;

    for (const pattern of rule.patterns) {
      let matched = false;
      if (pattern.regex) {
        try { matched = new RegExp(pattern.regex, 'i').test(content); } catch { /* invalid regex */ }
      }
      if (pattern.keyword) {
        matched = matched || content.toLowerCase().includes(pattern.keyword.toLowerCase());
      }
      if (matched) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: rule.id,
          ruleName: rule.description,
          severity: rule.severity,
          category: 'custom',
          owaspCategory: 'Custom',
          description: rule.description,
          session: context.session,
          channel: context.channel,
          action: rule.action as 'alert' | 'log' | 'block',
        });
      }
    }
    return findings;
  };
}

export function runSecurityScan(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
  const config = store.getConfig();
  const findings: SecurityFinding[] = [];

  // Built-in rules
  for (const rule of builtinRules) {
    if (!rule.enabled) continue;
    if (!config.security.enabledRules.includes(rule.id)) continue;
    try {
      findings.push(...rule.check(content, direction, context));
    } catch { /* rule error, skip */ }
  }

  // Custom rules
  for (const custom of customRulesLoaded) {
    try {
      findings.push(...custom.check(content, direction, context));
    } catch { /* skip */ }
  }

  // Store findings
  for (const f of findings) {
    store.appendFinding(f);
  }

  return findings;
}

export function getSecurityScore(): number {
  const findings = store.getFindings(1000);
  const dayStart = new Date();
  dayStart.setHours(0, 0, 0, 0);
  const todayFindings = findings.filter(f => f.timestamp >= dayStart.getTime());

  let score = 100;
  for (const f of todayFindings) {
    switch (f.severity) {
      case 'critical': score -= 20; break;
      case 'high': score -= 10; break;
      case 'warning': score -= 3; break;
      case 'info': score -= 1; break;
    }
  }
  return Math.max(0, Math.min(100, score));
}

export function getRuleStatuses(): { id: string; name: string; enabled: boolean; triggerCount: number; owaspCategory: string }[] {
  const config = store.getConfig();
  const findings = store.getFindings(10000);

  return builtinRules.map(rule => ({
    id: rule.id,
    name: rule.name,
    enabled: config.security.enabledRules.includes(rule.id),
    triggerCount: findings.filter(f => f.ruleId === rule.id).length,
    owaspCategory: rule.owaspCategory,
  }));
}
