// OpenClaw Watch — Skill Scanner
// Standalone CLI tool for scanning files/directories for security threats
// Usage: openclaw-watch scan <path> [--strict] [--format json|sarif|text]

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { SecurityFinding, RuleContext } from './types';
import { builtinRules } from './rules';
import { ScanFinding, toSarif } from './exporters/sarif';
import { calculateRisk } from './risk-engine';

export interface ScanOptions {
  strict: boolean;
  format: 'text' | 'json' | 'sarif';
}

export interface ScanResult {
  totalFiles: number;
  totalFindings: number;
  findings: ScanFinding[];
  summary: Record<string, number>;
}

const SCANNABLE_EXTENSIONS = new Set([
  '.md', '.txt', '.ts', '.js', '.mjs', '.cjs', '.json', '.yaml', '.yml',
  '.py', '.sh', '.bash', '.zsh', '.ps1', '.toml', '.cfg', '.ini', '.env',
]);

function makeContext(): RuleContext {
  return {
    session: 'scan',
    channel: 'cli',
    timestamp: Date.now(),
    recentMessages: [],
    recentFindings: [],
  };
}

function scanContent(content: string, filePath: string): ScanFinding[] {
  const ctx = makeContext();
  const findings: ScanFinding[] = [];

  for (const rule of builtinRules) {
    if (!rule.enabled) continue;
    try {
      const ruleFindings = rule.check(content, 'inbound', ctx);
      for (const f of ruleFindings) {
        let line = 1;
        if (f.evidence) {
          const idx = content.indexOf(f.evidence.slice(0, 30));
          if (idx >= 0) {
            line = content.slice(0, idx).split('\n').length;
          }
        }
        findings.push({ ...f, file: filePath, line });
      }
    } catch { /* skip rule errors */ }
  }

  return findings;
}

function collectFiles(targetPath: string): string[] {
  const stat = fs.statSync(targetPath);
  if (stat.isFile()) {
    return [targetPath];
  }

  const files: string[] = [];
  const entries = fs.readdirSync(targetPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(targetPath, entry.name);
    if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'dist') continue;
    if (entry.isDirectory()) {
      files.push(...collectFiles(fullPath));
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SCANNABLE_EXTENSIONS.has(ext) || entry.name.startsWith('.env')) {
        files.push(fullPath);
      }
    }
  }
  return files;
}

/** Scan a file or directory for security threats, returning aggregated results */
export function scan(targetPath: string, options: Partial<ScanOptions> = {}): ScanResult {
  const resolved = path.resolve(targetPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Path not found: ${resolved}`);
  }

  const files = collectFiles(resolved);
  const allFindings: ScanFinding[] = [];

  for (const file of files) {
    try {
      const content = fs.readFileSync(file, 'utf-8');
      const relPath = path.relative(process.cwd(), file);
      allFindings.push(...scanContent(content, relPath));
    } catch { /* skip unreadable files */ }
  }

  const summary: Record<string, number> = { critical: 0, high: 0, warning: 0, info: 0 };
  for (const f of allFindings) {
    summary[f.severity] = (summary[f.severity] || 0) + 1;
  }

  return {
    totalFiles: files.length,
    totalFindings: allFindings.length,
    findings: allFindings,
    summary,
  };
}

/** Format scan results as human-readable text */
export function formatText(result: ScanResult): string {
  const lines: string[] = [];
  lines.push('');
  lines.push('🛡️  OpenClaw Watch — Security Scan Results');
  lines.push('═'.repeat(50));
  lines.push(`📁 Files scanned: ${result.totalFiles}`);
  lines.push(`🔍 Findings: ${result.totalFindings}`);
  lines.push('');

  if (result.totalFindings === 0) {
    lines.push('✅ No security issues found!');
    return lines.join('\n');
  }

  const icons: Record<string, string> = { critical: '🔴', high: '🟠', warning: '🟡', info: '🔵' };

  lines.push('📊 Summary:');
  for (const [sev, count] of Object.entries(result.summary)) {
    if (count > 0) lines.push(`   ${icons[sev] || '⚪'} ${sev}: ${count}`);
  }

  // Risk Score
  const riskFindings = result.findings.map(f => ({
    id: f.file + ':' + f.line,
    timestamp: Date.now(),
    ruleId: f.ruleId,
    ruleName: f.ruleId,
    severity: f.severity as 'critical' | 'high' | 'warning' | 'info',
    category: f.ruleId,
    description: f.description,
    action: 'log' as const,
  }));
  const risk = calculateRisk(riskFindings);
  lines.push('');
  lines.push(`🎯 Risk Score: ${risk.icon} ${risk.score}/100 — ${risk.verdict}`);
  if (risk.attackChains.length > 0) {
    lines.push(`   ⛓️ Attack chains: ${risk.attackChains.join(', ')}`);
  }
  lines.push('');

  lines.push('📋 Findings:');
  lines.push('─'.repeat(50));

  for (const f of result.findings) {
    const icon = icons[f.severity] || '⚪';
    lines.push(`${icon} [${f.severity.toUpperCase()}] ${f.ruleId}`);
    lines.push(`   📄 ${f.file}${f.line ? `:${f.line}` : ''}`);
    lines.push(`   📝 ${f.description}`);
    if (f.evidence) lines.push(`   🔎 ${f.evidence.slice(0, 100)}`);
    lines.push('');
  }

  return lines.join('\n');
}

/** Format scan results as JSON */
export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

/** Format scan results as SARIF 2.1.0 for GitHub Code Scanning */
export function formatSarif(result: ScanResult): string {
  return JSON.stringify(toSarif(result.findings), null, 2);
}

/** Run scan and output results to stdout, exiting with code 1 in strict mode on high/critical findings */
export function runScan(targetPath: string, options: Partial<ScanOptions> = {}): void {
  const format = options.format || 'text';
  const strict = options.strict || false;

  try {
    const result = scan(targetPath, options);

    switch (format) {
      case 'json':
        process.stdout.write(formatJson(result) + '\n');
        break;
      case 'sarif':
        process.stdout.write(formatSarif(result) + '\n');
        break;
      default:
        process.stdout.write(formatText(result) + '\n');
    }

    if (strict && (result.summary.critical > 0 || result.summary.high > 0)) {
      process.exit(1);
    }
  } catch (err) {
    process.stderr.write(`Error: ${(err as Error).message}\n`);
    process.exit(2);
  }
}
