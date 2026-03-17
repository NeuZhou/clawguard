// ClawGuard — Skill Scanner
// Standalone CLI tool for scanning files/directories for security threats
// Usage: ClawGuard scan <path> [--strict] [--format json|sarif|text]

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { SecurityFinding, RuleContext } from './types';
import { builtinRules } from './rules';
import { ScanFinding, toSarif } from './exporters/sarif';
import { calculateRisk } from './risk-engine';
import { loadCustomRules as loadCustomRulesFromDir, runSecurityScan as runEngineSecurityScan, getCustomRulesLoaded } from './security-engine';

export interface ScanOptions {
  strict: boolean;
  format: 'text' | 'json' | 'sarif';
  rules?: string;
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
    staticScan: true,
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

  // Apply custom rules loaded via --rules
  for (const custom of getCustomRulesLoaded()) {
    try {
      const ruleFindings = custom.check(content, 'inbound', ctx);
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
    } catch { /* skip custom rule errors */ }
  }

  return findings;
}

/**
 * Load .clawguardignore patterns (glob-like, one per line).
 * Supports simple patterns: exact paths, directory names, and * wildcards.
 */
function loadIgnorePatterns(baseDir: string): ((filePath: string) => boolean) {
  // Search upwards for .clawguardignore (like .gitignore)
  let searchDir = path.resolve(baseDir);
  let ignoreFile = '';
  for (let i = 0; i < 10; i++) {
    const candidate = path.join(searchDir, '.clawguardignore');
    if (fs.existsSync(candidate)) { ignoreFile = candidate; break; }
    const parent = path.dirname(searchDir);
    if (parent === searchDir) break;
    searchDir = parent;
  }
  if (!ignoreFile) return () => false;
  const ignoreBase = path.dirname(ignoreFile);
  const lines = fs.readFileSync(ignoreFile, 'utf-8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
  if (lines.length === 0) return () => false;
  return (filePath: string) => {
    const rel = path.relative(ignoreBase, filePath).replace(/\\/g, '/');
    return lines.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
        return regex.test(rel);
      }
      return rel === pattern || rel.startsWith(pattern + '/') || rel.includes('/' + pattern + '/') || rel.includes('/' + pattern);
    });
  };
}

function collectFiles(targetPath: string, isIgnored?: (f: string) => boolean): string[] {
  const stat = fs.statSync(targetPath);
  if (stat.isFile()) {
    return [targetPath];
  }

  if (!isIgnored) {
    isIgnored = loadIgnorePatterns(targetPath);
  }

  const files: string[] = [];
  const entries = fs.readdirSync(targetPath, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(targetPath, entry.name);
    if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === 'dist') continue;
    if (isIgnored(fullPath)) continue;
    if (entry.isDirectory()) {
      files.push(...collectFiles(fullPath, isIgnored));
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

  if (options.rules) {
    loadCustomRulesFromDir(options.rules);
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

/** Map severity to CVSS-like score */
function severityCvss(severity: string): string {
  switch (severity) {
    case 'critical': return '9.0-10.0';
    case 'high': return '7.0-8.9';
    case 'warning': return '4.0-6.9';
    case 'info': return '0.1-3.9';
    default: return '0.0';
  }
}

/** Remediation suggestions by rule/description */
function getRemediation(ruleId: string, description: string): string {
  const remediations: Record<string, string> = {
    'prompt-injection': 'Sanitize user inputs; use input validation; implement prompt firewalls',
    'data-leakage': 'Remove or redact PII/credentials; use environment variables for secrets',
    'mcp-security': 'Enable sandboxing; restrict tool permissions; validate MCP server origins',
    'supply-chain': 'Pin dependencies; audit npm scripts; avoid eval(); verify package names',
    'memory-poisoning': 'Validate memory file contents; strip HTML comments; reject encoded payloads',
    'api-key-exposure': 'Move secrets to environment variables or a vault; add to .gitignore',
    'permission-escalation': 'Use least-privilege principle; avoid sudo in scripts; restrict agent file access',
    'anomaly-detection': 'Review unusual patterns; set rate limits; monitor for behavioral anomalies',
    'compliance': 'Review compliance requirements; ensure data handling meets policy',
    'file-protection': 'Restrict file access paths; use allowlists for file operations',
    'identity-protection': 'Protect identity information; use access controls',
  };

  if (description.includes('SSRF')) return 'Block private IP ranges; validate URLs; use allowlists for outbound requests';
  if (description.includes('reverse shell')) return 'Block outbound connections to unknown IPs; disable shell access';
  if (description.includes('eval')) return 'Replace eval() with safe alternatives; use AST-based code analysis';
  if (description.includes('API key') || description.includes('token')) return 'Rotate the exposed key immediately; use env vars or secret managers';
  if (description.includes('shadow')) return 'Verify MCP tool names; use tool name allowlists';

  return remediations[ruleId] || 'Review and remediate the finding based on security best practices';
}

// ANSI color helpers (auto-disabled when NO_COLOR is set or not a TTY)
const useColor = !process.env.NO_COLOR && (process.stdout.isTTY ?? false);
const c = {
  reset: useColor ? '\x1b[0m' : '',
  bold: useColor ? '\x1b[1m' : '',
  dim: useColor ? '\x1b[2m' : '',
  red: useColor ? '\x1b[31m' : '',
  green: useColor ? '\x1b[32m' : '',
  yellow: useColor ? '\x1b[33m' : '',
  blue: useColor ? '\x1b[34m' : '',
  magenta: useColor ? '\x1b[35m' : '',
  cyan: useColor ? '\x1b[36m' : '',
  white: useColor ? '\x1b[37m' : '',
  bgRed: useColor ? '\x1b[41m' : '',
  bgGreen: useColor ? '\x1b[42m' : '',
  orange: useColor ? '\x1b[38;5;208m' : '',
};

function sevColor(severity: string): string {
  switch (severity) {
    case 'critical': return c.red;
    case 'high': return c.orange;
    case 'warning': return c.yellow;
    case 'info': return c.green;
    default: return c.dim;
  }
}

/** Format scan results as human-readable text with color */
export function formatText(result: ScanResult, elapsedMs?: number): string {
  const lines: string[] = [];
  const elapsed = elapsedMs != null ? `${(elapsedMs / 1000).toFixed(2)}s` : '';

  lines.push('');
  lines.push(`${c.bold}${c.cyan}🛡️  ClawGuard${c.reset} ${c.dim}— Security Scan Results${c.reset}`);
  lines.push(`${c.dim}${'═'.repeat(55)}${c.reset}`);
  lines.push(`${c.bold}📁 Files scanned:${c.reset} ${result.totalFiles}    ${c.bold}🔍 Findings:${c.reset} ${result.totalFindings}${elapsed ? `    ${c.bold}⏱️  ${elapsed}${c.reset}` : ''}`);
  lines.push('');

  if (result.totalFindings === 0) {
    lines.push(`${c.bgGreen}${c.bold} ✅ CLEAN ${c.reset} ${c.green}No security issues found!${c.reset}`);
    return lines.join('\n');
  }

  const icons: Record<string, string> = { critical: '🔴', high: '🟠', warning: '🟡', info: '🟢' };

  // Summary bar
  const parts: string[] = [];
  for (const sev of ['critical', 'high', 'warning', 'info']) {
    const count = result.summary[sev] || 0;
    if (count > 0) parts.push(`${sevColor(sev)}${icons[sev]} ${count} ${sev}${c.reset}`);
  }
  lines.push(`${c.bold}📊 Summary:${c.reset} ${parts.join('  ')}`);

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
  const riskColor = risk.score >= 70 ? c.red : risk.score >= 40 ? c.yellow : c.green;
  lines.push(`${c.bold}🎯 Risk Score:${c.reset} ${riskColor}${c.bold}${risk.score}/100 — ${risk.verdict}${c.reset}`);
  if (risk.attackChains.length > 0) {
    lines.push(`   ${c.red}⛓️  Attack chains: ${risk.attackChains.join(', ')}${c.reset}`);
  }
  lines.push('');

  lines.push(`${c.bold}📋 Findings:${c.reset}`);
  lines.push(`${c.dim}${'─'.repeat(55)}${c.reset}`);

  for (const f of result.findings) {
    const sc = sevColor(f.severity);
    const icon = icons[f.severity] || '⚪';
    const cvss = severityCvss(f.severity);
    lines.push(`${sc}${c.bold}${icon} [${f.severity.toUpperCase()}]${c.reset} ${c.bold}${f.ruleId}${c.reset} ${c.dim}(CVSS: ${cvss})${c.reset}`);
    lines.push(`   ${c.dim}📄 ${f.file}${f.line ? `:${f.line}` : ''}${c.reset}`);
    lines.push(`   📝 ${f.description}`);
    if (f.evidence) lines.push(`   ${c.dim}🔎 ${f.evidence.slice(0, 100)}${c.reset}`);
    const remediation = getRemediation(f.ruleId, f.description);
    if (remediation) lines.push(`   ${c.cyan}💡 Fix: ${remediation}${c.reset}`);
    lines.push('');
  }

  return lines.join('\n');
}

/** Format scan results as JSON with severity scores and remediation */
export function formatJson(result: ScanResult): string {
  const enriched = {
    ...result,
    findings: result.findings.map(f => ({
      ...f,
      cvssRange: severityCvss(f.severity),
      remediation: getRemediation(f.ruleId, f.description),
    })),
  };
  return JSON.stringify(enriched, null, 2);
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
    const startMs = performance.now();
    const result = scan(targetPath, options);
    const elapsedMs = performance.now() - startMs;

    switch (format) {
      case 'json':
        process.stdout.write(formatJson(result) + '\n');
        break;
      case 'sarif':
        process.stdout.write(formatSarif(result) + '\n');
        break;
      default:
        process.stdout.write(formatText(result, elapsedMs) + '\n');
    }

    if (strict && (result.summary.critical > 0 || result.summary.high > 0)) {
      process.exit(1);
    }
  } catch (err) {
    process.stderr.write(`Error: ${(err as Error).message}\n`);
    process.exit(2);
  }
}

