// ClawGuard — MCP Server Source Code Scanner
// Deep scan of MCP server source code for security issues

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { SecurityFinding, Severity } from '../types';
import { MCP_RULES, MCPRule, MCPRuleCategory } from './mcp-rules';
import { analyzeManifest, MCPManifest, MCPScorecard, MCPGrade, generateBadgeSVG } from './mcp-manifest-analyzer';

export { MCPScorecard, MCPGrade, generateBadgeSVG };

export interface MCPScanResult {
  serverPath: string;
  scorecard: MCPScorecard;
  fileFindings: Map<string, SecurityFinding[]>;
  dependencyFindings: SecurityFinding[];
  totalFiles: number;
  scannedFiles: number;
}

export interface MCPScanOptions {
  /** Scan manifest only (no source) */
  manifestOnly?: boolean;
  /** Custom manifest path */
  manifestPath?: string;
  /** File extensions to scan */
  extensions?: string[];
  /** Max file size in bytes */
  maxFileSize?: number;
  /** Output format */
  format?: 'text' | 'json';
  /** Strict mode (exit 1 on high+) */
  strict?: boolean;
}

const DEFAULT_EXTENSIONS = ['.ts', '.js', '.mjs', '.cjs', '.py', '.mts', '.cts'];
const DEFAULT_MAX_FILE_SIZE = 1024 * 1024; // 1MB

function collectFiles(dir: string, extensions: string[], maxSize: number): string[] {
  const files: string[] = [];
  const skipDirs = new Set(['node_modules', '.git', 'dist', 'build', '__pycache__', '.venv', 'venv']);

  function walk(d: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!skipDirs.has(entry.name)) walk(path.join(d, entry.name));
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (extensions.includes(ext)) {
          const full = path.join(d, entry.name);
          try {
            const stat = fs.statSync(full);
            if (stat.size <= maxSize) files.push(full);
          } catch { /* skip */ }
        }
      }
    }
  }
  walk(dir);
  return files;
}

function makeFinding(rule: MCPRule, evidence: string, filePath?: string): SecurityFinding {
  return {
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    category: 'mcp-security',
    owaspCategory: 'Agentic AI: Tool Manipulation',
    description: `${rule.description}${filePath ? ` [${path.basename(filePath)}]` : ''}`,
    evidence: evidence.slice(0, 300),
    session: 'mcp-scan',
    channel: 'cli',
    action: rule.severity === 'critical' ? 'alert' : 'log',
  };
}

function scanFileContent(content: string, filePath: string, rules: MCPRule[]): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  for (const rule of rules) {
    if (rule.matchPath) continue;
    for (const pattern of rule.patterns) {
      const match = pattern.exec(content);
      if (match) {
        findings.push(makeFinding(rule, match[0], filePath));
        break; // one finding per rule per file
      }
    }
  }
  return findings;
}

function scanDependencies(dir: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  // package.json
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

      // Check for dangerous scripts
      if (pkg.scripts) {
        for (const [name, cmd] of Object.entries(pkg.scripts) as [string, string][]) {
          if (/^(preinstall|postinstall|preuninstall)$/.test(name) && cmd) {
            if (/curl|wget|sh\s+-c|bash\s+-c|eval|node\s+-e/.test(cmd)) {
              findings.push({
                id: crypto.randomUUID(),
                timestamp: Date.now(),
                ruleId: 'mcp-dep-dangerous-script',
                ruleName: 'Dangerous Lifecycle Script',
                severity: 'critical',
                category: 'mcp-security',
                description: `package.json "${name}" script runs dangerous command`,
                evidence: `${name}: ${cmd.slice(0, 200)}`,
                session: 'mcp-scan',
                channel: 'cli',
                action: 'alert',
              });
            }
          }
        }
      }

      // Check for wildcard/latest versions
      for (const [dep, ver] of Object.entries(allDeps) as [string, string][]) {
        if (ver === '*' || ver === 'latest') {
          findings.push({
            id: crypto.randomUUID(),
            timestamp: Date.now(),
            ruleId: 'mcp-dep-unpinned',
            ruleName: 'Unpinned Dependency',
            severity: 'warning',
            category: 'mcp-security',
            description: `Dependency "${dep}" uses unpinned version "${ver}"`,
            evidence: `${dep}: ${ver}`,
            session: 'mcp-scan',
            channel: 'cli',
            action: 'log',
          });
        }
      }
    } catch { /* skip */ }
  }

  // pyproject.toml (basic check)
  const pyPath = path.join(dir, 'pyproject.toml');
  if (fs.existsSync(pyPath)) {
    try {
      const content = fs.readFileSync(pyPath, 'utf-8');
      // Check for setup scripts
      if (/\[tool\.setuptools\.cmdclass\]/.test(content)) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          ruleId: 'mcp-dep-custom-setup',
          ruleName: 'Custom Setup Command',
          severity: 'high',
          category: 'mcp-security',
          description: 'pyproject.toml defines custom setup commands (supply chain risk)',
          evidence: 'tool.setuptools.cmdclass',
          session: 'mcp-scan',
          channel: 'cli',
          action: 'alert',
        });
      }
    } catch { /* skip */ }
  }

  return findings;
}

function tryLoadManifest(dir: string, manifestPath?: string): MCPManifest | null {
  // Try explicit path first
  if (manifestPath) {
    try {
      return JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    } catch { return null; }
  }

  // Try common manifest locations
  const candidates = ['mcp.json', 'mcp-manifest.json', 'manifest.json', 'server.json'];
  for (const c of candidates) {
    const p = path.join(dir, c);
    if (fs.existsSync(p)) {
      try {
        return JSON.parse(fs.readFileSync(p, 'utf-8'));
      } catch { continue; }
    }
  }

  // Try to build manifest from package.json
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      if (pkg.name && (pkg.keywords?.includes('mcp') || pkg.description?.toLowerCase().includes('mcp'))) {
        return { name: pkg.name, version: pkg.version, description: pkg.description };
      }
    } catch { /* skip */ }
  }

  return null;
}

export function scanMCPServer(serverPath: string, options: MCPScanOptions = {}): MCPScanResult {
  const resolvedPath = path.resolve(serverPath);
  const isDir = fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isDirectory();
  const dir = isDir ? resolvedPath : path.dirname(resolvedPath);
  const extensions = options.extensions ?? DEFAULT_EXTENSIONS;
  const maxSize = options.maxFileSize ?? DEFAULT_MAX_FILE_SIZE;

  // Load manifest
  const manifest = tryLoadManifest(dir, options.manifestPath) ?? { name: path.basename(dir) };
  const fileFindings = new Map<string, SecurityFinding[]>();
  let totalFiles = 0;
  let scannedFiles = 0;

  if (!options.manifestOnly) {
    // Collect and scan files
    const files = isDir ? collectFiles(dir, extensions, maxSize) : [resolvedPath];
    totalFiles = files.length;

    for (const file of files) {
      try {
        const content = fs.readFileSync(file, 'utf-8');
        const findings = scanFileContent(content, file, MCP_RULES);
        if (findings.length > 0) {
          fileFindings.set(file, findings);
        }
        scannedFiles++;
      } catch { /* skip unreadable files */ }
    }
  }

  // Dependency scan
  const dependencyFindings = scanDependencies(dir);

  // Combine all findings for scoring
  const allFindings: SecurityFinding[] = [
    ...Array.from(fileFindings.values()).flat(),
    ...dependencyFindings,
  ];

  // Build scorecard (include manifest analysis)
  const manifestScorecard = analyzeManifest(manifest);
  const combinedFindings = [...manifestScorecard.findings, ...allFindings];

  // Re-score
  const totalPenalty = combinedFindings.reduce((sum, f) => {
    return sum + (f.severity === 'critical' ? 20 : f.severity === 'high' ? 10 : f.severity === 'warning' ? 5 : 2);
  }, 0);
  const score = Math.max(0, 100 - totalPenalty);
  const grade: MCPGrade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

  const scorecard: MCPScorecard = {
    ...manifestScorecard,
    grade,
    score,
    findings: combinedFindings,
    scannedAt: Date.now(),
  };

  return {
    serverPath: resolvedPath,
    scorecard,
    fileFindings,
    dependencyFindings,
    totalFiles,
    scannedFiles,
  };
}

export function formatMCPScanResult(result: MCPScanResult, format: 'text' | 'json' = 'text'): string {
  if (format === 'json') {
    return JSON.stringify({
      ...result,
      fileFindings: Object.fromEntries(result.fileFindings),
    }, null, 2);
  }

  const lines: string[] = [];
  const sc = result.scorecard;

  lines.push('');
  lines.push('🔒 ClawGuard MCP Security Scan');
  lines.push('═'.repeat(50));
  lines.push(`  Server:    ${sc.serverName}`);
  lines.push(`  Grade:     ${sc.grade} (${sc.score}/100)`);
  lines.push(`  Tools:     ${sc.toolCount}`);
  lines.push(`  Resources: ${sc.resourceCount}`);
  lines.push(`  Files:     ${result.scannedFiles}/${result.totalFiles} scanned`);
  lines.push('');

  if (sc.findings.length === 0) {
    lines.push('✅ No security issues found!');
  } else {
    const bySev = { critical: 0, high: 0, warning: 0, info: 0 };
    for (const f of sc.findings) bySev[f.severity]++;
    lines.push(`  Found ${sc.findings.length} issue(s): ${bySev.critical} critical, ${bySev.high} high, ${bySev.warning} warning, ${bySev.info} info`);
    lines.push('');

    // Group by category
    const byCategory = new Map<string, SecurityFinding[]>();
    for (const f of sc.findings) {
      const cat = f.ruleId.split('-').slice(1, 3).join('-');
      if (!byCategory.has(cat)) byCategory.set(cat, []);
      byCategory.get(cat)!.push(f);
    }

    for (const [cat, findings] of byCategory) {
      lines.push(`  ── ${cat} ──`);
      for (const f of findings) {
        const icon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'warning' ? '🟡' : '🔵';
        lines.push(`  ${icon} [${f.severity.toUpperCase()}] ${f.description}`);
        if (f.evidence) lines.push(`    Evidence: ${f.evidence}`);
      }
      lines.push('');
    }
  }

  lines.push('─'.repeat(50));
  lines.push(`  Breakdown: poison=${sc.breakdown.toolPoisoning} perms=${sc.breakdown.permissions} exfil=${sc.breakdown.exfiltration} schema=${sc.breakdown.schemaQuality} supply=${sc.breakdown.supplyChain}`);
  lines.push('');

  return lines.join('\n');
}
