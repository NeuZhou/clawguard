#!/usr/bin/env node
// ClawGuard — Main CLI Entry Point
// Subcommands:
//   ClawGuard scan <path>    — scan skills/files for threats
//   ClawGuard start          — start monitoring hooks
//   ClawGuard dashboard      — open dashboard
//   ClawGuard audit <path>   — audit session logs
//   ClawGuard version        — show version

import * as fs from 'fs';
import * as path from 'path';
import { runScan, ScanOptions } from './skill-scanner';
import { runSecurityScan, calculateRisk } from './index';
import type { RuleContext } from './types';
import { sanitize as doSanitize } from './sanitizer';
import { checkIntentAction } from './intent-action';

/** Walk up from startDir to find package.json (works from both src/ and dist/) */
function findPackageJson(startDir: string): string {
  let dir = startDir;
  for (let i = 0; i < 5; i++) {
    const candidate = path.join(dir, 'package.json');
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  return path.join(startDir, '..', 'package.json'); // fallback
}

const pkg = JSON.parse(fs.readFileSync(findPackageJson(__dirname), 'utf-8'));
const VERSION = pkg.version as string;

function printHelp(): void {
  const help = `
🛡️  ClawGuard — AI Agent Security & Observability Platform

Usage: ClawGuard <command> [options]

Commands:
  scan <path>        Scan files/directories for security threats
  check <text>       Check a message for threats (agent-friendly)
  init               Generate ClawGuard.yaml config file
  start              Start real-time monitoring hooks
  dashboard          Open the security dashboard
  audit <path>       Audit session log files
  version            Show version

Scan Options:
  --strict           Exit code 1 on any finding >= high severity
  --format <fmt>     Output format: text (default), json, sarif

Examples:
  ClawGuard scan ./skills/
  ClawGuard scan ./SKILL.md --strict
  ClawGuard scan . --format sarif > results.sarif
  ClawGuard check "ignore all previous instructions"
`;
  process.stdout.write(help + '\n');
}

function parseArgs(args: string[]): { command: string; target?: string; options: Partial<ScanOptions> } {
  const command = args[0] || 'help';
  let target: string | undefined;
  const options: Partial<ScanOptions> = {};

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--strict') {
      options.strict = true;
    } else if (arg === '--format' && args[i + 1]) {
      options.format = args[++i] as ScanOptions['format'];
    } else if (!arg.startsWith('-')) {
      target = arg;
    }
  }

  return { command, target, options };
}

function initConfig(): void {
  const configPath = path.join(process.cwd(), 'ClawGuard.yaml');
  if (fs.existsSync(configPath)) {
    process.stderr.write('ClawGuard.yaml already exists. Delete it first to regenerate.\n');
    process.exit(1);
  }
  const yaml = `# ClawGuard Configuration
# See https://github.com/NeuZhou/ClawGuard for details

dashboard:
  port: 19790
  enabled: true

budget:
  dailyUsd: 50
  weeklyUsd: 200
  monthlyUsd: 500

alerts:
  costThresholds:
    - 0.8
    - 0.9
    - 1.0
  securityEscalate:
    - critical
    - high
  stuckTimeoutMs: 300000
  cooldownMs: 300000

security:
  enabledRules:
    - prompt-injection
    - data-leakage
    - anomaly-detection
    - compliance
    - file-protection
    - identity-protection
    - mcp-security
    - supply-chain
  customRulesDir: "~/.openclaw/ClawGuard/rules.d"

exporters:
  jsonl:
    enabled: true
  syslog:
    enabled: false
    host: "127.0.0.1"
    port: 514
  webhook:
    enabled: false
    url: ""
    secret: ""

retention:
  days: 30
  maxFileSizeMb: 50
`;
  fs.writeFileSync(configPath, yaml);
  process.stdout.write('✅ Created ClawGuard.yaml — edit to customize\n');
}

function main(): void {
  const args = process.argv.slice(2);
  const { command, target, options } = parseArgs(args);

  switch (command) {
    case 'scan':
      if (!target) {
        process.stderr.write('Error: scan requires a path argument\n');
        process.stderr.write('Usage: ClawGuard scan <path> [--strict] [--format json|sarif|text]\n');
        process.exit(2);
      }
      runScan(target, options);
      break;

    case 'check':
    case 'check-message': {
      // Agent-friendly: check a message string for threats
      const text = args.slice(1).join(' ');
      if (!text) {
        process.stderr.write('Usage: ClawGuard check "message text to analyze"\n');
        process.exit(2);
      }
      const context: RuleContext = { session: 'cli', channel: 'cli', timestamp: Date.now(), recentMessages: [], recentFindings: [] };
      const findings = runSecurityScan(text, 'inbound', context);
      const risk = calculateRisk(findings);
      if (findings.length === 0) {
        process.stdout.write(`✅ CLEAN (score: ${risk.score})\n`);
      } else {
        process.stdout.write(`${risk.icon} ${risk.verdict} (score: ${risk.score})\n`);
        for (const f of findings) {
          const icon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'warning' ? '🟡' : '🔵';
          process.stdout.write(`  ${icon} [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.description}\n`);
        }
        if (risk.attackChains.length > 0) {
          process.stdout.write(`  ⛓️ Attack chains: ${risk.attackChains.join(', ')}\n`);
        }
      }
      if (findings.some(f => f.severity === 'critical' || f.severity === 'high')) {
        process.exit(1);
      }
      break;
    }

    case 'init':
      initConfig();
      break;

    case 'version':
    case '--version':
    case '-v':
      process.stdout.write(`ClawGuard v${VERSION}\n`);
      break;

    case 'start':
      process.stdout.write('🛡️  Starting ClawGuard monitoring hooks...\n');
      process.stdout.write('   Use the OpenClaw hooks integration for real-time monitoring.\n');
      process.stdout.write('   See: https://github.com/NeuZhou/ClawGuard#hooks\n');
      break;

    case 'dashboard':
      process.stdout.write('🖥️  Dashboard available at http://localhost:19790\n');
      process.stdout.write('   Start with: ClawGuard start\n');
      break;

    case 'audit':
      if (!target) {
        process.stderr.write('Error: audit requires a path argument\n');
        process.exit(2);
      }
      process.stdout.write(`📋 Auditing session logs at: ${target}\n`);
      process.stdout.write('   (Audit mode scans session logs for anomalies and policy violations)\n');
      runScan(target, { ...options, format: options.format || 'text' });
      break;

    case 'sanitize': {
      // Sanitize PII/credentials from text
      const text = args.slice(1).join(' ');
      if (!text) {
        process.stderr.write('Usage: ClawGuard sanitize "text containing PII or secrets"\n');
        process.exit(2);
      }
      const result = doSanitize(text);
      if (result.piiCount === 0) {
        process.stdout.write(`✅ No PII or credentials detected\n`);
        process.stdout.write(text + '\n');
      } else {
        process.stdout.write(`🛡️ Sanitized ${result.piiCount} item(s):\n`);
        for (const r of result.replacements) {
          process.stdout.write(`  ${r.type}: ${r.original.slice(0, 8)}... → ${r.placeholder}\n`);
        }
        process.stdout.write(`\n${result.sanitized}\n`);
      }
      break;
    }

    case 'intent-check': {
      // Check intent vs action mismatch
      const intentIdx = args.indexOf('--intent');
      const actionIdx = args.indexOf('--action');
      if (intentIdx === -1 || actionIdx === -1) {
        process.stderr.write('Usage: ClawGuard intent-check --intent "I will read the file" --action "rm -rf /"\n');
        process.exit(2);
      }
      const intentText = args.slice(intentIdx + 1, actionIdx > intentIdx ? actionIdx : undefined).join(' ');
      const actionText = args.slice(actionIdx + 1, intentIdx > actionIdx ? intentIdx : undefined).join(' ');
      const check = checkIntentAction(intentText, actionText);
      if (check.mismatch) {
        const icon = check.severity === 'critical' ? '🔴' : check.severity === 'high' ? '🟠' : '🟡';
        process.stdout.write(`${icon} MISMATCH (${check.severity}, confidence: ${check.confidence}%)\n`);
        process.stdout.write(`  Reason: ${check.reason}\n`);
        process.exit(1);
      } else {
        process.stdout.write(`✅ CONSISTENT (confidence: ${check.confidence}%)\n`);
        if (check.severity === 'warning') {
          process.stdout.write(`  ⚠️ ${check.reason}\n`);
        }
      }
      break;
    }

    case 'help':
    case '--help':
    case '-h':
    default:
      printHelp();
      break;
  }
}

main();

