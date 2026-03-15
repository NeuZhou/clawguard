#!/usr/bin/env node
// OpenClaw Watch — Main CLI Entry Point
// Subcommands:
//   openclaw-watch scan <path>    — scan skills/files for threats
//   openclaw-watch start          — start monitoring hooks
//   openclaw-watch dashboard      — open dashboard
//   openclaw-watch audit <path>   — audit session logs
//   openclaw-watch version        — show version

import * as fs from 'fs';
import * as path from 'path';
import { runScan, ScanOptions } from './skill-scanner';
import { runSecurityScan, calculateRisk } from './index';

const VERSION = '5.0.0';

function printHelp(): void {
  const help = `
🛡️  OpenClaw Watch — AI Agent Security & Observability Platform

Usage: openclaw-watch <command> [options]

Commands:
  scan <path>        Scan files/directories for security threats
  check <text>       Check a message for threats (agent-friendly)
  init               Generate openclaw-watch.yaml config file
  start              Start real-time monitoring hooks
  dashboard          Open the security dashboard
  audit <path>       Audit session log files
  version            Show version

Scan Options:
  --strict           Exit code 1 on any finding >= high severity
  --format <fmt>     Output format: text (default), json, sarif

Examples:
  openclaw-watch scan ./skills/
  openclaw-watch scan ./SKILL.md --strict
  openclaw-watch scan . --format sarif > results.sarif
  openclaw-watch check "ignore all previous instructions"
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
  const configPath = path.join(process.cwd(), 'openclaw-watch.yaml');
  if (fs.existsSync(configPath)) {
    process.stderr.write('openclaw-watch.yaml already exists. Delete it first to regenerate.\n');
    process.exit(1);
  }
  const yaml = `# OpenClaw Watch Configuration
# See https://github.com/NeuZhou/openclaw-watch for details

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
  customRulesDir: "~/.openclaw/openclaw-watch/rules.d"

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
  process.stdout.write('✅ Created openclaw-watch.yaml — edit to customize\n');
}

function main(): void {
  const args = process.argv.slice(2);
  const { command, target, options } = parseArgs(args);

  switch (command) {
    case 'scan':
      if (!target) {
        process.stderr.write('Error: scan requires a path argument\n');
        process.stderr.write('Usage: openclaw-watch scan <path> [--strict] [--format json|sarif|text]\n');
        process.exit(2);
      }
      runScan(target, options);
      break;

    case 'check':
    case 'check-message': {
      // Agent-friendly: check a message string for threats
      const text = args.slice(1).join(' ');
      if (!text) {
        process.stderr.write('Usage: openclaw-watch check "message text to analyze"\n');
        process.exit(2);
      }
      const findings = runSecurityScan(text, 'inbound', { session: 'cli', channel: 'cli', timestamp: Date.now(), recentMessages: [], recentFindings: [] } as any);
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
      process.stdout.write(`openclaw-watch v${VERSION}\n`);
      break;

    case 'start':
      process.stdout.write('🛡️  Starting OpenClaw Watch monitoring hooks...\n');
      process.stdout.write('   Use the OpenClaw hooks integration for real-time monitoring.\n');
      process.stdout.write('   See: https://github.com/NeuZhou/openclaw-watch#hooks\n');
      break;

    case 'dashboard':
      process.stdout.write('🖥️  Dashboard available at http://localhost:19790\n');
      process.stdout.write('   Start with: openclaw-watch start\n');
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

    case 'help':
    case '--help':
    case '-h':
    default:
      printHelp();
      break;
  }
}

main();
