#!/usr/bin/env node
// OpenClaw Watch — Main CLI Entry Point
// Subcommands:
//   openclaw-watch scan <path>    — scan skills/files for threats
//   openclaw-watch start          — start monitoring hooks
//   openclaw-watch dashboard      — open dashboard
//   openclaw-watch audit <path>   — audit session logs
//   openclaw-watch version        — show version

import { runScan, ScanOptions } from './skill-scanner';

const VERSION = '2.0.0';

function printHelp(): void {
  const help = `
🛡️  OpenClaw Watch — AI Agent Security & Observability Platform

Usage: openclaw-watch <command> [options]

Commands:
  scan <path>        Scan files/directories for security threats
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
  openclaw-watch scan . --format json | jq '.summary'
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
