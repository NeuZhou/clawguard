#!/usr/bin/env node
// ClawGuard — MCP Firewall: CLI Entry Point
// Usage: clawguard firewall --config firewall.yaml

import * as fs from 'fs';
import * as path from 'path';
import * as readline from 'readline';
import { McpFirewallProxy } from './proxy';
import { loadFirewallConfig, DEFAULT_FIREWALL_CONFIG } from './policy';
import { FirewallDashboard, formatEventLog } from './dashboard';
import { FirewallConfig } from './types';

export interface FirewallCliOptions {
  configPath?: string;
  mode?: string;
  verbose?: boolean;
  logFile?: string;
  server?: string;
}

/**
 * Parse CLI arguments for the firewall subcommand.
 */
export function parseFirewallArgs(args: string[]): FirewallCliOptions {
  const options: FirewallCliOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if ((arg === '--config' || arg === '-c') && args[i + 1]) {
      options.configPath = args[++i];
    } else if ((arg === '--mode' || arg === '-m') && args[i + 1]) {
      options.mode = args[++i];
    } else if (arg === '--verbose' || arg === '-v') {
      options.verbose = true;
    } else if ((arg === '--log' || arg === '-l') && args[i + 1]) {
      options.logFile = args[++i];
    } else if ((arg === '--server' || arg === '-s') && args[i + 1]) {
      options.server = args[++i];
    }
  }

  return options;
}

/**
 * Load config from file or use defaults.
 */
export function resolveConfig(options: FirewallCliOptions): FirewallConfig {
  let config: FirewallConfig;

  if (options.configPath) {
    const resolvedPath = path.resolve(options.configPath);
    if (!fs.existsSync(resolvedPath)) {
      process.stderr.write(`Error: Config file not found: ${resolvedPath}\n`);
      process.exit(1);
    }
    config = loadFirewallConfig(resolvedPath);
  } else {
    // Try default locations
    const defaultPaths = [
      path.join(process.cwd(), 'firewall.yaml'),
      path.join(process.cwd(), 'firewall.yml'),
      path.join(process.cwd(), '.clawguard', 'firewall.yaml'),
    ];
    let found = false;
    config = DEFAULT_FIREWALL_CONFIG;
    for (const p of defaultPaths) {
      if (fs.existsSync(p)) {
        config = loadFirewallConfig(p);
        found = true;
        process.stderr.write(`📋 Loaded config: ${p}\n`);
        break;
      }
    }
    if (!found) {
      process.stderr.write('⚠️  No config file found, using defaults (monitor mode)\n');
    }
  }

  // CLI overrides
  if (options.mode) {
    config.mode = options.mode as FirewallConfig['mode'];
  }

  return config;
}

/**
 * Run the firewall in stdio proxy mode.
 * Reads JSON-RPC messages from stdin, processes them, writes to stdout.
 */
export function runStdioProxy(config: FirewallConfig, options: FirewallCliOptions): void {
  const proxy = new McpFirewallProxy(config);
  const serverName = options.server || 'default';
  const logStream = options.logFile ? fs.createWriteStream(options.logFile, { flags: 'a' }) : null;

  // Event logging
  proxy.onEvent((event) => {
    if (options.verbose) {
      process.stderr.write(formatEventLog(event) + '\n');
    }
    if (logStream) {
      logStream.write(formatEventLog(event) + '\n');
    }
  });

  process.stderr.write(`🛡️  ClawGuard MCP Firewall started (mode: ${config.mode})\n`);
  process.stderr.write(`   Server: ${serverName}\n`);

  const rl = readline.createInterface({
    input: process.stdin,
    crlfDelay: Infinity,
  });

  rl.on('line', (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;

    // Try to process as JSON-RPC
    const result = proxy.processMessage(trimmed, 'client-to-server', serverName);
    if (result) {
      process.stdout.write(JSON.stringify(result.message) + '\n');
    } else {
      // Pass through unrecognized content
      process.stdout.write(line + '\n');
    }
  });

  rl.on('close', () => {
    process.stderr.write('🛡️  Firewall proxy shutting down\n');
    if (logStream) logStream.end();
    const stats = proxy.getStats();
    process.stderr.write(`📊 Final stats: ${stats.totalMessages} total, ${stats.blocked} blocked, ${stats.allowed} allowed\n`);
  });
}

/**
 * Print firewall help.
 */
export function printFirewallHelp(): void {
  const help = `
🛡️  ClawGuard MCP Firewall

Usage: clawguard firewall [options]

Options:
  --config, -c <path>    Config file path (default: ./firewall.yaml)
  --mode, -m <mode>      Override mode: enforce | monitor | disabled
  --server, -s <name>    Server name for stdio proxy (default: "default")
  --verbose, -v          Verbose output to stderr
  --log, -l <path>       Write event log to file

Modes:
  monitor   Log threats but don't block (default)
  enforce   Actively block threats
  disabled  Pass through all traffic

Examples:
  clawguard firewall --config firewall.yaml
  clawguard firewall --mode enforce --server filesystem
  clawguard firewall -v --log firewall.log
`;
  process.stdout.write(help + '\n');
}

/**
 * Main firewall CLI entry point.
 */
export function runFirewallCli(args: string[]): void {
  if (args.includes('--help') || args.includes('-h')) {
    printFirewallHelp();
    return;
  }

  const options = parseFirewallArgs(args);
  const config = resolveConfig(options);

  // Default to stdio proxy mode
  runStdioProxy(config, options);
}
