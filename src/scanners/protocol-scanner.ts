// ClawGuard - Unified Protocol Scanner
// Scans both MCP server configs and A2A agent cards for security issues

import { SecurityFinding, RuleContext } from '../types';
import { runSecurityScan } from '../security-engine';
import { checkA2ACard, scanA2ATaskMessage, A2AAgentCard, A2ATaskMessage } from '../rules/a2a-security';
import * as crypto from 'crypto';

export interface MCPServerConfig {
  name?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  transport?: string;
  tools?: Array<{ name: string; description?: string; inputSchema?: unknown }>;
  [key: string]: unknown;
}

export interface ProtocolScanResult {
  protocol: 'mcp' | 'a2a' | 'both';
  findings: SecurityFinding[];
  summary: {
    total: number;
    critical: number;
    high: number;
    warning: number;
    info: number;
  };
  scannedAt: number;
  mcpFindings?: SecurityFinding[];
  a2aFindings?: SecurityFinding[];
}

function makeContext(overrides?: Partial<RuleContext>): RuleContext {
  return {
    session: 'protocol-scan',
    channel: 'cli',
    timestamp: Date.now(),
    recentMessages: [],
    recentFindings: [],
    staticScan: true,
    ...overrides,
  };
}

function summarize(findings: SecurityFinding[]): ProtocolScanResult['summary'] {
  return {
    total: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    warning: findings.filter(f => f.severity === 'warning').length,
    info: findings.filter(f => f.severity === 'info').length,
  };
}

export class ProtocolScanner {
  /**
   * Scan an MCP server configuration for security issues.
   * Serializes config to JSON and runs it through the security engine.
   */
  scanMCPServer(config: MCPServerConfig): ProtocolScanResult {
    const ctx = makeContext();
    const content = JSON.stringify(config, null, 2);
    const findings = runSecurityScan(content, 'inbound', ctx);

    // Additional MCP-specific checks
    if (config.command) {
      const dangerousCmds = ['sudo', 'rm -rf', 'chmod 777', 'curl | bash', 'wget | sh'];
      for (const dc of dangerousCmds) {
        if (config.command.includes(dc) || (config.args ?? []).join(' ').includes(dc)) {
          findings.push({
            id: crypto.randomUUID(),
            timestamp: ctx.timestamp,
            ruleId: 'mcp-dangerous-command',
            ruleName: 'MCP Dangerous Command',
            severity: 'critical',
            category: 'mcp-security',
            owaspCategory: 'Agentic AI: Tool Manipulation',
            description: `MCP server launches dangerous command: ${dc}`,
            evidence: `${config.command} ${(config.args ?? []).join(' ')}`.slice(0, 200),
            session: ctx.session,
            channel: ctx.channel,
            action: 'alert',
          });
        }
      }
    }

    // Check for secrets in env
    if (config.env) {
      for (const [key, val] of Object.entries(config.env)) {
        if (/^(password|secret|token|api[_-]?key|private[_-]?key)/i.test(key) && val && val.length > 0) {
          // Only flag if the value looks like it's hardcoded (not a reference)
          if (!val.startsWith('$') && !val.startsWith('${') && !val.startsWith('%')) {
            findings.push({
              id: crypto.randomUUID(),
              timestamp: ctx.timestamp,
              ruleId: 'mcp-hardcoded-secret',
              ruleName: 'MCP Hardcoded Secret',
              severity: 'high',
              category: 'mcp-security',
              owaspCategory: 'Agentic AI: Tool Manipulation',
              description: `MCP server config contains hardcoded secret in env.${key}`,
              evidence: `${key}=${val.slice(0, 4)}***`,
              session: ctx.session,
              channel: ctx.channel,
              action: 'alert',
            });
          }
        }
      }
    }

    return { protocol: 'mcp', findings, summary: summarize(findings), scannedAt: ctx.timestamp };
  }

  /**
   * Scan an A2A agent card for security issues.
   */
  scanA2AAgent(agentCard: A2AAgentCard): ProtocolScanResult {
    const ctx = makeContext();
    const findings = checkA2ACard(agentCard, ctx);
    return { protocol: 'a2a', findings, summary: summarize(findings), scannedAt: ctx.timestamp };
  }

  /**
   * Scan an A2A task message for injection.
   */
  scanA2ATask(taskMessage: A2ATaskMessage): ProtocolScanResult {
    const ctx = makeContext();
    const issues = scanA2ATaskMessage(taskMessage);
    const findings: SecurityFinding[] = issues.map(issue => ({
      id: crypto.randomUUID(),
      timestamp: ctx.timestamp,
      ruleId: 'a2a-task-injection',
      ruleName: 'A2A Task Injection',
      severity: 'high' as const,
      category: 'a2a-security',
      owaspCategory: 'Agentic AI: Agent Communication',
      description: issue,
      session: ctx.session,
      channel: ctx.channel,
      action: 'alert' as const,
    }));
    return { protocol: 'a2a', findings, summary: summarize(findings), scannedAt: ctx.timestamp };
  }

  /**
   * Unified scan: MCP + A2A together.
   */
  scanBoth(config: { mcp?: MCPServerConfig; a2a?: A2AAgentCard }): ProtocolScanResult {
    const mcpResult = config.mcp ? this.scanMCPServer(config.mcp) : null;
    const a2aResult = config.a2a ? this.scanA2AAgent(config.a2a) : null;

    const allFindings = [
      ...(mcpResult?.findings ?? []),
      ...(a2aResult?.findings ?? []),
    ];

    return {
      protocol: 'both',
      findings: allFindings,
      summary: summarize(allFindings),
      scannedAt: Date.now(),
      mcpFindings: mcpResult?.findings,
      a2aFindings: a2aResult?.findings,
    };
  }
}
