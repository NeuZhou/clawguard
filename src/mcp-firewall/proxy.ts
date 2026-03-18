// ClawGuard — MCP Firewall: Core Proxy
// Intercepts MCP JSON-RPC messages bidirectionally

import * as crypto from 'crypto';
import { SecurityFinding } from '../types';
import {
  JsonRpcMessage,
  JsonRpcRequest,
  JsonRpcResponse,
  McpToolDefinition,
  McpToolCallParams,
  McpToolResult,
  InterceptResult,
  InterceptDirection,
  ProxyEvent,
  FirewallConfig,
  DashboardStats,
} from './types';
import {
  scanToolsList,
  scanToolCallParams,
  scanToolOutput,
  clearDescriptionPins,
} from './scanner';
import {
  evaluateToolPolicy,
  shouldEnforce,
  recordDataFlow,
  DEFAULT_FIREWALL_CONFIG,
  PolicyDecision,
} from './policy';

// ── JSON-RPC Message Classification ──

export function isRequest(msg: JsonRpcMessage): msg is JsonRpcRequest {
  return 'method' in msg;
}

export function isResponse(msg: JsonRpcMessage): msg is JsonRpcResponse {
  return 'result' in msg || 'error' in msg;
}

/**
 * Parse a raw JSON string into a JsonRpcMessage.
 * Returns null if parsing fails.
 */
export function parseMessage(raw: string): JsonRpcMessage | null {
  try {
    const parsed = JSON.parse(raw);
    if (parsed.jsonrpc !== '2.0') return null;
    return parsed as JsonRpcMessage;
  } catch {
    return null;
  }
}

// ── Pending Request Tracking ──

interface PendingRequest {
  method: string;
  params?: Record<string, unknown>;
  server: string;
  timestamp: number;
}

// ── MCP Firewall Proxy ──

export class McpFirewallProxy {
  private config: FirewallConfig;
  private pendingRequests = new Map<string | number, PendingRequest>();
  private events: ProxyEvent[] = [];
  private stats = {
    totalMessages: 0,
    blocked: 0,
    allowed: 0,
    modified: 0,
    pendingApproval: 0,
  };
  private eventListeners: ((event: ProxyEvent) => void)[] = [];

  constructor(config?: FirewallConfig) {
    this.config = config || DEFAULT_FIREWALL_CONFIG;
  }

  /** Update the firewall config dynamically */
  setConfig(config: FirewallConfig): void {
    this.config = config;
  }

  /** Get current config */
  getConfig(): FirewallConfig {
    return this.config;
  }

  /** Register an event listener for proxy events */
  onEvent(listener: (event: ProxyEvent) => void): void {
    this.eventListeners.push(listener);
  }

  /** Remove an event listener */
  offEvent(listener: (event: ProxyEvent) => void): void {
    this.eventListeners = this.eventListeners.filter(l => l !== listener);
  }

  private emitEvent(event: ProxyEvent): void {
    this.events.push(event);
    if (this.events.length > 10000) {
      this.events.splice(0, this.events.length - 10000);
    }
    for (const listener of this.eventListeners) {
      try { listener(event); } catch { /* ignore listener errors */ }
    }
  }

  /** Get dashboard statistics */
  getStats(): DashboardStats {
    const serverStats: Record<string, { calls: number; blocked: number }> = {};
    for (const event of this.events) {
      if (!serverStats[event.server]) {
        serverStats[event.server] = { calls: 0, blocked: 0 };
      }
      serverStats[event.server].calls++;
      if (event.action === 'block') serverStats[event.server].blocked++;
    }

    return {
      ...this.stats,
      findings: this.events.flatMap(e => e.findings),
      recentEvents: this.events.slice(-50),
      serverStats,
    };
  }

  /** Reset stats (for testing) */
  resetStats(): void {
    this.stats = { totalMessages: 0, blocked: 0, allowed: 0, modified: 0, pendingApproval: 0 };
    this.events = [];
    this.pendingRequests.clear();
  }

  /**
   * Intercept a message from client to server.
   * This handles outgoing requests (tools/call, etc.)
   */
  interceptClientToServer(
    msg: JsonRpcMessage,
    serverName: string,
  ): InterceptResult {
    this.stats.totalMessages++;
    const startTime = Date.now();

    if (this.config.mode === 'disabled') {
      return this.forward(msg, []);
    }

    if (!isRequest(msg)) {
      return this.forward(msg, []);
    }

    const request = msg as JsonRpcRequest;

    // Track pending request for response correlation
    if (request.id !== undefined && request.id !== null) {
      this.pendingRequests.set(request.id, {
        method: request.method,
        params: request.params,
        server: serverName,
        timestamp: startTime,
      });
    }

    const findings: SecurityFinding[] = [];

    // === Handle tools/call requests ===
    if (request.method === 'tools/call' && request.params) {
      const toolCall: McpToolCallParams = {
        name: String(request.params.name || ''),
        arguments: (request.params.arguments as Record<string, unknown>) || {},
      };

      // 1. Check policy
      const policyDecision = evaluateToolPolicy(this.config, serverName, toolCall.name);

      if (policyDecision.action === 'block') {
        const blockFinding = this.createPolicyFinding(policyDecision, serverName, toolCall.name);
        findings.push(blockFinding);

        this.emitEvent({
          id: crypto.randomUUID(),
          timestamp: startTime,
          direction: 'client-to-server',
          server: serverName,
          method: request.method,
          action: 'block',
          findings,
          latencyMs: Date.now() - startTime,
        });
        this.stats.blocked++;

        recordDataFlow({
          server: serverName,
          tool: toolCall.name,
          direction: 'request',
          paramKeys: Object.keys(toolCall.arguments || {}),
          blocked: true,
        });

        if (shouldEnforce(this.config)) {
          return this.block(msg, findings, policyDecision.reason);
        }
      }

      if (policyDecision.action === 'approve') {
        this.stats.pendingApproval++;
        const approveFinding = this.createPolicyFinding(policyDecision, serverName, toolCall.name);
        findings.push(approveFinding);

        this.emitEvent({
          id: crypto.randomUUID(),
          timestamp: startTime,
          direction: 'client-to-server',
          server: serverName,
          method: request.method,
          action: 'approve',
          findings,
          latencyMs: Date.now() - startTime,
        });

        // In enforce mode, block until approval
        if (shouldEnforce(this.config)) {
          return {
            action: 'approve',
            message: msg,
            findings,
            reason: `Requires approval: ${policyDecision.reason}`,
          };
        }
      }

      // 2. Parameter sanitization scan
      if (this.config.detection.parameter_sanitization) {
        const paramResult = scanToolCallParams(serverName, toolCall);
        findings.push(...paramResult.findings);

        if (paramResult.blocked && shouldEnforce(this.config)) {
          this.stats.blocked++;
          this.emitEvent({
            id: crypto.randomUUID(),
            timestamp: startTime,
            direction: 'client-to-server',
            server: serverName,
            method: request.method,
            action: 'block',
            findings,
            latencyMs: Date.now() - startTime,
          });

          recordDataFlow({
            server: serverName,
            tool: toolCall.name,
            direction: 'request',
            paramKeys: Object.keys(toolCall.arguments || {}),
            blocked: true,
          });

          return this.block(msg, findings, paramResult.reason!);
        }
      }

      // Record allowed data flow
      recordDataFlow({
        server: serverName,
        tool: toolCall.name,
        direction: 'request',
        paramKeys: Object.keys(toolCall.arguments || {}),
        blocked: false,
      });
    }

    const action = findings.length > 0 ? 'modify' : 'forward';
    if (action === 'modify') this.stats.modified++;
    else this.stats.allowed++;

    this.emitEvent({
      id: crypto.randomUUID(),
      timestamp: startTime,
      direction: 'client-to-server',
      server: serverName,
      method: request.method,
      action,
      findings,
      latencyMs: Date.now() - startTime,
    });

    return this.forward(msg, findings);
  }

  /**
   * Intercept a message from server to client.
   * This handles incoming responses (tools/list results, tools/call results, etc.)
   */
  interceptServerToClient(
    msg: JsonRpcMessage,
    serverName: string,
  ): InterceptResult {
    this.stats.totalMessages++;
    const startTime = Date.now();

    if (this.config.mode === 'disabled') {
      return this.forward(msg, []);
    }

    const findings: SecurityFinding[] = [];

    // For responses, correlate with the original request
    if (isResponse(msg)) {
      const response = msg as JsonRpcResponse;
      const pending = response.id !== null ? this.pendingRequests.get(response.id!) : undefined;

      if (pending) {
        // Remove from pending
        if (response.id !== null) this.pendingRequests.delete(response.id!);

        // === Handle tools/list responses ===
        if (pending.method === 'tools/list' && response.result) {
          const result = response.result as { tools?: McpToolDefinition[] };
          if (result.tools && Array.isArray(result.tools)) {
            if (this.config.detection.injection_scanning || this.config.detection.rug_pull_detection) {
              const scanResult = scanToolsList(
                serverName,
                result.tools,
                this.config.detection.rug_pull_detection,
              );
              findings.push(...scanResult.findings);

              if (scanResult.blocked && shouldEnforce(this.config)) {
                this.stats.blocked++;
                this.emitEvent({
                  id: crypto.randomUUID(),
                  timestamp: startTime,
                  direction: 'server-to-client',
                  server: serverName,
                  method: pending.method,
                  action: 'block',
                  findings,
                  latencyMs: Date.now() - startTime,
                });
                return this.block(msg, findings, scanResult.reason!);
              }
            }
          }
        }

        // === Handle tools/call responses ===
        if (pending.method === 'tools/call' && response.result && this.config.detection.output_validation) {
          const toolName = pending.params?.name as string || 'unknown';
          const result = response.result as { content?: McpToolResult['content'] };

          if (result.content && Array.isArray(result.content)) {
            const outputResult = scanToolOutput(serverName, toolName, {
              content: result.content,
            });
            findings.push(...outputResult.findings);

            if (outputResult.blocked && shouldEnforce(this.config)) {
              this.stats.blocked++;
              this.emitEvent({
                id: crypto.randomUUID(),
                timestamp: startTime,
                direction: 'server-to-client',
                server: serverName,
                method: pending.method,
                action: 'block',
                findings,
                latencyMs: Date.now() - startTime,
              });

              recordDataFlow({
                server: serverName,
                tool: toolName,
                direction: 'response',
                resultTypes: result.content.map(c => c.type),
                blocked: true,
              });

              return this.block(msg, findings, outputResult.reason!);
            }

            recordDataFlow({
              server: serverName,
              tool: toolName,
              direction: 'response',
              resultTypes: result.content.map(c => c.type),
              blocked: false,
            });
          }
        }

        // === Handle resources/read responses ===
        if (pending.method === 'resources/read' && response.result && this.config.detection.output_validation) {
          const result = response.result as { contents?: { text?: string; uri?: string }[] };
          if (result.contents && Array.isArray(result.contents)) {
            for (const content of result.contents) {
              if (content.text) {
                const outputResult = scanToolOutput(serverName, 'resources/read', {
                  content: [{ type: 'text', text: content.text }],
                });
                findings.push(...outputResult.findings);
              }
            }
          }
        }
      }
    }

    // Also scan requests from server (notifications like tool changes)
    if (isRequest(msg)) {
      const request = msg as JsonRpcRequest;

      // Handle notifications/tool_list_changed
      if (request.method === 'notifications/tools/list_changed') {
        // Flag this as a potential concern - the server changed its tool list
        findings.push({
          id: crypto.randomUUID(),
          timestamp: startTime,
          ruleId: 'mcp-firewall-tool-change',
          ruleName: 'MCP Firewall: Tool List Changed',
          severity: 'warning',
          category: 'rug-pull',
          owaspCategory: 'Agentic AI: Rug Pull',
          description: `Server "${serverName}" notified tool list change — re-verify tools`,
          action: 'alert',
        });
      }
    }

    const action = findings.some(f => f.severity === 'critical' || f.severity === 'high')
      ? 'modify' : 'forward';
    if (action === 'modify') this.stats.modified++;
    else this.stats.allowed++;

    this.emitEvent({
      id: crypto.randomUUID(),
      timestamp: startTime,
      direction: 'server-to-client',
      server: serverName,
      method: isRequest(msg) ? (msg as JsonRpcRequest).method : undefined,
      action,
      findings,
      latencyMs: Date.now() - startTime,
    });

    return this.forward(msg, findings);
  }

  /**
   * Process a raw JSON message string. Determines direction and delegates.
   */
  processMessage(
    raw: string,
    direction: InterceptDirection,
    serverName: string,
  ): InterceptResult | null {
    const msg = parseMessage(raw);
    if (!msg) return null;

    if (direction === 'client-to-server') {
      return this.interceptClientToServer(msg, serverName);
    } else {
      return this.interceptServerToClient(msg, serverName);
    }
  }

  // ── Helper Methods ──

  private forward(msg: JsonRpcMessage, findings: SecurityFinding[]): InterceptResult {
    return { action: 'forward', message: msg, findings };
  }

  private block(msg: JsonRpcMessage, findings: SecurityFinding[], reason: string): InterceptResult {
    // Return an error response for requests
    if (isRequest(msg)) {
      const request = msg as JsonRpcRequest;
      const errorResponse: JsonRpcResponse = {
        jsonrpc: '2.0',
        id: request.id ?? null,
        error: {
          code: -32600,
          message: `Blocked by ClawGuard MCP Firewall: ${reason}`,
        },
      };
      return { action: 'block', message: errorResponse, findings, reason };
    }
    return { action: 'block', message: msg, findings, reason };
  }

  private createPolicyFinding(
    decision: PolicyDecision,
    server: string,
    tool: string,
  ): SecurityFinding {
    const severity = decision.action === 'block' ? 'high' : 'warning';
    return {
      id: crypto.randomUUID(),
      timestamp: Date.now(),
      ruleId: 'mcp-firewall-policy',
      ruleName: 'MCP Firewall: Policy',
      severity,
      category: 'policy',
      owaspCategory: 'Agentic AI: Tool Manipulation',
      description: decision.reason,
      evidence: `${server}/${tool} → ${decision.action}`,
      action: decision.action === 'block' ? 'block' : 'alert',
    };
  }
}
