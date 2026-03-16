// ClawGuard — Runtime MCP Interceptor
// Intercepts MCP tool calls at runtime, applying policies, PII filtering, and audit logging

import { evaluateToolCall } from './policy-engine';
import { sanitize } from './sanitizer';
import { AuditLogger } from './audit-logger';
import { PolicyConfig, PolicyDecision } from './types';

export type InterceptMode = 'scan' | 'intercept' | 'monitor';

export interface InterceptorConfig {
  rules?: string;
  mode?: InterceptMode;
  policies?: PolicyConfig;
  piiFilter?: boolean;
  auditLog?: boolean;
  rateLimits?: Record<string, RateLimitConfig>;
  onBlock?: (decision: PolicyDecision, tool: string, args: Record<string, unknown>) => void;
  onWarn?: (decision: PolicyDecision, tool: string, args: Record<string, unknown>) => void;
  onAudit?: (event: { tool: string; args: Record<string, unknown>; decision: PolicyDecision }) => void;
}

export interface RateLimitConfig {
  limit: number;
  windowMs: number;
}

interface RateLimitState {
  timestamps: number[];
}

export interface MCPToolCall {
  tool: string;
  args: Record<string, unknown>;
}

export interface MCPToolResult {
  content: string | Record<string, unknown>;
  [key: string]: unknown;
}

export interface MCPClient {
  callTool(tool: string, args: Record<string, unknown>): Promise<MCPToolResult>;
}

export interface ProtectedMCPClient extends MCPClient {
  getAuditLogger(): AuditLogger;
  getStats(): InterceptorStats;
}

export interface InterceptorStats {
  totalCalls: number;
  blocked: number;
  warned: number;
  allowed: number;
  rateLimited: number;
  piiFiltered: number;
}

export class MCPInterceptor {
  private config: Required<Pick<InterceptorConfig, 'mode' | 'piiFilter' | 'auditLog'>> & InterceptorConfig;
  private auditLogger: AuditLogger;
  private rateLimitState: Map<string, RateLimitState> = new Map();
  private stats: InterceptorStats = {
    totalCalls: 0,
    blocked: 0,
    warned: 0,
    allowed: 0,
    rateLimited: 0,
    piiFiltered: 0,
  };

  constructor(config: InterceptorConfig = {}) {
    this.config = {
      mode: config.mode || 'intercept',
      piiFilter: config.piiFilter ?? true,
      auditLog: config.auditLog ?? true,
      ...config,
    };
    this.auditLogger = new AuditLogger();
  }

  /** Check rate limit for a tool */
  private checkRateLimit(tool: string): boolean {
    const limits = this.config.rateLimits;
    if (!limits || !limits[tool]) return true;

    const { limit, windowMs } = limits[tool];
    const now = Date.now();
    let state = this.rateLimitState.get(tool);
    if (!state) {
      state = { timestamps: [] };
      this.rateLimitState.set(tool, state);
    }

    // Remove timestamps outside the window
    state.timestamps = state.timestamps.filter(t => now - t < windowMs);

    if (state.timestamps.length >= limit) {
      return false;
    }

    state.timestamps.push(now);
    return true;
  }

  /** Intercept a tool call, applying policies */
  async interceptCall(
    tool: string,
    args: Record<string, unknown>,
    execute: (tool: string, args: Record<string, unknown>) => Promise<MCPToolResult>,
  ): Promise<MCPToolResult> {
    this.stats.totalCalls++;

    // 1. Policy evaluation
    const decision = evaluateToolCall(tool, args, this.config.policies);

    // 2. Audit logging
    if (this.config.auditLog) {
      this.auditLogger.log({
        type: 'tool_call',
        detail: `${tool}: ${JSON.stringify(args).slice(0, 200)}`,
        metadata: { tool, decision: decision.decision, reason: decision.reason },
      });
    }

    // 3. Callback
    this.config.onAudit?.({ tool, args, decision });

    // 4. Handle decision based on mode
    if (decision.decision === 'deny') {
      this.stats.blocked++;
      if (this.config.mode === 'intercept') {
        this.config.onBlock?.(decision, tool, args);
        return {
          content: `BLOCKED: ${decision.reason}`,
          blocked: true,
          decision,
        };
      }
      // monitor/scan mode — log but don't block
      if (this.config.mode === 'monitor') {
        this.config.onWarn?.(decision, tool, args);
      }
    }

    if (decision.decision === 'warn') {
      this.stats.warned++;
      this.config.onWarn?.(decision, tool, args);
    }

    // 5. Rate limiting
    if (!this.checkRateLimit(tool)) {
      this.stats.rateLimited++;
      if (this.config.mode === 'intercept') {
        const rateLimitDecision: PolicyDecision = {
          decision: 'deny',
          tool,
          reason: `Rate limit exceeded for tool: ${tool}`,
          severity: 'warning',
        };
        this.config.onBlock?.(rateLimitDecision, tool, args);
        return {
          content: `RATE_LIMITED: ${rateLimitDecision.reason}`,
          blocked: true,
          decision: rateLimitDecision,
        };
      }
    }

    // 6. PII filtering on args (if enabled)
    let filteredArgs = args;
    if (this.config.piiFilter) {
      const argsStr = JSON.stringify(args);
      const sanitized = sanitize(argsStr);
      if (sanitized.piiCount > 0) {
        this.stats.piiFiltered++;
        try {
          filteredArgs = JSON.parse(sanitized.sanitized);
        } catch {
          // If we can't parse back, use original args
          filteredArgs = args;
        }
      }
    }

    // 7. Execute the actual tool call
    this.stats.allowed++;
    const result = await execute(tool, this.config.mode === 'intercept' ? filteredArgs : args);

    // 8. PII filtering on response (if enabled)
    if (this.config.piiFilter && typeof result.content === 'string') {
      const sanitizedResponse = sanitize(result.content);
      if (sanitizedResponse.piiCount > 0) {
        result.content = sanitizedResponse.sanitized;
      }
    }

    return result;
  }

  /** Wrap an MCP client with interception */
  wrapMCPClient(client: MCPClient): ProtectedMCPClient {
    const interceptor = this;
    return {
      async callTool(tool: string, args: Record<string, unknown>): Promise<MCPToolResult> {
        return interceptor.interceptCall(tool, args, (t, a) => client.callTool(t, a));
      },
      getAuditLogger(): AuditLogger {
        return interceptor.auditLogger;
      },
      getStats(): InterceptorStats {
        return interceptor.stats;
      },
    };
  }

  /** Get audit logger instance */
  getAuditLogger(): AuditLogger {
    return this.auditLogger;
  }

  /** Get interceptor statistics */
  getStats(): InterceptorStats {
    return { ...this.stats };
  }

  /** Reset statistics */
  resetStats(): void {
    this.stats = {
      totalCalls: 0,
      blocked: 0,
      warned: 0,
      allowed: 0,
      rateLimited: 0,
      piiFiltered: 0,
    };
  }
}
