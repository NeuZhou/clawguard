// ClawGuard — MCP Firewall Type Definitions

import { SecurityFinding, Severity } from '../types';

// === JSON-RPC 2.0 Types ===

export interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: '2.0';
  id: string | number | null;
  result?: unknown;
  error?: JsonRpcError;
}

export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcResponse;

// === MCP Protocol Types ===

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface McpToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
}

export interface McpToolResult {
  content: McpContentItem[];
  isError?: boolean;
}

export interface McpContentItem {
  type: 'text' | 'image' | 'resource';
  text?: string;
  data?: string;
  mimeType?: string;
}

export interface McpCapabilities {
  tools?: Record<string, unknown>;
  resources?: Record<string, unknown>;
  prompts?: Record<string, unknown>;
}

export interface McpInitializeResult {
  protocolVersion: string;
  capabilities: McpCapabilities;
  serverInfo: { name: string; version: string };
}

// === Firewall Policy Types ===

export type FirewallMode = 'enforce' | 'monitor' | 'disabled';
export type ToolAction = 'allow' | 'block' | 'approve' | 'log-only';
export type ServerPolicy = 'allow-all' | 'block-all' | 'approve-writes' | 'block-destructive' | 'monitor';

export interface ToolRule {
  action: ToolAction;
  alert?: boolean;
}

export interface ServerConfig {
  name: string;
  policy: ServerPolicy;
  tools?: Record<string, ToolRule>;
}

export interface TransportConfig {
  type: 'stdio' | 'sse';
  port?: number;
  host?: string;
}

export interface DetectionConfig {
  injection_scanning: boolean;
  rug_pull_detection: boolean;
  parameter_sanitization: boolean;
  output_validation: boolean;
}

export interface AlertsConfig {
  console: boolean;
  webhook: string | null;
}

export interface FirewallConfig {
  mode: FirewallMode;
  transports: TransportConfig[];
  defaults: {
    policy: ServerPolicy;
  };
  servers: ServerConfig[];
  detection: DetectionConfig;
  alerts: AlertsConfig;
}

// === Proxy Event Types ===

export type InterceptDirection = 'client-to-server' | 'server-to-client';

export interface InterceptResult {
  action: 'forward' | 'block' | 'modify' | 'approve';
  message: JsonRpcMessage;
  findings: SecurityFinding[];
  modified?: boolean;
  reason?: string;
}

export interface ProxyEvent {
  id: string;
  timestamp: number;
  direction: InterceptDirection;
  server: string;
  method?: string;
  action: 'forward' | 'block' | 'modify' | 'approve';
  findings: SecurityFinding[];
  latencyMs?: number;
}

// === Scanner Types ===

export interface ToolDescriptionPin {
  server: string;
  toolName: string;
  descriptionHash: string;
  firstSeen: number;
  lastSeen: number;
}

export interface ScanResult {
  findings: SecurityFinding[];
  blocked: boolean;
  reason?: string;
}

// === Dashboard Types ===

export interface DashboardStats {
  totalMessages: number;
  blocked: number;
  allowed: number;
  modified: number;
  pendingApproval: number;
  findings: SecurityFinding[];
  recentEvents: ProxyEvent[];
  serverStats: Record<string, { calls: number; blocked: number }>;
}
