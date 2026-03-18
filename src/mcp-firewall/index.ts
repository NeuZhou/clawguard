// ClawGuard — MCP Firewall: Main Exports

export {
  McpFirewallProxy,
  parseMessage,
  isRequest,
  isResponse,
} from './proxy';

export {
  scanToolDescription,
  scanToolCallParams,
  scanToolOutput,
  scanToolsList,
  pinToolDescription,
  getDescriptionPins,
  clearDescriptionPins,
} from './scanner';

export {
  loadFirewallConfig,
  parseFirewallConfig,
  evaluateToolPolicy,
  shouldEnforce,
  recordDataFlow,
  getDataFlowLog,
  clearDataFlowLog,
  getDataFlowSummary,
  DEFAULT_FIREWALL_CONFIG,
} from './policy';
export type { PolicyDecision } from './policy';

export {
  FirewallDashboard,
  formatEventLog,
} from './dashboard';

export {
  runFirewallCli,
  parseFirewallArgs,
  resolveConfig,
  printFirewallHelp,
} from './cli';

// Re-export types
export type {
  JsonRpcRequest,
  JsonRpcResponse,
  JsonRpcMessage,
  JsonRpcError,
  McpToolDefinition,
  McpToolCallParams,
  McpToolResult,
  McpContentItem,
  McpCapabilities,
  McpInitializeResult,
  FirewallMode,
  ToolAction,
  ServerPolicy,
  ToolRule,
  ServerConfig,
  TransportConfig,
  DetectionConfig,
  AlertsConfig,
  FirewallConfig,
  InterceptDirection,
  InterceptResult,
  ProxyEvent,
  ToolDescriptionPin,
  ScanResult,
  DashboardStats,
} from './types';
