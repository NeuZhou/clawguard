// ClawGuard - Main Entry Point / Barrel Export

/** Type definitions for ClawGuard */
export * from './types';

/** Built-in security rules and rule utilities */
export {
  builtinRules,
  getRuleById,
  promptInjectionRule,
  dataLeakageRule,
  anomalyDetectionRule,
  complianceRule,
  fileProtectionRule,
  identityProtectionRule,
  mcpSecurityRule,
  supplyChainRule,
  privilegeEscalationRule,
  rugPullRule,
  resourceAbuseRule,
  crossAgentContaminationRule,
  complianceFrameworksRule,
  detectInsiderThreats,
  INSIDER_THREAT_PATTERNS,
  insiderThreatRule,
  memoryAttackRule,
} from './rules';

/** Security scanning engine - OWASP LLM Top 10 aligned */
export { runSecurityScan, getSecurityScore, getRuleStatuses, loadCustomRules, registerCustomRule, clearCustomRules } from './security-engine';

/** Risk scoring with attack chain detection */
export { calculateRisk, getVerdict, enrichFinding } from './risk-engine';

/** Policy engine for tool call evaluation */
export { evaluateToolCall, evaluateToolCallBatch } from './policy-engine';

/** YARA rule engine — custom pattern matching */
export { loadYaraRules, matchYaraRules } from './yara-engine';
export type { YaraRule, YaraMatch, YaraString } from './yara-engine';

/** Persistent storage for messages, findings, and config */
export { store } from './store';

/** Alert engine — security alert dispatch and budget monitoring */
export { checkSecurityAlert, checkCostBudget, checkHealthAlerts, setAlertSink, resetDailyBudgetAlerts, getAlertState } from './alert-engine';
export type { AlertSink } from './alert-engine';

/** Cost estimation engine — model pricing and token cost calculation */
export { estimateTokens, getModelPricing, calculateCost, getAllModelPricing } from './cost-engine';
export type { ModelPricing } from './cost-engine';

/** Integrity engine — SHA-256 hash chain audit trail */
export { createAuditEvent, verifyChain, initIntegrity } from './integrity';

/** Exporters — JSONL, Syslog/CEF, Webhook, SARIF */
export { exportJsonl, formatJsonlLine } from './exporters/jsonl';
export { sendToSyslog, formatCEF } from './exporters/syslog';
export { sendWebhook } from './exporters/webhook';
export { toSarif } from './exporters/sarif';
export type { ScanFinding } from './exporters/sarif';

/** PII Sanitizer — local PII/credential removal before LLM calls */
export { sanitize, restore, containsPII } from './sanitizer';
export type { SanitizeResult, Replacement } from './sanitizer';

/** Intent-Action Mismatch Detection — catches agents that say one thing but do another */
export { checkIntentAction, checkIntentActionBatch } from './intent-action';
export type { IntentActionCheck } from './intent-action';

/** MCP Firewall — real-time security proxy for Model Context Protocol */
export {
  McpFirewallProxy,
  parseMessage,
  isRequest,
  isResponse,
  scanToolDescription,
  scanToolCallParams,
  scanToolOutput,
  scanToolsList,
  pinToolDescription,
  getDescriptionPins,
  clearDescriptionPins,
  loadFirewallConfig,
  parseFirewallConfig,
  evaluateToolPolicy,
  shouldEnforce,
  recordDataFlow,
  getDataFlowLog,
  clearDataFlowLog,
  getDataFlowSummary,
  DEFAULT_FIREWALL_CONFIG,
  FirewallDashboard,
  formatEventLog,
  runFirewallCli,
  parseFirewallArgs,
} from './mcp-firewall';
export type {
  JsonRpcRequest,
  JsonRpcResponse,
  JsonRpcMessage,
  McpToolDefinition,
  McpToolCallParams,
  McpToolResult,
  FirewallConfig,
  FirewallMode,
  ToolAction,
  ServerPolicy,
  InterceptResult,
  ProxyEvent,
  ScanResult,
  DashboardStats,
  ToolDescriptionPin,
} from './mcp-firewall';


