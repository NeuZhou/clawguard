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
  a2aSecurityRule,
  a2aRules,
  checkA2ACard,
  scanA2ATaskMessage,
  detectInsiderThreats,
  INSIDER_THREAT_PATTERNS,
} from './rules';

/** Security scanning engine - OWASP LLM Top 10 aligned */
export { runSecurityScan, getSecurityScore, getRuleStatuses, loadCustomRules, loadCustomRulesFromFile, getCustomRuleCount } from './security-engine';

/** Risk scoring with attack chain detection */
export { calculateRisk, getVerdict, enrichFinding } from './risk-engine';

/** Policy engine for tool call evaluation */
export { evaluateToolCall, evaluateToolCallBatch, PolicyEngine } from './policy-engine';
export type { YAMLPolicy, PolicyRule, ArgumentRule, RateLimitRule, TimeRestriction, ConditionalRule } from './policy-engine';

/** Threat Intelligence - known bad patterns database */
export { ThreatIntel } from './threat-intel';
export type { ThreatResult, ThreatStats } from './threat-intel';

/** Compliance Reporter - generate compliance reports */
export { ComplianceReporter } from './compliance-reporter';
export type { ComplianceReport, ComplianceControl, ComplianceData, ComplianceStandard, ControlStatus } from './compliance-reporter';

/** Persistent storage for messages, findings, and config */
export { store } from './store';

/** PII Sanitizer — local PII/credential removal before LLM calls */
export { sanitize, restore, containsPII } from './sanitizer';
export type { SanitizeResult, Replacement } from './sanitizer';

/** Intent-Action Mismatch Detection — catches agents that say one thing but do another */
export { checkIntentAction, checkIntentActionBatch } from './intent-action';
export type { IntentActionCheck } from './intent-action';

/** Runtime MCP Interceptor — intercept, filter, and audit MCP tool calls */
export { MCPInterceptor } from './interceptor';
export type {
  InterceptMode,
  InterceptorConfig,
  RateLimitConfig,
  MCPClient,
  ProtectedMCPClient,
  InterceptorStats,
  MCPToolCall,
  MCPToolResult,
} from './interceptor';

/** Audit Logger — tamper-resistant hash-chained audit logging */
export { AuditLogger } from './audit-logger';
export type { AuditFilter } from './audit-logger';

/** Anomaly Detector — detect unusual agent behavior patterns */
export { AnomalyDetector } from './anomaly-detector';
export type { ToolCall, AnomalyResult, AnomalyReason } from './anomaly-detector';

/** Cost Tracker — track API costs per agent/session with budgets */
export { CostTracker } from './cost-tracker';
export type { CostCall, BudgetInfo, CostReport } from './cost-tracker';

/** Dashboard Generator — generate HTML security dashboards */
export { generateDashboard, loadDashboardData, writeDashboard } from './dashboard';
export type { DashboardData } from './dashboard';

/** A2A types re-export */
export type { A2AAgentCard, A2ATaskMessage, A2ASkill, A2AAuthentication, A2ACapabilities } from './rules/a2a-security';

/** Unified Protocol Scanner - MCP + A2A combined scanning */
export { ProtocolScanner } from './scanners/protocol-scanner';
export type { MCPServerConfig, ProtocolScanResult } from './scanners/protocol-scanner';
