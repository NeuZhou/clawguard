// OpenClaw Watch — Main Entry Point / Barrel Export

// Types
export * from './types';

// Rules
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
  detectInsiderThreats,
  INSIDER_THREAT_PATTERNS,
} from './rules';

// Engines
export { runSecurityScan, getSecurityScore, getRuleStatuses, loadCustomRules } from './security-engine';
export { calculateRisk, getVerdict, enrichFinding } from './risk-engine';
export { evaluateToolCall, evaluateToolCallBatch } from './policy-engine';

// Cost & Store
export { store } from './store';
