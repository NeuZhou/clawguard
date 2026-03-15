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
  detectInsiderThreats,
  INSIDER_THREAT_PATTERNS,
} from './rules';

/** Security scanning engine - OWASP LLM Top 10 aligned */
export { runSecurityScan, getSecurityScore, getRuleStatuses, loadCustomRules } from './security-engine';

/** Risk scoring with attack chain detection */
export { calculateRisk, getVerdict, enrichFinding } from './risk-engine';

/** Policy engine for tool call evaluation */
export { evaluateToolCall, evaluateToolCallBatch } from './policy-engine';

/** Persistent storage for messages, findings, and config */
export { store } from './store';

/** PII Sanitizer — local PII/credential removal before LLM calls */
export { sanitize, restore, containsPII } from './sanitizer';
export type { SanitizeResult, Replacement } from './sanitizer';

/** Intent-Action Mismatch Detection — catches agents that say one thing but do another */
export { checkIntentAction, checkIntentActionBatch } from './intent-action';
export type { IntentActionCheck } from './intent-action';


