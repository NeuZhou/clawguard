// ClawGuard — Security Rules Index

import { SecurityRule } from '../types';
import { promptInjectionRule } from './prompt-injection';
import { dataLeakageRule } from './data-leakage';
import { anomalyDetectionRule } from './anomaly-detection';
import { complianceRule } from './compliance';
import { fileProtectionRule } from './file-protection';
import { identityProtectionRule } from './identity-protection';
import { mcpSecurityRule } from './mcp-security';
import { supplyChainRule } from './supply-chain';
import { memoryPoisoningRule } from './memory-poisoning';
import { apiKeyExposureRule } from './api-key-exposure';
import { permissionEscalationRule } from './permission-escalation';
import { a2aSecurityRule } from './a2a-security';

export const builtinRules: SecurityRule[] = [
  promptInjectionRule,
  dataLeakageRule,
  anomalyDetectionRule,
  complianceRule,
  fileProtectionRule,
  identityProtectionRule,
  mcpSecurityRule,
  supplyChainRule,
  memoryPoisoningRule,
  apiKeyExposureRule,
  permissionEscalationRule,
  a2aSecurityRule,
];

export function getRuleById(id: string): SecurityRule | undefined {
  return builtinRules.find(r => r.id === id);
}

export {
  promptInjectionRule,
  dataLeakageRule,
  anomalyDetectionRule,
  complianceRule,
  fileProtectionRule,
  identityProtectionRule,
  mcpSecurityRule,
  supplyChainRule,
  memoryPoisoningRule,
  apiKeyExposureRule,
  permissionEscalationRule,
};

// A2A Security exports
export { a2aSecurityRule, a2aRules, checkA2ACard, scanA2ATaskMessage } from './a2a-security';
export type { A2AAgentCard, A2ATaskMessage, A2ASkill, A2AAuthentication, A2ACapabilities } from './a2a-security';

// Re-export insider threat as standalone module (not a SecurityRule, uses different API)
export { detectInsiderThreats, INSIDER_THREAT_PATTERNS } from './insider-threat';
