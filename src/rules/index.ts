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

export const builtinRules: SecurityRule[] = [
  promptInjectionRule,
  dataLeakageRule,
  anomalyDetectionRule,
  complianceRule,
  fileProtectionRule,
  identityProtectionRule,
  mcpSecurityRule,
  supplyChainRule,
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
};

// Re-export insider threat as standalone module (not a SecurityRule, uses different API)
export { detectInsiderThreats, INSIDER_THREAT_PATTERNS } from './insider-threat';


