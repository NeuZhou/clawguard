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
import { privilegeEscalationRule } from './privilege-escalation';
import { rugPullRule } from './rug-pull';
import { resourceAbuseRule } from './resource-abuse';
import { crossAgentContaminationRule } from './cross-agent-contamination';
import { complianceFrameworksRule } from './compliance-frameworks';

import { insiderThreatRule } from './insider-threat';
import { memoryAttackRule } from './memory-attacks';

export const builtinRules: SecurityRule[] = [
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
  insiderThreatRule,
  memoryAttackRule,
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
  privilegeEscalationRule,
  rugPullRule,
  resourceAbuseRule,
  crossAgentContaminationRule,
  complianceFrameworksRule,
  memoryAttackRule,
};

// Re-export insider threat as standalone module (not a SecurityRule, uses different API)
export { detectInsiderThreats, INSIDER_THREAT_PATTERNS, insiderThreatRule } from './insider-threat';
