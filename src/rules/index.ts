// OpenClaw Watch — Security Rules Index

import { SecurityRule } from '../types';
import { promptInjectionRule } from './prompt-injection';
import { dataLeakageRule } from './data-leakage';
import { anomalyDetectionRule } from './anomaly-detection';
import { complianceRule } from './compliance';

export const builtinRules: SecurityRule[] = [
  promptInjectionRule,
  dataLeakageRule,
  anomalyDetectionRule,
  complianceRule,
];

export function getRuleById(id: string): SecurityRule | undefined {
  return builtinRules.find(r => r.id === id);
}

export { promptInjectionRule, dataLeakageRule, anomalyDetectionRule, complianceRule };
