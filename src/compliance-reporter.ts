// ClawGuard - Compliance Reporter
// Generate compliance reports against SOC2, ISO27001, NIST, GDPR standards

import { AuditEvent, SecurityFinding, Severity } from './types';

export type ComplianceStandard = 'soc2' | 'iso27001' | 'nist' | 'gdpr';
export type ControlStatus = 'pass' | 'partial' | 'fail' | 'not-applicable';

export interface ComplianceControl {
  id: string;
  name: string;
  description: string;
  status: ControlStatus;
  evidence: string[];
  recommendations: string[];
}

export interface ComplianceReport {
  standard: ComplianceStandard;
  generatedAt: number;
  overallScore: number;  // 0-100
  overallStatus: ControlStatus;
  controls: ComplianceControl[];
  summary: string;
}

export interface ComplianceData {
  auditEvents?: AuditEvent[];
  findings?: SecurityFinding[];
  toolAccessControls?: boolean;
  auditLoggingEnabled?: boolean;
  piiSanitizationEnabled?: boolean;
  encryptionEnabled?: boolean;
  retentionDays?: number;
  rateLimitsConfigured?: boolean;
  anomalyDetectionEnabled?: boolean;
  incidentResponsePlan?: boolean;
  dataClassification?: boolean;
}

// ─── Standard Definitions ───

const SOC2_CONTROLS: Array<{ id: string; name: string; description: string; check: (data: ComplianceData) => { status: ControlStatus; evidence: string[]; recommendations: string[] } }> = [
  {
    id: 'CC6.1',
    name: 'Logical Access',
    description: 'Logical access security controls over protected information assets',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.toolAccessControls) evidence.push('Tool access controls are in place');
      else recs.push('Enable tool access controls in policy engine');
      if (data.rateLimitsConfigured) evidence.push('Rate limits configured');
      else recs.push('Configure rate limits for tool calls');
      const status: ControlStatus = evidence.length >= 2 ? 'pass' : evidence.length >= 1 ? 'partial' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'CC6.2',
    name: 'System Boundaries',
    description: 'Controls over system boundaries and network security',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      const unbounded = data.findings?.filter(f => f.category === 'unbounded-tool').length || 0;
      if (unbounded === 0) {
        evidence.push('All tools have defined boundaries');
      } else {
        recs.push(`${unbounded} unbounded tools detected — define policies`);
      }
      if (data.toolAccessControls) evidence.push('Policy engine active');
      const status: ControlStatus = recs.length === 0 ? 'pass' : evidence.length > 0 ? 'partial' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'CC6.3',
    name: 'Access Removal',
    description: 'Timely removal of access for terminated entities',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.auditEvents && data.auditEvents.length > 0) evidence.push('Audit trail exists for access changes');
      else recs.push('Enable audit logging for access changes');
      const status: ControlStatus = evidence.length > 0 ? 'pass' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'CC7.1',
    name: 'Monitoring',
    description: 'Detection and monitoring of security events',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.auditLoggingEnabled) evidence.push('Audit logging enabled');
      else recs.push('Enable audit logging');
      if (data.anomalyDetectionEnabled) evidence.push('Anomaly detection active');
      else recs.push('Enable anomaly detection');
      const status: ControlStatus = evidence.length >= 2 ? 'pass' : evidence.length >= 1 ? 'partial' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'CC7.2',
    name: 'Incident Response',
    description: 'Incident identification and response procedures',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.incidentResponsePlan) evidence.push('Incident response plan documented');
      else recs.push('Document incident response plan');
      const criticalFindings = data.findings?.filter(f => f.severity === 'critical').length || 0;
      if (criticalFindings === 0) evidence.push('No unresolved critical findings');
      else recs.push(`${criticalFindings} critical findings require attention`);
      const status: ControlStatus = recs.length === 0 ? 'pass' : evidence.length > 0 ? 'partial' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'CC8.1',
    name: 'Change Management',
    description: 'Changes are authorized and controlled',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.auditLoggingEnabled) evidence.push('Changes are audit-logged');
      else recs.push('Enable audit logging for change tracking');
      const status: ControlStatus = evidence.length > 0 ? 'pass' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
];

const ISO27001_CONTROLS: Array<{ id: string; name: string; description: string; check: (data: ComplianceData) => { status: ControlStatus; evidence: string[]; recommendations: string[] } }> = [
  {
    id: 'A.8.2',
    name: 'Information Classification',
    description: 'Information shall be classified in terms of legal requirements, value, criticality and sensitivity',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.dataClassification) evidence.push('Data classification is active');
      else recs.push('Implement data classification policies');
      if (data.piiSanitizationEnabled) evidence.push('PII sanitization enabled');
      else recs.push('Enable PII sanitization');
      const status: ControlStatus = evidence.length >= 2 ? 'pass' : evidence.length >= 1 ? 'partial' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'A.9.2',
    name: 'User Access Management',
    description: 'Formal user access provisioning and de-provisioning',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.toolAccessControls) evidence.push('Tool access controls active');
      else recs.push('Define tool access control policies');
      const status: ControlStatus = evidence.length > 0 ? 'pass' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'A.12.4',
    name: 'Logging and Monitoring',
    description: 'Event logs recording user activities and security events',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.auditLoggingEnabled) evidence.push('Audit logging enabled');
      else recs.push('Enable audit logging');
      if (data.retentionDays && data.retentionDays >= 90) evidence.push(`Log retention: ${data.retentionDays} days`);
      else recs.push('Set log retention to at least 90 days');
      const status: ControlStatus = evidence.length >= 2 ? 'pass' : evidence.length >= 1 ? 'partial' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'A.10.1',
    name: 'Cryptographic Controls',
    description: 'Policy on the use of cryptographic controls',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.encryptionEnabled) evidence.push('Encryption enabled for data at rest');
      else recs.push('Enable encryption for stored data');
      const status: ControlStatus = evidence.length > 0 ? 'pass' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
];

const GDPR_CONTROLS: Array<{ id: string; name: string; description: string; check: (data: ComplianceData) => { status: ControlStatus; evidence: string[]; recommendations: string[] } }> = [
  {
    id: 'Art.5',
    name: 'Data Processing Principles',
    description: 'Lawfulness, fairness, transparency, purpose limitation, data minimisation',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.piiSanitizationEnabled) evidence.push('PII sanitization prevents unnecessary data processing');
      else recs.push('Enable PII sanitization for data minimisation');
      if (data.dataClassification) evidence.push('Data classification active');
      else recs.push('Implement data classification');
      const status: ControlStatus = evidence.length >= 2 ? 'pass' : evidence.length >= 1 ? 'partial' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'Art.30',
    name: 'Records of Processing',
    description: 'Maintain records of processing activities',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.auditLoggingEnabled) evidence.push('Audit logging captures processing records');
      else recs.push('Enable audit logging for GDPR compliance');
      const status: ControlStatus = evidence.length > 0 ? 'pass' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'Art.32',
    name: 'Security of Processing',
    description: 'Implement appropriate technical and organisational measures',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.encryptionEnabled) evidence.push('Encryption enabled');
      if (data.anomalyDetectionEnabled) evidence.push('Anomaly detection active');
      if (data.toolAccessControls) evidence.push('Access controls in place');
      if (evidence.length < 2) recs.push('Implement additional security measures');
      const status: ControlStatus = evidence.length >= 3 ? 'pass' : evidence.length >= 1 ? 'partial' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
  {
    id: 'Art.33',
    name: 'Breach Notification',
    description: 'Notification of personal data breach to supervisory authority',
    check: (data) => {
      const evidence: string[] = [];
      const recs: string[] = [];
      if (data.incidentResponsePlan) evidence.push('Incident response plan includes breach notification');
      else recs.push('Document breach notification procedures');
      const status: ControlStatus = evidence.length > 0 ? 'pass' : 'fail';
      return { status, evidence, recommendations: recs };
    },
  },
];

// ─── Compliance Reporter Class ───

export class ComplianceReporter {
  /** Generate a compliance report for a given standard */
  generateReport(standard: ComplianceStandard, data: ComplianceData): ComplianceReport {
    const controls = this.getControlChecks(standard);
    const evaluatedControls: ComplianceControl[] = controls.map(ctrl => {
      const result = ctrl.check(data);
      return {
        id: ctrl.id,
        name: ctrl.name,
        description: ctrl.description,
        ...result,
      };
    });

    const passCount = evaluatedControls.filter(c => c.status === 'pass').length;
    const partialCount = evaluatedControls.filter(c => c.status === 'partial').length;
    const total = evaluatedControls.length;
    const overallScore = Math.round(((passCount + partialCount * 0.5) / total) * 100);

    const overallStatus: ControlStatus =
      overallScore >= 90 ? 'pass' :
      overallScore >= 60 ? 'partial' : 'fail';

    const summary = this.buildSummary(standard, evaluatedControls, overallScore);

    return {
      standard,
      generatedAt: Date.now(),
      overallScore,
      overallStatus,
      controls: evaluatedControls,
      summary,
    };
  }

  /** Format report as human-readable text */
  formatReport(report: ComplianceReport): string {
    const statusIcon = (s: ControlStatus) =>
      s === 'pass' ? '✅ PASS' :
      s === 'partial' ? '⚠️  PARTIAL' :
      s === 'fail' ? '❌ FAIL' : '➖ N/A';

    const lines: string[] = [
      `\n🛡️  ${report.standard.toUpperCase()} Compliance Report`,
      `Generated: ${new Date(report.generatedAt).toISOString()}`,
      `Overall Score: ${report.overallScore}% (${statusIcon(report.overallStatus)})`,
      '─'.repeat(60),
    ];

    for (const ctrl of report.controls) {
      lines.push(`${ctrl.id} ${ctrl.name}: ${statusIcon(ctrl.status)}`);
      for (const e of ctrl.evidence) lines.push(`  ✓ ${e}`);
      for (const r of ctrl.recommendations) lines.push(`  → ${r}`);
    }

    lines.push('─'.repeat(60));
    lines.push(report.summary);
    return lines.join('\n');
  }

  /** Get supported standards */
  getSupportedStandards(): ComplianceStandard[] {
    return ['soc2', 'iso27001', 'nist', 'gdpr'];
  }

  private getControlChecks(standard: ComplianceStandard) {
    switch (standard) {
      case 'soc2': return SOC2_CONTROLS;
      case 'iso27001': return ISO27001_CONTROLS;
      case 'gdpr': return GDPR_CONTROLS;
      case 'nist': return ISO27001_CONTROLS; // Use ISO as proxy for now
      default: throw new Error(`Unsupported standard: ${standard}`);
    }
  }

  private buildSummary(standard: ComplianceStandard, controls: ComplianceControl[], score: number): string {
    const pass = controls.filter(c => c.status === 'pass').length;
    const partial = controls.filter(c => c.status === 'partial').length;
    const fail = controls.filter(c => c.status === 'fail').length;
    return `${standard.toUpperCase()}: ${pass} passed, ${partial} partial, ${fail} failed. Score: ${score}%`;
  }
}
