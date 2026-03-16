// ClawGuard - Tests: Compliance Reporter

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import { ComplianceReporter, ComplianceData, ComplianceStandard } from '../src/compliance-reporter';

describe('ComplianceReporter', () => {
  const reporter = new ComplianceReporter();

  // === SOC2 ===
  describe('SOC2', () => {
    it('generates full-pass report with all controls enabled', () => {
      const data: ComplianceData = {
        toolAccessControls: true,
        auditLoggingEnabled: true,
        anomalyDetectionEnabled: true,
        piiSanitizationEnabled: true,
        rateLimitsConfigured: true,
        incidentResponsePlan: true,
        findings: [],
        auditEvents: [{ id: '1', timestamp: Date.now(), type: 'test', detail: 'test', prevHash: '', hash: '' }],
      };
      const report = reporter.generateReport('soc2', data);
      assert.strictEqual(report.standard, 'soc2');
      assert.ok(report.overallScore >= 80);
      assert.ok(report.controls.length > 0);
    });

    it('reports failures when nothing is configured', () => {
      const report = reporter.generateReport('soc2', {});
      assert.ok(report.overallScore < 50);
      const failCount = report.controls.filter(c => c.status === 'fail').length;
      assert.ok(failCount > 0);
    });

    it('CC6.1 passes with access controls + rate limits', () => {
      const report = reporter.generateReport('soc2', {
        toolAccessControls: true,
        rateLimitsConfigured: true,
      });
      const cc61 = report.controls.find(c => c.id === 'CC6.1');
      assert.ok(cc61);
      assert.strictEqual(cc61!.status, 'pass');
    });

    it('CC7.1 partial with only audit logging', () => {
      const report = reporter.generateReport('soc2', {
        auditLoggingEnabled: true,
        anomalyDetectionEnabled: false,
      });
      const cc71 = report.controls.find(c => c.id === 'CC7.1');
      assert.ok(cc71);
      assert.strictEqual(cc71!.status, 'partial');
    });

    it('CC7.2 warns on critical findings', () => {
      const report = reporter.generateReport('soc2', {
        findings: [
          { id: '1', timestamp: Date.now(), ruleId: 'test', ruleName: 'test', severity: 'critical', category: 'test', description: 'test', action: 'alert' },
        ],
      });
      const cc72 = report.controls.find(c => c.id === 'CC7.2');
      assert.ok(cc72);
      assert.ok(cc72!.recommendations.length > 0);
    });
  });

  // === ISO 27001 ===
  describe('ISO 27001', () => {
    it('generates report', () => {
      const report = reporter.generateReport('iso27001', {
        dataClassification: true,
        piiSanitizationEnabled: true,
        auditLoggingEnabled: true,
        retentionDays: 90,
        encryptionEnabled: true,
        toolAccessControls: true,
      });
      assert.strictEqual(report.standard, 'iso27001');
      assert.ok(report.overallScore >= 80);
    });

    it('A.12.4 partial without sufficient retention', () => {
      const report = reporter.generateReport('iso27001', {
        auditLoggingEnabled: true,
        retentionDays: 30,
      });
      const a124 = report.controls.find(c => c.id === 'A.12.4');
      assert.ok(a124);
      assert.strictEqual(a124!.status, 'partial');
    });
  });

  // === GDPR ===
  describe('GDPR', () => {
    it('generates report', () => {
      const report = reporter.generateReport('gdpr', {
        piiSanitizationEnabled: true,
        dataClassification: true,
        auditLoggingEnabled: true,
        encryptionEnabled: true,
        anomalyDetectionEnabled: true,
        toolAccessControls: true,
        incidentResponsePlan: true,
      });
      assert.strictEqual(report.standard, 'gdpr');
      assert.ok(report.overallScore >= 80);
    });

    it('Art.5 fails without PII sanitization', () => {
      const report = reporter.generateReport('gdpr', {});
      const art5 = report.controls.find(c => c.id === 'Art.5');
      assert.ok(art5);
      assert.strictEqual(art5!.status, 'fail');
    });
  });

  // === Format ===
  describe('formatReport', () => {
    it('produces readable text output', () => {
      const report = reporter.generateReport('soc2', { auditLoggingEnabled: true });
      const text = reporter.formatReport(report);
      assert.ok(text.includes('SOC2'));
      assert.ok(text.includes('CC6.1'));
      assert.ok(text.includes('Overall Score'));
    });
  });

  // === Meta ===
  describe('getSupportedStandards', () => {
    it('returns all supported standards', () => {
      const standards = reporter.getSupportedStandards();
      assert.ok(standards.includes('soc2'));
      assert.ok(standards.includes('iso27001'));
      assert.ok(standards.includes('gdpr'));
      assert.ok(standards.includes('nist'));
    });
  });

  describe('NIST', () => {
    it('generates report (uses ISO proxy)', () => {
      const report = reporter.generateReport('nist', { auditLoggingEnabled: true });
      assert.strictEqual(report.standard, 'nist');
      assert.ok(report.controls.length > 0);
    });
  });
});
