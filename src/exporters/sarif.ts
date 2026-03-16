// ClawGuard - SARIF 2.1.0 Exporter
// For GitHub Code Scanning / Security tab integration

import { SecurityFinding } from '../types';
import { builtinRules } from '../rules';

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: 'error' | 'warning' | 'note' };
  properties: { tags: string[] };
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number; startColumn?: number };
    };
  }[];
  fixes?: { description: { text: string } }[];
  properties?: Record<string, unknown>;
}

interface SarifOutput {
  $schema: string;
  version: '2.1.0';
  runs: [{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }];
}

function severityToLevel(severity: string): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high': return 'error';
    case 'warning': return 'warning';
    default: return 'note';
  }
}

function getCvssRange(severity: string): string {
  switch (severity) {
    case 'critical': return '9.0-10.0';
    case 'high': return '7.0-8.9';
    case 'warning': return '4.0-6.9';
    default: return '0.1-3.9';
  }
}

function getRemediationForSarif(ruleId: string, description: string): string {
  if (description.includes('SSRF')) return 'Block private IP ranges; validate URLs; use allowlists for outbound requests';
  if (description.includes('API key') || description.includes('token')) return 'Rotate the exposed key immediately; use env vars or secret managers';
  const defaults: Record<string, string> = {
    'prompt-injection': 'Sanitize user inputs; use input validation; implement prompt firewalls',
    'mcp-security': 'Enable sandboxing; restrict tool permissions; validate MCP server origins',
    'supply-chain': 'Pin dependencies; audit npm scripts; avoid eval(); verify package names',
    'memory-poisoning': 'Validate memory file contents; strip HTML comments; reject encoded payloads',
    'api-key-exposure': 'Move secrets to environment variables or a vault; add to .gitignore',
    'permission-escalation': 'Use least-privilege principle; avoid sudo in scripts; restrict agent file access',
    'data-leakage': 'Remove or redact PII/credentials; use environment variables for secrets',
  };
  return defaults[ruleId] || 'Review and remediate the finding based on security best practices';
}

export interface ScanFinding extends SecurityFinding {
  file?: string;
  line?: number;
}

export function toSarif(findings: ScanFinding[], version: string = '2.0.0'): SarifOutput {
  const rules: SarifRule[] = builtinRules.map(rule => ({
    id: rule.id,
    name: rule.name,
    shortDescription: { text: rule.description.slice(0, 200) },
    fullDescription: { text: rule.description },
    defaultConfiguration: { level: 'warning' as const },
    properties: { tags: ['security', rule.owaspCategory] },
  }));

  const results: SarifResult[] = findings.map(f => ({
    ruleId: f.ruleId,
    level: severityToLevel(f.severity),
    message: { text: `${f.description}${f.evidence ? ` - Evidence: ${f.evidence}` : ''}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.file || 'unknown' },
        ...(f.line ? { region: { startLine: f.line } } : {}),
      },
    }],
    fixes: [{
      description: { text: getRemediationForSarif(f.ruleId, f.description) },
    }],
    properties: {
      severity: f.severity,
      category: f.category,
      owaspCategory: f.owaspCategory,
      cvssRange: getCvssRange(f.severity),
    },
  }));

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'ClawGuard',
          version,
          informationUri: 'https://github.com/NeuZhou/ClawGuard',
          rules,
        },
      },
      results,
    }],
  };
}


