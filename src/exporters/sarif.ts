// ClawGuard — SARIF 2.1.0 Exporter
// For GitHub Code Scanning / Security tab integration

import { SecurityFinding } from '../types';
import { builtinRules } from '../rules';
import * as fs from 'fs';
import * as path from 'path';

// Walk up from this file to find package.json (works from both src/ and dist/)
function findPackageJson(): string {
  let dir = __dirname;
  for (let i = 0; i < 5; i++) {
    const candidate = path.join(dir, 'package.json');
    if (fs.existsSync(candidate)) return candidate;
    dir = path.dirname(dir);
  }
  return path.join(__dirname, '..', '..', 'package.json'); // fallback
}

const pkg = JSON.parse(fs.readFileSync(findPackageJson(), 'utf-8'));
const PKG_VERSION: string = pkg.version;

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

export interface ScanFinding extends SecurityFinding {
  file?: string;
  line?: number;
}

export function toSarif(findings: ScanFinding[], version: string = PKG_VERSION): SarifOutput {
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
    message: { text: `${f.description}${f.evidence ? ` — Evidence: ${f.evidence}` : ''}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: f.file || 'unknown' },
        ...(f.line ? { region: { startLine: f.line } } : {}),
      },
    }],
    properties: {
      severity: f.severity,
      category: f.category,
      owaspCategory: f.owaspCategory,
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


