// ClawGuard — MCP Manifest Analyzer
// Analyzes MCP server manifests/configs for risk scoring

import { SecurityFinding, Severity } from '../types';
import * as crypto from 'crypto';

export interface MCPManifest {
  name?: string;
  version?: string;
  description?: string;
  transport?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  tools?: MCPToolDef[];
  resources?: MCPResourceDef[];
  prompts?: MCPPromptDef[];
  permissions?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface MCPToolDef {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface MCPResourceDef {
  uri: string;
  name?: string;
  description?: string;
  mimeType?: string;
}

export interface MCPPromptDef {
  name: string;
  description?: string;
  arguments?: Array<{ name: string; description?: string; required?: boolean }>;
}

export type MCPGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface MCPScorecard {
  grade: MCPGrade;
  score: number;          // 0-100 (100 = safest)
  serverName: string;
  toolCount: number;
  resourceCount: number;
  promptCount: number;
  findings: SecurityFinding[];
  breakdown: {
    toolPoisoning: number;
    permissions: number;
    exfiltration: number;
    schemaQuality: number;
    supplyChain: number;
  };
  scannedAt: number;
}

// ── High-risk tool names that deserve extra scrutiny ──
const DANGEROUS_TOOL_NAMES = [
  'exec', 'execute', 'run', 'shell', 'command', 'bash', 'eval',
  'write_file', 'delete_file', 'remove', 'unlink',
  'send_email', 'send_message', 'post', 'upload',
  'fetch', 'request', 'http', 'curl', 'wget',
];

const BUILTIN_TOOL_NAMES = ['exec', 'read', 'write', 'edit', 'browser', 'message', 'process', 'tts', 'web_search', 'web_fetch', 'image'];

function makeFinding(opts: { ruleId: string; ruleName: string; severity: Severity; description: string; evidence?: string }): SecurityFinding {
  return {
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    ruleId: opts.ruleId,
    ruleName: opts.ruleName,
    severity: opts.severity,
    category: 'mcp-security',
    owaspCategory: 'Agentic AI: Tool Manipulation',
    description: opts.description,
    evidence: opts.evidence,
    session: 'mcp-scan',
    channel: 'cli',
    action: opts.severity === 'critical' ? 'alert' : 'log',
  };
}

export function analyzeManifest(manifest: MCPManifest): MCPScorecard {
  const findings: SecurityFinding[] = [];
  const tools = manifest.tools ?? [];
  const resources = manifest.resources ?? [];
  const prompts = manifest.prompts ?? [];

  // ── Tool analysis ──
  for (const tool of tools) {
    // Shadow built-in tools
    if (BUILTIN_TOOL_NAMES.includes(tool.name.toLowerCase())) {
      findings.push(makeFinding({
        ruleId: 'mcp-manifest-tool-shadow',
        ruleName: 'Tool Shadows Built-in',
        severity: 'critical',
        description: `Tool "${tool.name}" shadows a built-in tool`,
        evidence: tool.name,
      }));
    }

    // Dangerous tool names
    if (DANGEROUS_TOOL_NAMES.some(d => tool.name.toLowerCase().includes(d))) {
      findings.push(makeFinding({
        ruleId: 'mcp-manifest-dangerous-tool',
        ruleName: 'Dangerous Tool Name',
        severity: 'high',
        description: `Tool "${tool.name}" has a potentially dangerous capability`,
        evidence: tool.name,
      }));
    }

    // Tool description checks
    const desc = tool.description ?? '';
    if (desc.length > 500) {
      findings.push(makeFinding({
        ruleId: 'mcp-manifest-long-description',
        ruleName: 'Suspiciously Long Tool Description',
        severity: 'warning',
        description: `Tool "${tool.name}" has an unusually long description (${desc.length} chars) — may hide injections`,
        evidence: desc.slice(0, 200),
      }));
    }

    // Check for injection in description
    if (/(?:ignore|override|disregard)\s+(?:previous|all|prior)\s+(?:instructions|rules)/i.test(desc)) {
      findings.push(makeFinding({
        ruleId: 'mcp-manifest-desc-injection',
        ruleName: 'Prompt Injection in Tool Description',
        severity: 'critical',
        description: `Tool "${tool.name}" description contains prompt injection`,
        evidence: desc.slice(0, 200),
      }));
    }

    // Unicode tricks
    if (/[\u200B\u200C\u200D\u2060\uFEFF]{2,}|\u202E/.test(desc)) {
      findings.push(makeFinding({
        ruleId: 'mcp-manifest-unicode-trick',
        ruleName: 'Hidden Unicode in Tool Description',
        severity: 'high',
        description: `Tool "${tool.name}" description contains hidden Unicode characters`,
        evidence: `${desc.length} chars, contains zero-width or bidi chars`,
      }));
    }

    // Schema quality
    const schema = tool.inputSchema;
    if (!schema || Object.keys(schema).length === 0) {
      findings.push(makeFinding({
        ruleId: 'mcp-manifest-no-schema',
        ruleName: 'Missing Input Schema',
        severity: 'high',
        description: `Tool "${tool.name}" has no input schema — accepts arbitrary input`,
        evidence: tool.name,
      }));
    } else if (schema && typeof schema === 'object') {
      const s = schema as Record<string, unknown>;
      if (s.additionalProperties === true) {
        findings.push(makeFinding({
          ruleId: 'mcp-manifest-loose-schema',
          ruleName: 'Loose Input Schema',
          severity: 'warning',
          description: `Tool "${tool.name}" schema allows additional properties`,
          evidence: tool.name,
        }));
      }
      if (!s.required || (Array.isArray(s.required) && s.required.length === 0)) {
        findings.push(makeFinding({
          ruleId: 'mcp-manifest-no-required',
          ruleName: 'No Required Fields in Schema',
          severity: 'warning',
          description: `Tool "${tool.name}" schema has no required fields`,
          evidence: tool.name,
        }));
      }
    }
  }

  // ── Too many tools ──
  if (tools.length > 20) {
    findings.push(makeFinding({
      ruleId: 'mcp-manifest-too-many-tools',
      ruleName: 'Excessive Tool Count',
      severity: 'warning',
      description: `Server declares ${tools.length} tools — increases attack surface`,
      evidence: `${tools.length} tools`,
    }));
  }

  // ── Command analysis ──
  if (manifest.command) {
    const cmd = `${manifest.command} ${(manifest.args ?? []).join(' ')}`;
    if (/sudo|chmod\s+777|rm\s+-rf|curl.*\|\s*(?:bash|sh)|wget.*\|\s*(?:bash|sh)/.test(cmd)) {
      findings.push(makeFinding({
        ruleId: 'mcp-manifest-dangerous-cmd',
        ruleName: 'Dangerous Launch Command',
        severity: 'critical',
        description: 'MCP server launch command contains dangerous operations',
        evidence: cmd.slice(0, 200),
      }));
    }
  }

  // ── Env secrets ──
  if (manifest.env) {
    for (const [key, val] of Object.entries(manifest.env)) {
      if (/^(password|secret|token|api[_-]?key|private[_-]?key)/i.test(key)) {
        if (typeof val === 'string' && val.length > 0 && !val.startsWith('$') && !val.startsWith('${') && !val.startsWith('%')) {
          findings.push(makeFinding({
            ruleId: 'mcp-manifest-hardcoded-secret',
            ruleName: 'Hardcoded Secret in Config',
            severity: 'high',
            description: `Hardcoded secret in env.${key}`,
            evidence: `${key}=${String(val).slice(0, 4)}***`,
          }));
        }
      }
    }
  }

  // ── Scoring ──
  const breakdown = {
    toolPoisoning: 0,
    permissions: 0,
    exfiltration: 0,
    schemaQuality: 0,
    supplyChain: 0,
  };

  for (const f of findings) {
    const penalty = f.severity === 'critical' ? 20 : f.severity === 'high' ? 10 : f.severity === 'warning' ? 5 : 2;
    if (f.ruleId.includes('poison') || f.ruleId.includes('injection') || f.ruleId.includes('unicode') || f.ruleId.includes('desc-injection')) {
      breakdown.toolPoisoning += penalty;
    } else if (f.ruleId.includes('perm') || f.ruleId.includes('shadow') || f.ruleId.includes('dangerous')) {
      breakdown.permissions += penalty;
    } else if (f.ruleId.includes('exfil') || f.ruleId.includes('secret') || f.ruleId.includes('hardcoded')) {
      breakdown.exfiltration += penalty;
    } else if (f.ruleId.includes('schema') || f.ruleId.includes('required') || f.ruleId.includes('loose') || f.ruleId.includes('no-schema')) {
      breakdown.schemaQuality += penalty;
    } else {
      breakdown.supplyChain += penalty;
    }
  }

  const totalPenalty = Object.values(breakdown).reduce((a, b) => a + b, 0);
  const score = Math.max(0, 100 - totalPenalty);
  const grade: MCPGrade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';

  return {
    grade,
    score,
    serverName: manifest.name ?? 'unknown',
    toolCount: tools.length,
    resourceCount: resources.length,
    promptCount: prompts.length,
    findings,
    breakdown,
    scannedAt: Date.now(),
  };
}

export function generateBadgeSVG(scorecard: MCPScorecard): string {
  const colors: Record<MCPGrade, string> = {
    A: '#4c1',
    B: '#97ca00',
    C: '#dfb317',
    D: '#fe7d37',
    F: '#e05d44',
  };
  const color = colors[scorecard.grade];
  const label = 'ClawGuard MCP';
  const value = `${scorecard.grade} (${scorecard.score}/100)`;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="210" height="20" role="img" aria-label="${label}: ${value}">
  <title>${label}: ${value}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="210" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="120" height="20" fill="#555"/>
    <rect x="120" width="90" height="20" fill="${color}"/>
    <rect width="210" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <text x="60" y="14">${label}</text>
    <text x="165" y="14">${value}</text>
  </g>
</svg>`;
}
