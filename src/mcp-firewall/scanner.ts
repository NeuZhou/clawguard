// ClawGuard — MCP Firewall: Threat Detection Scanner
// Leverages clawguard's existing security rule system for MCP-specific scanning

import * as crypto from 'crypto';
import { SecurityFinding, Severity, RuleContext } from '../types';
import { promptInjectionRule } from '../rules/prompt-injection';
import { mcpSecurityRule } from '../rules/mcp-security';
import { dataLeakageRule } from '../rules/data-leakage';
import {
  McpToolDefinition,
  McpToolCallParams,
  McpToolResult,
  McpContentItem,
  ToolDescriptionPin,
  ScanResult,
} from './types';

// ── Tool Description Injection Detection ──

/** Injection patterns specific to MCP tool descriptions */
const TOOL_DESC_INJECTION_PATTERNS: { regex: RegExp; severity: Severity; description: string }[] = [
  { regex: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules)/i, severity: 'critical', description: 'Tool description contains instruction override' },
  { regex: /you\s+are\s+now/i, severity: 'critical', description: 'Tool description contains role reassignment' },
  { regex: /system\s*prompt/i, severity: 'critical', description: 'Tool description references system prompt' },
  { regex: /\[INST\]|\[\/INST\]|<\|system\|>|<\|im_start\|>/i, severity: 'critical', description: 'Tool description contains chat template delimiters' },
  { regex: /instead\s+of\s+(calling|using|executing)\s+this\s+tool/i, severity: 'high', description: 'Tool description redirects execution' },
  { regex: /before\s+(calling|using|executing)\s+(?:any\s+)?(?:other\s+)?tools?/i, severity: 'high', description: 'Tool description hijacks tool ordering' },
  { regex: /always\s+call\s+this\s+tool\s+(first|before)/i, severity: 'high', description: 'Tool description demands priority execution' },
  { regex: /do\s+not\s+(?:show|tell|reveal|display)\s+(?:the\s+)?(?:user|human)/i, severity: 'high', description: 'Tool description hides information from user' },
  { regex: /(?:send|post|fetch|request)\s+(?:to|from)\s+https?:\/\//i, severity: 'high', description: 'Tool description contains URL for data exfiltration' },
  { regex: /pass\s+(?:all|the|any)\s+(?:conversation|context|messages?|data)/i, severity: 'high', description: 'Tool description requests conversation data' },
  { regex: /(?:include|embed|attach)\s+(?:the\s+)?(?:system\s+prompt|conversation|chat\s+history)/i, severity: 'high', description: 'Tool description requests embedding context' },
  { regex: /(?:when|if)\s+(?:the\s+)?user\s+(?:asks?|says?|mentions?)\s+/i, severity: 'warning', description: 'Tool description contains conditional user-targeting logic' },
];

// ── Parameter Sanitization Patterns ──

/** Patterns that indicate suspicious parameters in tool calls */
const PARAM_PATTERNS: { regex: RegExp; severity: Severity; description: string }[] = [
  // Base64-encoded payloads (possible exfiltration)
  { regex: /^[A-Za-z0-9+/]{100,}={0,2}$/, severity: 'high', description: 'Large base64-encoded parameter value detected' },
  // Data URIs embedding scripts
  { regex: /^data:(?:text\/html|application\/javascript|text\/javascript)/i, severity: 'critical', description: 'Data URI with executable content in parameter' },
  // Shell injection in parameters
  { regex: /;\s*(?:curl|wget|nc|bash|sh|python|node|php)\s/i, severity: 'critical', description: 'Shell command injection in parameter' },
  { regex: /\$\(.*\)|\`.*\`/, severity: 'high', description: 'Command substitution in parameter' },
  // Path traversal
  { regex: /(?:\.\.\/){3,}/, severity: 'high', description: 'Deep path traversal in parameter' },
  { regex: /(?:\/etc\/(?:passwd|shadow|hosts)|\/proc\/|\/dev\/)/i, severity: 'critical', description: 'Sensitive system path in parameter' },
  // URL-based exfiltration
  { regex: /https?:\/\/[^\s]*\?(?:.*&)?(?:d|data|q|exfil|leak|token|key|secret)=/i, severity: 'high', description: 'Possible data exfiltration URL in parameter' },
  // Encoded payloads
  { regex: /(?:%[0-9a-f]{2}){10,}/i, severity: 'warning', description: 'Heavily URL-encoded parameter value' },
  // SQL injection
  { regex: /(?:;\s*DROP\s|UNION\s+SELECT|'\s+OR\s+'|--\s+)/i, severity: 'high', description: 'SQL injection pattern in parameter' },
];

// ── Rug Pull (Tool Description Change) Detection ──

/** In-memory store for tool description pins */
const descriptionPins = new Map<string, ToolDescriptionPin>();

function pinKey(server: string, toolName: string): string {
  return `${server}::${toolName}`;
}

function hashDescription(description: string): string {
  return crypto.createHash('sha256').update(description).digest('hex');
}

/**
 * Pin a tool description hash. Returns null if first time,
 * or a finding if the description changed (rug pull).
 */
export function pinToolDescription(
  server: string,
  tool: McpToolDefinition,
): SecurityFinding | null {
  const key = pinKey(server, tool.name);
  const desc = tool.description || '';
  const hash = hashDescription(desc);
  const now = Date.now();

  const existing = descriptionPins.get(key);
  if (!existing) {
    descriptionPins.set(key, {
      server,
      toolName: tool.name,
      descriptionHash: hash,
      firstSeen: now,
      lastSeen: now,
    });
    return null;
  }

  // Update lastSeen
  existing.lastSeen = now;

  if (existing.descriptionHash !== hash) {
    const oldHash = existing.descriptionHash;
    // Update the pin with new hash
    existing.descriptionHash = hash;

    return {
      id: crypto.randomUUID(),
      timestamp: now,
      ruleId: 'mcp-firewall-rug-pull',
      ruleName: 'MCP Firewall: Rug Pull Detection',
      severity: 'critical',
      category: 'rug-pull',
      owaspCategory: 'Agentic AI: Rug Pull',
      description: `Tool description changed for ${server}/${tool.name} — possible rug pull attack`,
      evidence: `Old hash: ${oldHash.slice(0, 16)}... New hash: ${hash.slice(0, 16)}...`,
      action: 'alert',
    };
  }

  return null;
}

/** Get all current pins (for inspection/debugging) */
export function getDescriptionPins(): ToolDescriptionPin[] {
  return Array.from(descriptionPins.values());
}

/** Clear all pins (for testing) */
export function clearDescriptionPins(): void {
  descriptionPins.clear();
}

// ── Scan Functions ──

function makeContext(): RuleContext {
  return {
    session: 'mcp-firewall',
    channel: 'mcp',
    timestamp: Date.now(),
    recentMessages: [],
    recentFindings: [],
  };
}

/**
 * Scan a tool description for injection attacks.
 * Uses both MCP Firewall-specific patterns and clawguard's existing prompt injection rules.
 */
export function scanToolDescription(
  server: string,
  tool: McpToolDefinition,
): ScanResult {
  const findings: SecurityFinding[] = [];
  const desc = tool.description || '';
  if (!desc) return { findings, blocked: false };

  // 1. Check MCP Firewall-specific injection patterns
  for (const pattern of TOOL_DESC_INJECTION_PATTERNS) {
    const match = pattern.regex.exec(desc);
    if (match) {
      findings.push({
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        ruleId: 'mcp-firewall-desc-injection',
        ruleName: 'MCP Firewall: Tool Description Injection',
        severity: pattern.severity,
        category: 'prompt-injection',
        owaspCategory: 'LLM01',
        description: `${pattern.description} in tool "${tool.name}" from server "${server}"`,
        evidence: match[0].slice(0, 200),
        action: pattern.severity === 'critical' ? 'block' : 'alert',
      });
    }
  }

  // 2. Leverage clawguard's existing prompt injection rule
  const ctx = makeContext();
  const piFindings = promptInjectionRule.check(desc, 'inbound', ctx);
  for (const f of piFindings) {
    findings.push({
      ...f,
      id: crypto.randomUUID(),
      ruleId: 'mcp-firewall-desc-injection',
      ruleName: 'MCP Firewall: Tool Description Injection',
      description: `[via prompt-injection] ${f.description} in tool "${tool.name}" from server "${server}"`,
    });
  }

  // 3. Leverage clawguard's MCP security rule
  const descJson = JSON.stringify({ name: tool.name, description: desc });
  const mcpFindings = mcpSecurityRule.check(descJson, 'inbound', ctx);
  for (const f of mcpFindings) {
    findings.push({
      ...f,
      id: crypto.randomUUID(),
      ruleId: 'mcp-firewall-schema-poison',
      ruleName: 'MCP Firewall: Schema Poisoning',
    });
  }

  const blocked = findings.some(f => f.severity === 'critical');
  return { findings, blocked, reason: blocked ? 'Critical injection detected in tool description' : undefined };
}

/**
 * Scan tool call parameters for malicious payloads.
 */
export function scanToolCallParams(
  server: string,
  call: McpToolCallParams,
): ScanResult {
  const findings: SecurityFinding[] = [];
  const args = call.arguments || {};

  // Scan each parameter value
  for (const [key, value] of Object.entries(args)) {
    const strValue = typeof value === 'string' ? value : JSON.stringify(value);

    // Check parameter-specific patterns
    for (const pattern of PARAM_PATTERNS) {
      const match = pattern.regex.exec(strValue);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: Date.now(),
          ruleId: 'mcp-firewall-param-sanitize',
          ruleName: 'MCP Firewall: Parameter Sanitization',
          severity: pattern.severity,
          category: 'parameter-injection',
          owaspCategory: 'Agentic AI: Tool Manipulation',
          description: `${pattern.description} (param: "${key}", tool: "${call.name}", server: "${server}")`,
          evidence: match[0].slice(0, 200),
          action: pattern.severity === 'critical' ? 'block' : 'alert',
        });
      }
    }

    // Check for prompt injection in parameter values
    if (typeof value === 'string' && value.length > 20) {
      const ctx = makeContext();
      const piFindings = promptInjectionRule.check(value, 'inbound', ctx);
      for (const f of piFindings) {
        if (f.severity === 'critical' || f.severity === 'high') {
          findings.push({
            ...f,
            id: crypto.randomUUID(),
            ruleId: 'mcp-firewall-param-injection',
            ruleName: 'MCP Firewall: Parameter Injection',
            description: `[via prompt-injection] ${f.description} (param: "${key}", tool: "${call.name}")`,
          });
        }
      }
    }
  }

  const blocked = findings.some(f => f.severity === 'critical');
  return { findings, blocked, reason: blocked ? 'Critical threat in tool parameters' : undefined };
}

/**
 * Scan tool call output/result for prompt injection before forwarding to client.
 */
export function scanToolOutput(
  server: string,
  toolName: string,
  result: McpToolResult,
): ScanResult {
  const findings: SecurityFinding[] = [];

  for (const item of result.content) {
    const text = extractText(item);
    if (!text || text.length < 10) continue;

    // Check for prompt injection in tool output
    const ctx = makeContext();
    const piFindings = promptInjectionRule.check(text, 'inbound', ctx);
    for (const f of piFindings) {
      findings.push({
        ...f,
        id: crypto.randomUUID(),
        ruleId: 'mcp-firewall-output-injection',
        ruleName: 'MCP Firewall: Output Injection',
        description: `[output] ${f.description} in output of "${toolName}" from server "${server}"`,
        action: f.severity === 'critical' ? 'block' : 'alert',
      });
    }

    // Check for data leakage in tool output
    const dlFindings = dataLeakageRule.check(text, 'outbound', ctx);
    for (const f of dlFindings) {
      findings.push({
        ...f,
        id: crypto.randomUUID(),
        ruleId: 'mcp-firewall-output-leakage',
        ruleName: 'MCP Firewall: Output Data Leakage',
        description: `[output] ${f.description} in output of "${toolName}" from server "${server}"`,
      });
    }

    // Check for base64-encoded hidden payloads in output
    const b64Regex = /[A-Za-z0-9+/]{60,}={0,2}/g;
    let b64Match;
    while ((b64Match = b64Regex.exec(text)) !== null) {
      try {
        const decoded = Buffer.from(b64Match[0], 'base64').toString('utf-8');
        if (/ignore|override|system|instruction|jailbreak|<\|system\|>/i.test(decoded)) {
          findings.push({
            id: crypto.randomUUID(),
            timestamp: Date.now(),
            ruleId: 'mcp-firewall-output-injection',
            ruleName: 'MCP Firewall: Output Injection',
            severity: 'critical',
            category: 'prompt-injection',
            owaspCategory: 'LLM01',
            description: `Base64-encoded injection payload in output of "${toolName}" from server "${server}"`,
            evidence: decoded.slice(0, 200),
            action: 'block',
          });
        }
      } catch { /* not valid base64 */ }
    }
  }

  const blocked = findings.some(f => f.action === 'block');
  return { findings, blocked, reason: blocked ? 'Injection detected in tool output' : undefined };
}

/** Extract text from an MCP content item */
function extractText(item: McpContentItem): string | null {
  if (item.type === 'text' && item.text) return item.text;
  if (item.type === 'resource' && item.text) return item.text;
  // For base64-encoded data, decode and return if it looks like text
  if (item.data && item.mimeType?.startsWith('text/')) {
    try {
      return Buffer.from(item.data, 'base64').toString('utf-8');
    } catch { return null; }
  }
  return null;
}

/**
 * Scan an entire tools/list response for injection and rug pulls.
 */
export function scanToolsList(
  server: string,
  tools: McpToolDefinition[],
  rugPullDetection: boolean = true,
): ScanResult {
  const allFindings: SecurityFinding[] = [];
  let blocked = false;

  for (const tool of tools) {
    // Description injection scan
    const descResult = scanToolDescription(server, tool);
    allFindings.push(...descResult.findings);
    if (descResult.blocked) blocked = true;

    // Rug pull detection
    if (rugPullDetection) {
      const rpFinding = pinToolDescription(server, tool);
      if (rpFinding) {
        allFindings.push(rpFinding);
        blocked = true;
      }
    }
  }

  return {
    findings: allFindings,
    blocked,
    reason: blocked ? 'Threat(s) detected in tools list' : undefined,
  };
}
