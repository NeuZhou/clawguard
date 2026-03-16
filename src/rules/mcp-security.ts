// ClawGuard — Security Rule: MCP Security
// OWASP Agentic AI: Tool Manipulation / SSRF / Schema Poisoning

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

const BUILTIN_TOOL_NAMES = ['exec', 'read', 'write', 'edit', 'browser', 'message', 'process', 'tts', 'web_search', 'web_fetch', 'image'];

// Tool shadowing: MCP tool names that shadow built-in tools
const TOOL_SHADOW_PATTERNS: Pattern[] = BUILTIN_TOOL_NAMES.map(name => ({
  regex: new RegExp(`"name"\\s*:\\s*"${name}"`, 'i'),
  severity: 'critical',
  description: `MCP tool shadows built-in tool: ${name}`,
}));

// SSRF via tool arguments
const SSRF_PATTERNS: Pattern[] = [
  { regex: /(?:url|uri|endpoint|host|target)\s*["']?\s*[:=]\s*["']?https?:\/\/(?:127\.0\.0\.1|localhost|0\.0\.0\.0)/i, severity: 'critical', description: 'SSRF: URL pointing to localhost' },
  { regex: /(?:url|uri|endpoint|host|target)\s*["']?\s*[:=]\s*["']?https?:\/\/(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})/i, severity: 'critical', description: 'SSRF: URL pointing to 10.x private network' },
  { regex: /(?:url|uri|endpoint|host|target)\s*["']?\s*[:=]\s*["']?https?:\/\/(?:192\.168\.\d{1,3}\.\d{1,3})/i, severity: 'critical', description: 'SSRF: URL pointing to 192.168.x private network' },
  { regex: /(?:url|uri|endpoint|host|target)\s*["']?\s*[:=]\s*["']?https?:\/\/(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})/i, severity: 'critical', description: 'SSRF: URL pointing to 172.16-31.x private network' },
  { regex: /169\.254\.169\.254/i, severity: 'critical', description: 'SSRF: AWS/cloud metadata endpoint access' },
  { regex: /metadata\.google\.internal/i, severity: 'critical', description: 'SSRF: GCP metadata endpoint access' },
  { regex: /(?:url|uri)\s*["']?\s*[:=]\s*["']?file:\/\//i, severity: 'critical', description: 'SSRF: file:// protocol access attempt' },
  { regex: /(?:url|uri)\s*["']?\s*[:=]\s*["']?gopher:\/\//i, severity: 'critical', description: 'SSRF: gopher:// protocol access attempt' },
];

// Schema poisoning: tool descriptions containing injection payloads
const SCHEMA_POISONING_PATTERNS: Pattern[] = [
  { regex: /"description"\s*:\s*"[^"]*(?:ignore|override|disregard)\s+(?:previous|all|prior)\s+(?:instructions|rules)[^"]*"/i, severity: 'high', description: 'MCP schema poisoning: injection in tool description' },
  { regex: /"description"\s*:\s*"[^"]*(?:system\s*prompt|you\s+are\s+now|new\s+instructions)[^"]*"/i, severity: 'high', description: 'MCP schema poisoning: role manipulation in description' },
  { regex: /"description"\s*:\s*"[^"]*<\|(?:system|im_start)\|>[^"]*"/i, severity: 'critical', description: 'MCP schema poisoning: delimiter injection in description' },
];

// Excessive permissions
const EXCESSIVE_PERM_PATTERNS: Pattern[] = [
  { regex: /["']?(?:path|file|directory)["']?\s*[:=]\s*["']?\*["']?/i, severity: 'high', description: 'MCP tool requesting wildcard file access' },
  { regex: /["']?(?:path|file|directory)["']?\s*[:=]\s*["']?\/["']?/i, severity: 'high', description: 'MCP tool requesting root filesystem access' },
  { regex: /["']?(?:command|cmd|exec)["']?\s*[:=]\s*["']?(?:sudo|chmod\s+777|rm\s+-rf)/i, severity: 'critical', description: 'MCP tool with dangerous command execution' },
  { regex: /["']?(?:network|host)["']?\s*[:=]\s*["']?\*["']?/i, severity: 'high', description: 'MCP tool requesting wildcard network access' },
];

// Unsandboxed access patterns
const UNSANDBOXED_ACCESS_PATTERNS: Pattern[] = [
  { regex: /["']?(?:filesystem|file[_-]?system|fs)[_-]?(?:access|read|write)["']?\s*[=:]\s*["']?(?:true|full|unrestricted)/i, severity: 'high', description: 'MCP tool with unsandboxed filesystem access' },
  { regex: /["']?(?:exec|execute|shell|command|subprocess)["']?\s*[=:]\s*["']?(?:true|enabled|allowed)/i, severity: 'critical', description: 'MCP tool with unsandboxed exec/shell access' },
  { regex: /["']?(?:network|http|fetch|request)["']?\s*[=:]\s*["']?(?:true|unrestricted|any|\*)/i, severity: 'high', description: 'MCP tool with unsandboxed network access' },
  { regex: /(?:sandbox|isolation)\s*[=:]\s*(?:false|off|disabled|none|0)/i, severity: 'critical', description: 'MCP tool with sandbox explicitly disabled' },
  { regex: /allowedDirectories\s*[=:]\s*\[\s*["']?\/["']?\s*\]/i, severity: 'critical', description: 'MCP tool with root directory access allowed' },
];

// Shadow server registration
const SHADOW_SERVER_PATTERNS: Pattern[] = [
  { regex: /mcp[_-]?server\s*[:=]\s*["']?https?:\/\//i, severity: 'high', description: 'Unauthorized MCP server registration attempt' },
  { regex: /(?:register|add|connect)\s+(?:new\s+)?(?:mcp|tool)\s+server/i, severity: 'high', description: 'MCP shadow server registration' },
  { regex: /(?:stdio|sse|streamable-http)\s*[:=].*(?:npx|node|python|uvx)\s+/i, severity: 'warning', description: 'Dynamic MCP server process spawning' },
];

const ALL_PATTERNS = [
  ...TOOL_SHADOW_PATTERNS,
  ...SSRF_PATTERNS,
  ...SCHEMA_POISONING_PATTERNS,
  ...EXCESSIVE_PERM_PATTERNS,
  ...UNSANDBOXED_ACCESS_PATTERNS,
  ...SHADOW_SERVER_PATTERNS,
];

export const mcpSecurityRule: SecurityRule = {
  id: 'mcp-security',
  name: 'MCP Security',
  description: 'Detects MCP-specific threats: tool shadowing, SSRF, schema poisoning, excessive permissions, and shadow server registration',
  owaspCategory: 'Agentic AI: Tool Manipulation',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'mcp-security',
          ruleName: 'MCP Security',
          severity: pattern.severity,
          category: 'mcp-security',
          owaspCategory: 'Agentic AI: Tool Manipulation',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    return findings;
  },
};


