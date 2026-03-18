// ClawGuard — MCP Firewall: Policy Engine
// YAML-based policy configuration and enforcement for MCP traffic

import * as fs from 'fs';
import * as crypto from 'crypto';
import {
  FirewallConfig,
  FirewallMode,
  ServerConfig,
  ServerPolicy,
  ToolAction,
  ToolRule,
  TransportConfig,
  DetectionConfig,
  AlertsConfig,
} from './types';

// ── Default Configuration ──

export const DEFAULT_FIREWALL_CONFIG: FirewallConfig = {
  mode: 'monitor',
  transports: [{ type: 'stdio' }],
  defaults: { policy: 'monitor' },
  servers: [],
  detection: {
    injection_scanning: true,
    rug_pull_detection: true,
    parameter_sanitization: true,
    output_validation: true,
  },
  alerts: {
    console: true,
    webhook: null,
  },
};

// ── Simple YAML Parser ──
// Minimal YAML parser for our firewall config schema
// (no external deps, consistent with clawguard's existing approach)

function parseValue(raw: string): string | number | boolean | null {
  const trimmed = raw.trim();
  if (trimmed === 'null' || trimmed === '~' || trimmed === '') return null;
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  if (/^-?\d+$/.test(trimmed)) return parseInt(trimmed, 10);
  if (/^-?\d+\.\d+$/.test(trimmed)) return parseFloat(trimmed);
  // Strip quotes
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

function stripComment(line: string): string {
  // Naive: strip trailing # comment (not inside quotes)
  const idx = line.indexOf(' #');
  if (idx >= 0) return line.slice(0, idx);
  return line;
}

interface ParsedYamlNode {
  [key: string]: unknown;
}

/** Stripped line with original indent preserved */
interface YamlLine {
  indent: number;
  text: string;   // trimmed, comments removed
}

/**
 * Parse a simplified YAML structure into a nested object.
 * Handles: scalars, nested maps, arrays of scalars/objects, inline objects { k: v }.
 */
function parseSimpleYaml(raw: string): ParsedYamlNode {
  const prepared: YamlLine[] = [];
  for (const rawLine of raw.split('\n')) {
    const stripped = stripComment(rawLine);
    const text = stripped.trim();
    if (!text || text.startsWith('#')) continue;
    prepared.push({ indent: rawLine.search(/\S/), text });
  }

  let pos = 0;

  function parseInlineObj(s: string): Record<string, unknown> {
    const inner = s.slice(1, -1).trim();
    const obj: Record<string, unknown> = {};
    for (const part of inner.split(',')) {
      const ci = part.indexOf(':');
      if (ci < 0) continue;
      obj[part.slice(0, ci).trim()] = parseValue(part.slice(ci + 1));
    }
    return obj;
  }

  function parseBlock(minIndent: number): Record<string, unknown> | unknown[] | unknown {
    // Peek: is the first element at minIndent an array item?
    if (pos < prepared.length && prepared[pos].indent >= minIndent && prepared[pos].text.startsWith('- ')) {
      // Array block
      const arr: unknown[] = [];
      while (pos < prepared.length && prepared[pos].indent >= minIndent) {
        const line = prepared[pos];
        if (line.indent < minIndent) break;
        if (line.indent > minIndent) break;  // unexpected deeper — stop
        if (!line.text.startsWith('- ')) break;  // not array item — stop

        pos++;
        const content = line.text.slice(2).trim();

        // Inline object: { k: v }
        if (content.startsWith('{') && content.endsWith('}')) {
          arr.push(parseInlineObj(content));
          continue;
        }

        // Array item with key: value (start of an object)
        if (content.includes(':')) {
          const ci = content.indexOf(':');
          const key = content.slice(0, ci).trim();
          const val = content.slice(ci + 1).trim();
          const obj: Record<string, unknown> = {};
          if (val) {
            obj[key] = parseValue(val);
          } else {
            // sub-block under this key
            obj[key] = parseBlock(line.indent + 2);
          }
          // Continue reading keys at deeper indent that belong to this object
          while (pos < prepared.length && prepared[pos].indent > line.indent && !prepared[pos].text.startsWith('- ')) {
            const sub = prepared[pos];
            pos++;
            const sci = sub.text.indexOf(':');
            if (sci < 0) continue;
            const sk = sub.text.slice(0, sci).trim();
            const sv = sub.text.slice(sci + 1).trim();
            if (sv.startsWith('{') && sv.endsWith('}')) {
              obj[sk] = parseInlineObj(sv);
            } else if (sv) {
              obj[sk] = parseValue(sv);
            } else {
              obj[sk] = parseBlock(sub.indent + 2);
            }
          }
          arr.push(obj);
          continue;
        }

        // Plain scalar array item
        arr.push(parseValue(content));
      }
      return arr;
    }

    // Map block
    const obj: Record<string, unknown> = {};
    while (pos < prepared.length && prepared[pos].indent >= minIndent) {
      const line = prepared[pos];
      if (line.indent < minIndent) break;
      if (line.indent > minIndent) break; // skip unexpected deeper
      if (line.text.startsWith('- ')) break; // array at this level — stop

      pos++;
      const ci = line.text.indexOf(':');
      if (ci < 0) continue;
      const key = line.text.slice(0, ci).trim();
      const val = line.text.slice(ci + 1).trim();

      if (val.startsWith('{') && val.endsWith('}')) {
        obj[key] = parseInlineObj(val);
      } else if (val) {
        obj[key] = parseValue(val);
      } else {
        // Sub-block
        obj[key] = parseBlock(line.indent + 2);
      }
    }
    return obj;
  }

  const result = parseBlock(0);
  return (typeof result === 'object' && result !== null && !Array.isArray(result))
    ? result as ParsedYamlNode
    : { value: result };
}

// ── Config Loading ──

/**
 * Load firewall configuration from a YAML file.
 */
export function loadFirewallConfig(filePath: string): FirewallConfig {
  const raw = fs.readFileSync(filePath, 'utf-8');
  return parseFirewallConfig(raw);
}

/**
 * Parse a firewall config from raw YAML string.
 */
export function parseFirewallConfig(raw: string): FirewallConfig {
  const parsed = parseSimpleYaml(raw);
  const fw = (parsed.firewall || parsed) as Record<string, unknown>;

  const config: FirewallConfig = { ...DEFAULT_FIREWALL_CONFIG };

  // Mode
  if (fw.mode && typeof fw.mode === 'string') {
    config.mode = fw.mode as FirewallMode;
  }

  // Transports
  if (Array.isArray(fw.transports)) {
    config.transports = fw.transports.map((t: Record<string, unknown>) => ({
      type: ((t.type as string) || 'stdio') as 'stdio' | 'sse',
      port: typeof t.port === 'number' ? t.port : undefined,
      host: typeof t.host === 'string' ? t.host : undefined,
    }));
  }

  // Defaults
  if (fw.defaults && typeof fw.defaults === 'object') {
    const defaults = fw.defaults as Record<string, unknown>;
    if (defaults.policy) {
      config.defaults = { policy: defaults.policy as ServerPolicy };
    }
  }

  // Servers
  if (Array.isArray(fw.servers)) {
    config.servers = fw.servers.map((s: Record<string, unknown>) => {
      const server: ServerConfig = {
        name: String(s.name || ''),
        policy: (s.policy as ServerPolicy) || config.defaults.policy,
      };

      if (s.tools && typeof s.tools === 'object') {
        server.tools = {};
        for (const [toolName, rule] of Object.entries(s.tools as Record<string, unknown>)) {
          if (typeof rule === 'object' && rule !== null) {
            const r = rule as Record<string, unknown>;
            server.tools[toolName] = {
              action: (r.action as ToolAction) || 'allow',
              alert: r.alert === true,
            };
          }
        }
      }

      return server;
    });
  }

  // Detection
  if (fw.detection && typeof fw.detection === 'object') {
    const d = fw.detection as Record<string, unknown>;
    config.detection = {
      injection_scanning: d.injection_scanning !== false,
      rug_pull_detection: d.rug_pull_detection !== false,
      parameter_sanitization: d.parameter_sanitization !== false,
      output_validation: d.output_validation !== false,
    };
  }

  // Alerts
  if (fw.alerts && typeof fw.alerts === 'object') {
    const a = fw.alerts as Record<string, unknown>;
    config.alerts = {
      console: a.console !== false,
      webhook: typeof a.webhook === 'string' && a.webhook ? a.webhook : null,
    };
  }

  return config;
}

// ── Policy Decision Engine ──

export interface PolicyDecision {
  action: ToolAction;
  reason: string;
  server?: string;
  tool?: string;
  alert?: boolean;
}

/**
 * Evaluate a tool call against the firewall policy.
 */
export function evaluateToolPolicy(
  config: FirewallConfig,
  serverName: string,
  toolName: string,
): PolicyDecision {
  // Disabled mode = allow all
  if (config.mode === 'disabled') {
    return { action: 'allow', reason: 'Firewall disabled', server: serverName, tool: toolName };
  }

  // Find server config
  const serverConfig = config.servers.find(
    s => s.name.toLowerCase() === serverName.toLowerCase()
  );

  // Check tool-specific rule first
  if (serverConfig?.tools?.[toolName]) {
    const rule = serverConfig.tools[toolName];
    return {
      action: rule.action,
      reason: `Tool rule: ${serverName}/${toolName} → ${rule.action}`,
      server: serverName,
      tool: toolName,
      alert: rule.alert,
    };
  }

  // Fall back to server policy
  const policy = serverConfig?.policy || config.defaults.policy;
  const action = resolveServerPolicy(policy, toolName);

  return {
    action,
    reason: `Server policy "${policy}" for ${serverName}/${toolName}`,
    server: serverName,
    tool: toolName,
  };
}

/**
 * Resolve a server-level policy to a tool action.
 */
function resolveServerPolicy(policy: ServerPolicy, toolName: string): ToolAction {
  switch (policy) {
    case 'allow-all':
      return 'allow';
    case 'block-all':
      return 'block';
    case 'approve-writes': {
      // Heuristic: tools with "write", "create", "delete", "update", "put", "modify" in name need approval
      const writePatterns = /write|create|delete|remove|update|put|set|modify|move|rename|drop|alter|insert|append|push/i;
      return writePatterns.test(toolName) ? 'approve' : 'allow';
    }
    case 'block-destructive': {
      // Block tools with "delete", "drop", "remove", "destroy", "truncate" in name
      const destructivePatterns = /delete|drop|remove|destroy|truncate|purge|wipe|erase|format/i;
      return destructivePatterns.test(toolName) ? 'block' : 'allow';
    }
    case 'monitor':
    default:
      return 'log-only';
  }
}

/**
 * Determine if a firewall mode should block or only log.
 */
export function shouldEnforce(config: FirewallConfig): boolean {
  return config.mode === 'enforce';
}

// ── Data Flow Tracking ──

export interface DataFlowEntry {
  id: string;
  timestamp: number;
  server: string;
  tool: string;
  direction: 'request' | 'response';
  paramKeys?: string[];
  resultTypes?: string[];
  blocked: boolean;
}

const dataFlowLog: DataFlowEntry[] = [];

/**
 * Record a data flow event for tracking.
 */
export function recordDataFlow(entry: Omit<DataFlowEntry, 'id' | 'timestamp'>): DataFlowEntry {
  const full: DataFlowEntry = {
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    ...entry,
  };
  dataFlowLog.push(full);
  // Keep only last 10000 entries
  if (dataFlowLog.length > 10000) {
    dataFlowLog.splice(0, dataFlowLog.length - 10000);
  }
  return full;
}

/**
 * Get recent data flow entries.
 */
export function getDataFlowLog(limit: number = 100): DataFlowEntry[] {
  return dataFlowLog.slice(-limit);
}

/**
 * Clear the data flow log (for testing).
 */
export function clearDataFlowLog(): void {
  dataFlowLog.length = 0;
}

/**
 * Get a summary of data flow by server.
 */
export function getDataFlowSummary(): Record<string, { requests: number; responses: number; blocked: number }> {
  const summary: Record<string, { requests: number; responses: number; blocked: number }> = {};
  for (const entry of dataFlowLog) {
    if (!summary[entry.server]) {
      summary[entry.server] = { requests: 0, responses: 0, blocked: 0 };
    }
    if (entry.direction === 'request') summary[entry.server].requests++;
    else summary[entry.server].responses++;
    if (entry.blocked) summary[entry.server].blocked++;
  }
  return summary;
}
