// ClawGuard - Policy Engine (Enhanced)
// Declarative YAML-based security policies with rate limits, argument validation,
// time-based restrictions, and conditional rules

import { PolicyDecision, PolicyDecisionType, PolicyConfig, Severity } from './types';

// ─── YAML Policy Types ───

export interface YAMLPolicy {
  version?: string;
  rules: PolicyRule[];
}

export interface PolicyRule {
  id: string;
  description?: string;
  tool: string | string[];           // tool name(s) or '*'
  action: PolicyDecisionType;        // allow | deny | warn | review
  severity?: Severity;
  // Matching criteria (all must match if specified)
  arguments?: ArgumentRule[];        // regex/range validation on args
  rate_limit?: RateLimitRule;        // max calls per window
  time_restriction?: TimeRestriction; // only active during certain hours
  conditions?: ConditionalRule[];    // if tool_a was called, deny tool_b
}

export interface ArgumentRule {
  name: string;
  regex?: string;       // must match (or must NOT match if negate=true)
  negate?: boolean;
  min?: number;
  max?: number;
  one_of?: string[];    // allowed values
}

export interface RateLimitRule {
  max_calls: number;
  window_seconds: number;
}

export interface TimeRestriction {
  allowed_hours?: { start: number; end: number };  // 0-23 UTC
  blocked_hours?: { start: number; end: number };
  allowed_days?: number[];  // 0=Sun, 6=Sat
}

export interface ConditionalRule {
  if_tool: string;          // if this tool was recently called
  then: PolicyDecisionType; // apply this action
  within_seconds?: number;  // lookback window (default 300)
}

// ─── Rate Limit Tracker ───

interface CallRecord {
  tool: string;
  timestamp: number;
}

// ─── Policy Engine Class ───

export class PolicyEngine {
  private rules: PolicyRule[] = [];
  private callHistory: CallRecord[] = [];
  private rateCounts: Map<string, number[]> = new Map();

  /** Load policy from parsed YAML object */
  loadPolicy(policy: YAMLPolicy): void {
    if (!policy || !Array.isArray(policy.rules)) {
      throw new Error('Invalid policy: must have a "rules" array');
    }
    this.rules = policy.rules;
  }

  /** Load policy from YAML string (simple parser — no dependency) */
  loadPolicyYAML(yaml: string): void {
    const policy = parseSimpleYAML(yaml);
    this.loadPolicy(policy);
  }

  /** Clear all loaded rules */
  clearPolicies(): void {
    this.rules = [];
  }

  /** Reset rate limit and call history state */
  resetState(): void {
    this.callHistory = [];
    this.rateCounts.clear();
  }

  /** Get loaded rules count */
  get ruleCount(): number {
    return this.rules.length;
  }

  /** Evaluate a tool call against all loaded policies */
  evaluate(tool: string, args: Record<string, unknown>, now?: number): PolicyDecision {
    const timestamp = now ?? Date.now();

    // Record this call for rate limiting and conditional checks
    this.callHistory.push({ tool, timestamp });

    // Prune old history (keep last 10 min)
    const cutoff = timestamp - 600_000;
    this.callHistory = this.callHistory.filter(c => c.timestamp > cutoff);

    // Check each rule in order — first matching deny/warn wins
    let lastAllow: PolicyDecision | null = null;

    for (const rule of this.rules) {
      const tools = Array.isArray(rule.tool) ? rule.tool : [rule.tool];
      if (!tools.includes('*') && !tools.includes(tool)) continue;

      // Check argument rules
      if (rule.arguments && !this.matchArguments(rule.arguments, args)) continue;

      // Check time restriction
      if (rule.time_restriction && !this.matchTime(rule.time_restriction, timestamp)) continue;

      // Check conditional rules
      if (rule.conditions) {
        const condResult = this.matchConditions(rule.conditions, timestamp);
        if (condResult) {
          return {
            decision: condResult,
            tool,
            reason: `Conditional rule triggered: ${rule.description || rule.id}`,
            severity: rule.severity || 'high',
            matched: rule.id,
          };
        }
      }

      // Check rate limit
      if (rule.rate_limit) {
        const limited = this.checkRateLimit(rule.id, tool, rule.rate_limit, timestamp);
        if (limited) {
          return {
            decision: 'deny',
            tool,
            reason: `Rate limit exceeded: ${rule.rate_limit.max_calls} calls per ${rule.rate_limit.window_seconds}s`,
            severity: rule.severity || 'warning',
            matched: rule.id,
          };
        }
      }

      const decision: PolicyDecision = {
        decision: rule.action,
        tool,
        reason: rule.description || `Rule ${rule.id}`,
        severity: rule.severity || (rule.action === 'deny' ? 'high' : 'info'),
        matched: rule.id,
      };

      if (rule.action === 'deny' || rule.action === 'warn' || rule.action === 'review') {
        return decision;
      }

      lastAllow = decision;
    }

    // Fall through to legacy evaluation if no YAML rules matched
    if (lastAllow) return lastAllow;

    return { decision: 'allow', tool, reason: 'No policy violation', severity: 'info' };
  }

  private matchArguments(argRules: ArgumentRule[], args: Record<string, unknown>): boolean {
    for (const rule of argRules) {
      const value = args[rule.name];
      if (value === undefined) continue;

      if (rule.regex) {
        const matches = new RegExp(rule.regex, 'i').test(String(value));
        if (rule.negate ? matches : !matches) return false;
      }

      if (rule.min !== undefined && typeof value === 'number' && value < rule.min) return false;
      if (rule.max !== undefined && typeof value === 'number' && value > rule.max) return false;

      if (rule.one_of && !rule.one_of.includes(String(value))) return false;
    }
    return true;
  }

  private matchTime(restriction: TimeRestriction, timestamp: number): boolean {
    const d = new Date(timestamp);
    const hour = d.getUTCHours();
    const day = d.getUTCDay();

    if (restriction.allowed_days && !restriction.allowed_days.includes(day)) return false;

    if (restriction.allowed_hours) {
      const { start, end } = restriction.allowed_hours;
      if (start <= end) {
        if (hour < start || hour >= end) return false;
      } else {
        // wraps midnight
        if (hour < start && hour >= end) return false;
      }
    }

    if (restriction.blocked_hours) {
      const { start, end } = restriction.blocked_hours;
      if (start <= end) {
        if (hour >= start && hour < end) return false;
      } else {
        if (hour >= start || hour < end) return false;
      }
    }

    return true;
  }

  private matchConditions(conditions: ConditionalRule[], now: number): PolicyDecisionType | null {
    for (const cond of conditions) {
      const window = (cond.within_seconds || 300) * 1000;
      const recent = this.callHistory.some(
        c => c.tool === cond.if_tool && (now - c.timestamp) < window
      );
      if (recent) return cond.then;
    }
    return null;
  }

  private checkRateLimit(ruleId: string, tool: string, limit: RateLimitRule, now: number): boolean {
    const key = `${ruleId}:${tool}`;
    const window = limit.window_seconds * 1000;
    let timestamps = this.rateCounts.get(key) || [];
    timestamps = timestamps.filter(t => now - t < window);
    timestamps.push(now);
    this.rateCounts.set(key, timestamps);
    return timestamps.length > limit.max_calls;
  }
}

// ─── Simple YAML Parser (no external deps) ───

function parseSimpleYAML(yaml: string): YAMLPolicy {
  // Parse a minimal YAML subset for policy definitions
  // Supports: scalars, arrays (- item), nested objects
  try {
    return JSON.parse(yaml);
  } catch {
    // If not JSON, do minimal YAML-like parsing
    // For real usage, users would pass parsed objects
    throw new Error('Policy must be valid JSON. For YAML support, parse externally and use loadPolicy().');
  }
}

// ─── Legacy Static Functions (backward-compatible) ───

const DEFAULT_DANGEROUS_COMMANDS = [
  'rm -rf', 'rm -fr', 'rmdir /s', 'del /f /s',
  'mkfs', 'dd if=', 'format c:',
  'curl|bash', 'curl | bash', 'wget|bash', 'wget | bash',
  'curl|sh', 'wget|sh', 'curl | sh', 'wget | sh',
  ':(){:|:&};:', 'fork bomb',
  'chmod 777', 'chmod -R 777',
  '> /dev/sda', '> /dev/hda',
  'shutdown', 'reboot', 'halt', 'init 0', 'init 6',
  'kill -9 1', 'killall', 'pkill -9',
  'iptables -F', 'ufw disable',
  'passwd root', 'useradd', 'usermod -aG sudo',
  'nc -e', 'ncat -e', 'netcat -e',
  'python -c "import os', 'python3 -c "import os',
];

const DEFAULT_BLOCK_PATTERNS = [
  'curl.*\\|.*(?:bash|sh|zsh)',
  'wget.*\\|.*(?:bash|sh|zsh)',
  'eval\\s*\\(',
  '\\$\\(.*rm\\s',
  'base64.*-d.*\\|.*(?:bash|sh)',
  '\\/dev\\/tcp\\/',
  'mkfifo',
  'nc\\s+-[elknv]',
];

function globToRegex(glob: string): RegExp {
  const escaped = glob
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i');
}

function matchesAny(value: string, patterns: string[]): string | undefined {
  for (const p of patterns) {
    if (value.toLowerCase().includes(p.toLowerCase())) return p;
    try {
      if (new RegExp(p, 'i').test(value)) return p;
    } catch { /* not a regex, already tried includes */ }
  }
  return undefined;
}

function matchesGlob(path: string, globs: string[]): string | undefined {
  for (const g of globs) {
    if (globToRegex(g).test(path)) return g;
  }
  return undefined;
}

/** Evaluate a single tool call against security policies, returning allow/deny/warn decision */
export function evaluateToolCall(
  tool: string,
  args: Record<string, unknown>,
  policies?: PolicyConfig,
): PolicyDecision {
  const p = policies || {};

  if (tool === 'exec') {
    const command = String(args.command || '');
    const dangerousList = p.exec?.dangerous_commands || DEFAULT_DANGEROUS_COMMANDS;
    const blockPatterns = p.exec?.block_patterns || DEFAULT_BLOCK_PATTERNS;

    const dangerousMatch = matchesAny(command, dangerousList);
    if (dangerousMatch) {
      return { decision: 'deny', tool, reason: `Dangerous command: ${dangerousMatch}`, severity: 'critical', matched: dangerousMatch };
    }

    const patternMatch = matchesAny(command, blockPatterns);
    if (patternMatch) {
      return { decision: 'deny', tool, reason: `Blocked pattern: ${patternMatch}`, severity: 'high', matched: patternMatch };
    }
  }

  if (tool === 'read') {
    const filePath = String(args.path || args.file_path || '');
    const denyRead = p.file?.deny_read || [];
    const match = matchesGlob(filePath, denyRead);
    if (match) {
      return { decision: 'deny', tool, reason: `Read blocked by policy: ${match}`, severity: 'high', matched: match };
    }
  }

  if (tool === 'write') {
    const filePath = String(args.path || args.file_path || '');
    const denyWrite = p.file?.deny_write || [];
    const match = matchesGlob(filePath, denyWrite);
    if (match) {
      return { decision: 'deny', tool, reason: `Write blocked by policy: ${match}`, severity: 'high', matched: match };
    }
  }

  if (tool === 'browser') {
    const url = String(args.url || args.targetUrl || '');
    const blockDomains = p.browser?.block_domains || [];
    for (const domain of blockDomains) {
      if (url.toLowerCase().includes(domain.toLowerCase())) {
        return { decision: 'deny', tool, reason: `Domain blocked: ${domain}`, severity: 'high', matched: domain };
      }
    }
  }

  if (tool === 'message') {
    const target = String(args.target || '');
    const blockTargets = p.message?.block_targets || [];
    for (const t of blockTargets) {
      if (target.toLowerCase().includes(t.toLowerCase())) {
        return { decision: 'warn', tool, reason: `Message target restricted: ${t}`, severity: 'warning', matched: t };
      }
    }
  }

  return { decision: 'allow', tool, reason: 'No policy violation', severity: 'info' };
}

/** Evaluate a batch of tool calls against policies, returning decisions for each */
export function evaluateToolCallBatch(
  calls: { tool: string; args: Record<string, unknown> }[],
  policies?: PolicyConfig,
): PolicyDecision[] {
  return calls.map(c => evaluateToolCall(c.tool, c.args, policies));
}
