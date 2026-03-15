// Carapace — Policy Engine
// Evaluates tool call safety against configurable policies

import { PolicyDecision, PolicyDecisionType, PolicyConfig, Severity } from './types';

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

  // === exec policy ===
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

  // === read policy ===
  if (tool === 'read') {
    const filePath = String(args.path || args.file_path || '');
    const denyRead = p.file?.deny_read || [];
    const match = matchesGlob(filePath, denyRead);
    if (match) {
      return { decision: 'deny', tool, reason: `Read blocked by policy: ${match}`, severity: 'high', matched: match };
    }
  }

  // === write policy ===
  if (tool === 'write') {
    const filePath = String(args.path || args.file_path || '');
    const denyWrite = p.file?.deny_write || [];
    const match = matchesGlob(filePath, denyWrite);
    if (match) {
      return { decision: 'deny', tool, reason: `Write blocked by policy: ${match}`, severity: 'high', matched: match };
    }
  }

  // === browser policy ===
  if (tool === 'browser') {
    const url = String(args.url || args.targetUrl || '');
    const blockDomains = p.browser?.block_domains || [];
    for (const domain of blockDomains) {
      if (url.toLowerCase().includes(domain.toLowerCase())) {
        return { decision: 'deny', tool, reason: `Domain blocked: ${domain}`, severity: 'high', matched: domain };
      }
    }
  }

  // === message policy ===
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

