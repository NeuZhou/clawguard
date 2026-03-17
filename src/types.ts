// ClawGuard — Type Definitions

export type Severity = 'critical' | 'high' | 'warning' | 'info';
export type Direction = 'inbound' | 'outbound';
export type AlertAction = 'log' | 'alert' | 'block';

export interface WatchMessage {
  id: string;
  timestamp: number;
  direction: Direction;
  session: string;
  channel: string;
  content: string;
  estimatedTokens: number;
  estimatedCostUsd: number;
  model?: string;
  latencyMs?: number;
  metadata?: Record<string, unknown>;
}

export interface SecurityFinding {
  id: string;
  timestamp: number;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  category: string;
  owaspCategory?: string;
  description: string;
  evidence?: string;
  session?: string;
  channel?: string;
  action: AlertAction;
  confidence?: number;
  attack_chain_id?: string | null;
  soulLock?: boolean;
}

// === Risk Engine Types ===
export interface RiskResult {
  score: number;
  verdict: string;
  icon: string;
  enrichedFindings: SecurityFinding[];
  attackChains: string[];
}

// === Policy Engine Types ===
export type PolicyDecisionType = 'allow' | 'deny' | 'warn' | 'review';

export interface PolicyDecision {
  decision: PolicyDecisionType;
  tool: string;
  reason: string;
  severity: Severity;
  matched?: string;
}

export interface PolicyConfig {
  exec?: { block_patterns?: string[]; dangerous_commands?: string[] };
  file?: { deny_read?: string[]; deny_write?: string[] };
  browser?: { block_domains?: string[] };
  message?: { block_targets?: string[] };
}

// === Insider Threat Types ===
export interface InsiderThreatResult {
  findings: SecurityFinding[];
  threatLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
}

export interface AuditEvent {
  id: string;
  timestamp: number;
  type: string;
  detail: string;
  session?: string;
  prevHash: string;
  hash: string;
  metadata?: Record<string, unknown>;
}

export interface SessionInfo {
  id: string;
  channel: string;
  startedAt: number;
  lastActivityAt: number;
  messageCount: number;
  estimatedTokens: number;
  estimatedCostUsd: number;
  securityFindings: number;
  model?: string;
}

export interface WatchConfig {
  dashboard: { port: number; enabled: boolean };
  budget: { dailyUsd: number; weeklyUsd: number; monthlyUsd: number };
  alerts: {
    costThresholds: number[];
    securityEscalate: Severity[];
    stuckTimeoutMs: number;
    cooldownMs: number;
  };
  security: {
    enabledRules: string[];
    customRulesDir: string;
    policies?: PolicyConfig;
  };
  exporters: {
    jsonl: { enabled: boolean };
    syslog: { enabled: boolean; host: string; port: number };
    webhook: { enabled: boolean; url: string; secret: string };
  };
  retention: { days: number; maxFileSizeMb: number };
}

export const DEFAULT_CONFIG: WatchConfig = {
  dashboard: { port: 19790, enabled: true },
  budget: { dailyUsd: 50, weeklyUsd: 200, monthlyUsd: 500 },
  alerts: {
    costThresholds: [0.8, 0.9, 1.0],
    securityEscalate: ['critical', 'high'],
    stuckTimeoutMs: 300_000,
    cooldownMs: 300_000,
  },
  security: {
    enabledRules: ['prompt-injection', 'data-leakage', 'anomaly-detection', 'compliance', 'file-protection', 'identity-protection', 'mcp-security', 'supply-chain', 'privilege-escalation', 'rug-pull', 'resource-abuse', 'cross-agent-contamination', 'compliance-frameworks'],
    customRulesDir: '~/.openclaw/ClawGuard/rules.d',
  },
  exporters: {
    jsonl: { enabled: true },
    syslog: { enabled: false, host: '127.0.0.1', port: 514 },
    webhook: { enabled: false, url: '', secret: '' },
  },
  retention: { days: 30, maxFileSizeMb: 50 },
};

export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  owaspCategory: string;
  enabled: boolean;
  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[];
}

export interface RuleContext {
  session: string;
  channel: string;
  timestamp: number;
  recentMessages: WatchMessage[];
  recentFindings: SecurityFinding[];
  sessionInfo?: SessionInfo;
  /** When true, scanning static files (skip runtime-only checks like tool call tracking) */
  staticScan?: boolean;
}

export interface CustomRuleDefinition {
  name: string;
  version: string;
  rules: CustomRuleEntry[];
}

export interface CustomRuleEntry {
  id: string;
  description: string;
  event: string;
  severity: Severity;
  patterns?: { regex?: string; keyword?: string }[];
  conditions?: { metric: string; operator: string; value: number }[];
  action: AlertAction;
}

export interface AlertState {
  lastAlertTime: Record<string, number>;
  budgetAlerted: Record<string, boolean>;
}

export interface CostBreakdown {
  daily: number;
  weekly: number;
  monthly: number;
  byModel: Record<string, number>;
  bySession: Record<string, number>;
  projection: number;
}

export interface OverviewStats {
  totalMessages: number;
  activeSessions: number;
  costToday: number;
  securityAlerts: number;
  uptimeMs: number;
  health: 'healthy' | 'warnings' | 'critical';
  recentActivity: number[];
}


