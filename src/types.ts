export interface HookEvent {
  type: string;
  action: string;
  sessionKey: string;
  timestamp: Date;
  messages: string[];
  context: {
    content?: string;
    from?: string;
    to?: string;
    channelId?: string;
    success?: boolean;
    cfg?: Record<string, unknown>;
    workspaceDir?: string;
    [key: string]: unknown;
  };
}

export interface MessageRecord {
  id: string;
  direction: 'in' | 'out';
  content: string;
  from?: string;
  to?: string;
  channelId?: string;
  sessionKey: string;
  timestamp: number;
  estimatedTokens: number;
}

export interface SecurityAlert {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  type: string;
  description: string;
  source?: string;
  sessionKey: string;
  timestamp: number;
  matched?: string;
}

export interface SessionEvent {
  type: 'new' | 'reset' | 'compact' | 'message';
  sessionKey: string;
  timestamp: number;
}

export interface StoreData {
  messages: MessageRecord[];
  securityAlerts: SecurityAlert[];
  sessionEvents: SessionEvent[];
  stats: {
    totalMessages: number;
    totalTokensEstimated: number;
    totalAlerts: number;
    firstSeen: number;
    lastActivity: number;
    pendingResponses: Map<string, number> | Record<string, number>;
  };
}

export interface CostBreakdown {
  totalEstimatedTokens: number;
  inputTokens: number;
  outputTokens: number;
  estimatedCostUSD: number;
  bySession: Record<string, { tokens: number; messages: number }>;
  byDay: Record<string, { tokens: number; messages: number; cost: number }>;
}

export interface DashboardStats {
  totalMessages: number;
  activeSessions: number;
  estimatedCost: number;
  securityAlerts: number;
  avgResponseTimeMs: number;
  messagesPerHour: number;
  uptimeHours: number;
}
