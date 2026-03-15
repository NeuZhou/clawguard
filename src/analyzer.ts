import { getMessages, getSessions, getAlerts, getStats, getRawData } from './store.js';
import { dayKey } from './utils.js';
import type { CostBreakdown, DashboardStats } from './types.js';

// Rough cost estimate: $0.01 per 1K tokens (blended input/output average)
const COST_PER_1K_TOKENS = 0.01;

export function getCostBreakdown(): CostBreakdown {
  const messages = getRawData().messages;
  const bySession: Record<string, { tokens: number; messages: number }> = {};
  const byDay: Record<string, { tokens: number; messages: number; cost: number }> = {};
  let inputTokens = 0;
  let outputTokens = 0;

  for (const msg of messages) {
    // Session breakdown
    if (!bySession[msg.sessionKey]) bySession[msg.sessionKey] = { tokens: 0, messages: 0 };
    bySession[msg.sessionKey].tokens += msg.estimatedTokens;
    bySession[msg.sessionKey].messages++;

    // Day breakdown
    const day = dayKey(msg.timestamp);
    if (!byDay[day]) byDay[day] = { tokens: 0, messages: 0, cost: 0 };
    byDay[day].tokens += msg.estimatedTokens;
    byDay[day].messages++;
    byDay[day].cost = (byDay[day].tokens / 1000) * COST_PER_1K_TOKENS;

    if (msg.direction === 'in') inputTokens += msg.estimatedTokens;
    else outputTokens += msg.estimatedTokens;
  }

  const totalEstimatedTokens = inputTokens + outputTokens;

  return {
    totalEstimatedTokens,
    inputTokens,
    outputTokens,
    estimatedCostUSD: (totalEstimatedTokens / 1000) * COST_PER_1K_TOKENS,
    bySession,
    byDay,
  };
}

export function getDashboardStats(): DashboardStats {
  const stats = getStats();
  const sessions = getSessions();
  const alerts = getAlerts(1000);
  const cost = getCostBreakdown();

  // Calculate avg response time from message pairs
  const messages = getRawData().messages;
  const responseTimes: number[] = [];
  const pendingReceived: Record<string, number> = {};

  for (const msg of messages) {
    if (msg.direction === 'in') {
      pendingReceived[msg.sessionKey] = msg.timestamp;
    } else if (msg.direction === 'out' && pendingReceived[msg.sessionKey]) {
      responseTimes.push(msg.timestamp - pendingReceived[msg.sessionKey]);
      delete pendingReceived[msg.sessionKey];
    }
  }

  const avgResponseTimeMs = responseTimes.length
    ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length
    : 0;

  // Active sessions = sessions with activity in last hour
  const oneHourAgo = Date.now() - 3600_000;
  const activeSessions = Object.values(sessions).filter((s) => s.lastActivity > oneHourAgo).length;

  // Messages per hour (last 24h)
  const oneDayAgo = Date.now() - 86400_000;
  const recentMessages = messages.filter((m) => m.timestamp > oneDayAgo);
  const hoursSpan = Math.max(1, (Date.now() - (stats.firstSeen || Date.now())) / 3600_000);
  const messagesPerHour = recentMessages.length / Math.min(24, hoursSpan);

  return {
    totalMessages: stats.totalMessages,
    activeSessions,
    estimatedCost: cost.estimatedCostUSD,
    securityAlerts: alerts.length,
    avgResponseTimeMs: Math.round(avgResponseTimeMs),
    messagesPerHour: Math.round(messagesPerHour * 10) / 10,
    uptimeHours: Math.round(hoursSpan * 10) / 10,
  };
}
