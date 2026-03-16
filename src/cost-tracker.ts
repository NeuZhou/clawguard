// ClawGuard — Cost Tracker
// Track API costs per agent/session with budgets, alerts, and reporting

import { getModelPricing, estimateTokens } from './cost-engine';

export interface CostCall {
  model: string;
  tokens: number;
  direction?: 'inbound' | 'outbound';
  agentId?: string;
  session?: string;
  timestamp?: number;
}

export interface BudgetInfo {
  spent: number;
  limit: number;
  remaining: number;
  utilization: number; // 0-1
}

export interface CostReport {
  totalSpent: number;
  totalTokens: number;
  byAgent: Record<string, { spent: number; tokens: number }>;
  byModel: Record<string, { spent: number; tokens: number; calls: number }>;
  byHour: Record<string, number>; // ISO hour string -> cost
  topExpensive: { agentId: string; spent: number }[];
  overBudgetAgents: string[];
}

interface CostEntry {
  model: string;
  tokens: number;
  cost: number;
  agentId: string;
  session: string;
  timestamp: number;
  direction: 'inbound' | 'outbound';
}

export class CostTracker {
  private entries: CostEntry[] = [];
  private budgets: Map<string, number> = new Map();
  private readonly defaultAgentId: string;

  constructor(defaultAgentId = 'default') {
    this.defaultAgentId = defaultAgentId;
  }

  /** Track an API call's cost */
  trackCall(call: CostCall): number {
    const direction = call.direction ?? 'outbound';
    const pricing = getModelPricing(call.model);
    const rate = direction === 'inbound' ? pricing.input : pricing.output;
    const cost = (call.tokens / 1_000_000) * rate;

    this.entries.push({
      model: call.model,
      tokens: call.tokens,
      cost,
      agentId: call.agentId ?? this.defaultAgentId,
      session: call.session ?? 'unknown',
      timestamp: call.timestamp ?? Date.now(),
      direction,
    });

    return cost;
  }

  /** Track a call from text content (estimates tokens) */
  trackText(model: string, text: string, options?: { direction?: 'inbound' | 'outbound'; agentId?: string; session?: string }): number {
    return this.trackCall({
      model,
      tokens: estimateTokens(text),
      direction: options?.direction,
      agentId: options?.agentId,
      session: options?.session,
    });
  }

  /** Set a budget limit for an agent (USD) */
  setBudget(agentId: string, limit: number): void {
    this.budgets.set(agentId, limit);
  }

  /** Get budget info for an agent */
  getBudget(agentId: string): BudgetInfo {
    const spent = this.getSpent(agentId);
    const limit = this.budgets.get(agentId) ?? Infinity;
    const remaining = Math.max(0, limit - spent);
    return {
      spent,
      limit,
      remaining,
      utilization: limit === Infinity ? 0 : spent / limit,
    };
  }

  /** Check if an agent is over budget */
  isOverBudget(agentId: string): boolean {
    const budget = this.budgets.get(agentId);
    if (budget === undefined) return false;
    return this.getSpent(agentId) >= budget;
  }

  /** Get total spent for an agent */
  getSpent(agentId: string): number {
    return this.entries
      .filter(e => e.agentId === agentId)
      .reduce((sum, e) => sum + e.cost, 0);
  }

  /** Get comprehensive cost report */
  getReport(): CostReport {
    const byAgent: Record<string, { spent: number; tokens: number }> = {};
    const byModel: Record<string, { spent: number; tokens: number; calls: number }> = {};
    const byHour: Record<string, number> = {};
    let totalSpent = 0;
    let totalTokens = 0;

    for (const entry of this.entries) {
      totalSpent += entry.cost;
      totalTokens += entry.tokens;

      // By agent
      if (!byAgent[entry.agentId]) byAgent[entry.agentId] = { spent: 0, tokens: 0 };
      byAgent[entry.agentId].spent += entry.cost;
      byAgent[entry.agentId].tokens += entry.tokens;

      // By model
      if (!byModel[entry.model]) byModel[entry.model] = { spent: 0, tokens: 0, calls: 0 };
      byModel[entry.model].spent += entry.cost;
      byModel[entry.model].tokens += entry.tokens;
      byModel[entry.model].calls++;

      // By hour
      const hour = new Date(entry.timestamp).toISOString().slice(0, 13);
      byHour[hour] = (byHour[hour] || 0) + entry.cost;
    }

    // Top expensive agents
    const topExpensive = Object.entries(byAgent)
      .map(([agentId, data]) => ({ agentId, spent: data.spent }))
      .sort((a, b) => b.spent - a.spent)
      .slice(0, 10);

    // Over budget agents
    const overBudgetAgents: string[] = [];
    for (const [agentId, limit] of this.budgets) {
      if (byAgent[agentId] && byAgent[agentId].spent >= limit) {
        overBudgetAgents.push(agentId);
      }
    }

    return { totalSpent, totalTokens, byAgent, byModel, byHour, topExpensive, overBudgetAgents };
  }

  /** Get entries count */
  get size(): number {
    return this.entries.length;
  }

  /** Clear all tracked data */
  clear(): void {
    this.entries = [];
  }

  /** Clear budgets */
  clearBudgets(): void {
    this.budgets.clear();
  }
}
