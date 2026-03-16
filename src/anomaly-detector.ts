// ClawGuard — Anomaly Detector
// Detect unusual agent behavior patterns: tool sequences, frequency spikes, new tools, time patterns

export interface ToolCall {
  tool: string;
  timestamp: number;
  args?: Record<string, unknown>;
  session?: string;
}

export interface AnomalyResult {
  anomalous: boolean;
  score: number; // 0-100
  reasons: AnomalyReason[];
}

export interface AnomalyReason {
  type: 'unknown_tool' | 'unusual_sequence' | 'frequency_spike' | 'time_anomaly' | 'burst_detected';
  description: string;
  severity: 'low' | 'medium' | 'high';
  confidence: number; // 0-1
}

interface ToolProfile {
  frequency: number; // calls per trace
  avgGapMs: number;
  followers: Map<string, number>; // tool -> count of times it follows
}

export class AnomalyDetector {
  private knownTools: Set<string> = new Set();
  private toolProfiles: Map<string, ToolProfile> = new Map();
  private bigramCounts: Map<string, number> = new Map();
  private totalBigrams = 0;
  private trained = false;
  private traceCount = 0;

  // Runtime state for detect()
  private recentCalls: ToolCall[] = [];
  private readonly windowMs: number;
  private readonly maxRecent: number;
  private readonly anomalyThreshold: number;

  constructor(options?: { windowMs?: number; maxRecent?: number; anomalyThreshold?: number }) {
    this.windowMs = options?.windowMs ?? 60_000;
    this.maxRecent = options?.maxRecent ?? 100;
    this.anomalyThreshold = options?.anomalyThreshold ?? 30;
  }

  /** Learn normal patterns from historical traces */
  train(normalTraces: ToolCall[][]): void {
    this.knownTools.clear();
    this.toolProfiles.clear();
    this.bigramCounts.clear();
    this.totalBigrams = 0;
    this.traceCount = normalTraces.length;

    // Collect all tools
    for (const trace of normalTraces) {
      for (const call of trace) {
        this.knownTools.add(call.tool);
      }
    }

    // Build tool profiles
    for (const tool of this.knownTools) {
      const profile: ToolProfile = { frequency: 0, avgGapMs: 0, followers: new Map() };
      let totalGaps = 0;
      let gapCount = 0;

      for (const trace of normalTraces) {
        let count = 0;
        let lastTs: number | null = null;
        for (let i = 0; i < trace.length; i++) {
          if (trace[i].tool === tool) {
            count++;
            if (lastTs !== null) {
              totalGaps += trace[i].timestamp - lastTs;
              gapCount++;
            }
            lastTs = trace[i].timestamp;
            // Track following tool
            if (i + 1 < trace.length) {
              const next = trace[i + 1].tool;
              profile.followers.set(next, (profile.followers.get(next) || 0) + 1);
            }
          }
        }
        profile.frequency += count;
      }

      profile.frequency = this.traceCount > 0 ? profile.frequency / this.traceCount : 0;
      profile.avgGapMs = gapCount > 0 ? totalGaps / gapCount : 0;
      this.toolProfiles.set(tool, profile);
    }

    // Build bigram model
    for (const trace of normalTraces) {
      for (let i = 0; i < trace.length - 1; i++) {
        const bigram = `${trace[i].tool}→${trace[i + 1].tool}`;
        this.bigramCounts.set(bigram, (this.bigramCounts.get(bigram) || 0) + 1);
        this.totalBigrams++;
      }
    }

    this.trained = true;
  }

  /** Check if a tool call is anomalous */
  detect(toolCall: ToolCall): AnomalyResult {
    const reasons: AnomalyReason[] = [];
    const now = toolCall.timestamp;

    // Add to recent calls and prune
    this.recentCalls.push(toolCall);
    this.recentCalls = this.recentCalls.filter(c => now - c.timestamp < this.windowMs);
    if (this.recentCalls.length > this.maxRecent) {
      this.recentCalls = this.recentCalls.slice(-this.maxRecent);
    }

    // 1. Unknown tool check
    if (this.trained && !this.knownTools.has(toolCall.tool)) {
      reasons.push({
        type: 'unknown_tool',
        description: `Tool "${toolCall.tool}" was never seen during training`,
        severity: 'high',
        confidence: 0.9,
      });
    }

    // 2. Unusual sequence check (bigram)
    if (this.trained && this.recentCalls.length >= 2) {
      const prev = this.recentCalls[this.recentCalls.length - 2];
      const bigram = `${prev.tool}→${toolCall.tool}`;
      const bigramCount = this.bigramCounts.get(bigram) || 0;
      if (this.totalBigrams > 0 && bigramCount === 0) {
        reasons.push({
          type: 'unusual_sequence',
          description: `Sequence "${prev.tool}" → "${toolCall.tool}" never seen in training data`,
          severity: 'medium',
          confidence: 0.7,
        });
      }
    }

    // 3. Frequency spike check
    if (this.trained) {
      const profile = this.toolProfiles.get(toolCall.tool);
      const recentCount = this.recentCalls.filter(c => c.tool === toolCall.tool).length;
      const expectedInWindow = profile ? profile.frequency * (this.windowMs / 60_000) : 0;
      // Spike if >3x expected or >10 calls with no baseline
      if (profile && expectedInWindow > 0 && recentCount > expectedInWindow * 3) {
        reasons.push({
          type: 'frequency_spike',
          description: `Tool "${toolCall.tool}" called ${recentCount} times in window (expected ~${expectedInWindow.toFixed(1)})`,
          severity: 'medium',
          confidence: Math.min(0.95, 0.5 + (recentCount / expectedInWindow) * 0.1),
        });
      } else if (!profile && recentCount > 10) {
        reasons.push({
          type: 'frequency_spike',
          description: `Unknown tool "${toolCall.tool}" called ${recentCount} times in window`,
          severity: 'high',
          confidence: 0.8,
        });
      }
    }

    // 4. Burst detection (many calls in very short time regardless of training)
    const burstWindowMs = 5_000;
    const burstCalls = this.recentCalls.filter(c => now - c.timestamp < burstWindowMs);
    if (burstCalls.length >= 15) {
      reasons.push({
        type: 'burst_detected',
        description: `${burstCalls.length} tool calls in ${burstWindowMs / 1000}s burst`,
        severity: 'high',
        confidence: 0.85,
      });
    }

    // 5. Time anomaly (calls at unusual hours if trained with time patterns)
    if (this.trained && this.traceCount >= 5) {
      const hour = new Date(toolCall.timestamp).getHours();
      // Simple: flag calls between 2-5 AM as suspicious if we have enough training data
      if (hour >= 2 && hour < 5) {
        reasons.push({
          type: 'time_anomaly',
          description: `Tool call at unusual hour (${hour}:00)`,
          severity: 'low',
          confidence: 0.4,
        });
      }
    }

    // Calculate composite score
    const score = this.calculateScore(reasons);

    return {
      anomalous: score >= this.anomalyThreshold,
      score,
      reasons,
    };
  }

  private calculateScore(reasons: AnomalyReason[]): number {
    if (reasons.length === 0) return 0;
    const weights = { low: 10, medium: 25, high: 45 };
    let total = 0;
    for (const r of reasons) {
      total += weights[r.severity] * r.confidence;
    }
    return Math.min(100, Math.round(total));
  }

  /** Reset runtime state */
  reset(): void {
    this.recentCalls = [];
  }

  /** Check if detector has been trained */
  get isTrained(): boolean {
    return this.trained;
  }

  /** Get known tools from training */
  getKnownTools(): string[] {
    return [...this.knownTools];
  }
}
