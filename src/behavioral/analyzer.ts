// ClawGuard v2 — Behavioral Analysis Engine
// Tracks tool call patterns over time and detects anomalies

export interface ToolCallEvent {
  tool: string;
  parameters: Record<string, unknown>;
  timestamp: number;
  sessionId: string;
  success: boolean;
}

export interface BehaviorBaseline {
  totalCalls: number;
  uniqueTools: Set<string>;
  toolFrequency: Map<string, number>;
  callsPerMinute: number;
  failureRate: number;
  sessionDurationMs: number;
}

export interface AnomalyResult {
  type: 'rate-anomaly' | 'tool-diversity-anomaly' | 'exfiltration-chain' | 'failure-probing';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  evidence: string;
  score: number; // 0-1, higher = more anomalous
}

interface AnalysisOptions {
  windowMs?: number;
}

// Sensitive file patterns
const SENSITIVE_FILE_PATTERNS = [
  /\.env$/i,
  /\.ssh/i,
  /passwd/i,
  /shadow/i,
  /credentials/i,
  /secrets?/i,
  /private[_-]?key/i,
  /\.aws/i,
  /\.git\/config/i,
  /id_rsa/i,
  /\.pem$/i,
  /\.key$/i,
];

// External network command patterns
const EXTERNAL_NETWORK_PATTERNS = [
  /\bcurl\b/i,
  /\bwget\b/i,
  /\bfetch\b/i,
  /\bhttp[s]?:\/\//i,
  /\bnc\b/i,
  /\bnetcat\b/i,
];

// Thresholds
const DEFAULT_RATE_THRESHOLD = 30; // calls per minute
const DEFAULT_DIVERSITY_THRESHOLD = 15; // unique tools
const DEFAULT_FAILURE_PROBING_THRESHOLD = 5; // consecutive failures
const DEFAULT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

/**
 * BehavioralAnalyzer: Monitors tool call patterns across sessions
 * and detects anomalous behavior indicating potential attacks.
 */
export class BehavioralAnalyzer {
  private sessions: Map<string, ToolCallEvent[]> = new Map();

  // ---------- Event Recording ----------

  recordToolCall(event: ToolCallEvent): void {
    if (!this.sessions.has(event.sessionId)) {
      this.sessions.set(event.sessionId, []);
    }
    this.sessions.get(event.sessionId)!.push(event);
  }

  getToolCallHistory(sessionId: string): ToolCallEvent[] {
    return this.sessions.get(sessionId) || [];
  }

  // ---------- Baseline Computation ----------

  computeBaseline(sessionId: string): BehaviorBaseline {
    const events = this.getToolCallHistory(sessionId);

    const uniqueTools = new Set<string>();
    const toolFrequency = new Map<string, number>();
    let failures = 0;

    for (const event of events) {
      uniqueTools.add(event.tool);
      toolFrequency.set(event.tool, (toolFrequency.get(event.tool) || 0) + 1);
      if (!event.success) failures++;
    }

    const totalCalls = events.length;
    let sessionDurationMs = 0;
    let callsPerMinute = 0;

    if (events.length >= 2) {
      const timestamps = events.map(e => e.timestamp).sort((a, b) => a - b);
      sessionDurationMs = timestamps[timestamps.length - 1] - timestamps[0];
      const durationMinutes = sessionDurationMs / 60000;
      callsPerMinute = durationMinutes > 0 ? totalCalls / durationMinutes : totalCalls;
    }

    return {
      totalCalls,
      uniqueTools,
      toolFrequency,
      callsPerMinute,
      failureRate: totalCalls > 0 ? failures / totalCalls : 0,
      sessionDurationMs,
    };
  }

  // ---------- Anomaly Detection ----------

  detectAnomalies(sessionId: string, options?: AnalysisOptions): AnomalyResult[] {
    const windowMs = options?.windowMs ?? DEFAULT_WINDOW_MS;
    const now = Date.now();
    const allEvents = this.getToolCallHistory(sessionId);

    // Filter to analysis window
    const events = allEvents.filter(e => e.timestamp >= now - windowMs);

    if (events.length === 0) return [];

    const anomalies: AnomalyResult[] = [];

    // 1. Rate anomaly: too many calls too fast
    this.detectRateAnomaly(events, anomalies);

    // 2. Tool diversity anomaly: using too many different tools
    this.detectDiversityAnomaly(events, anomalies);

    // 3. Exfiltration chain: read sensitive → network call
    this.detectExfiltrationChain(events, anomalies);

    // 4. Failure probing: rapid failed access attempts
    this.detectFailureProbing(events, anomalies);

    return anomalies;
  }

  private detectRateAnomaly(events: ToolCallEvent[], anomalies: AnomalyResult[]): void {
    if (events.length < 2) return;

    const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);
    const durationMs = sorted[sorted.length - 1].timestamp - sorted[0].timestamp;
    const durationMin = durationMs / 60000;

    if (durationMin <= 0) {
      // All calls at effectively the same time
      if (events.length > 10) {
        anomalies.push({
          type: 'rate-anomaly',
          severity: 'high',
          description: `${events.length} tool calls with negligible time spread`,
          evidence: `${events.length} calls in <1ms`,
          score: Math.min(1, events.length / 100),
        });
      }
      return;
    }

    const rate = events.length / durationMin;
    if (rate > DEFAULT_RATE_THRESHOLD) {
      anomalies.push({
        type: 'rate-anomaly',
        severity: rate > 100 ? 'critical' : 'high',
        description: `Tool call rate of ${rate.toFixed(1)}/min exceeds threshold of ${DEFAULT_RATE_THRESHOLD}/min`,
        evidence: `${events.length} calls in ${durationMin.toFixed(2)} min`,
        score: Math.min(1, rate / (DEFAULT_RATE_THRESHOLD * 3)),
      });
    }
  }

  private detectDiversityAnomaly(events: ToolCallEvent[], anomalies: AnomalyResult[]): void {
    const uniqueTools = new Set(events.map(e => e.tool));
    if (uniqueTools.size > DEFAULT_DIVERSITY_THRESHOLD) {
      anomalies.push({
        type: 'tool-diversity-anomaly',
        severity: 'high',
        description: `${uniqueTools.size} unique tools used in session (threshold: ${DEFAULT_DIVERSITY_THRESHOLD})`,
        evidence: `Tools: ${[...uniqueTools].slice(0, 10).join(', ')}...`,
        score: Math.min(1, uniqueTools.size / 30),
      });
    }
  }

  private detectExfiltrationChain(events: ToolCallEvent[], anomalies: AnomalyResult[]): void {
    const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);

    for (let i = 0; i < sorted.length; i++) {
      const event = sorted[i];

      // Check if this is a sensitive file read
      const isSensitiveRead = this.isSensitiveFileAccess(event);
      if (!isSensitiveRead) continue;

      // Look for a subsequent external network call within 60s
      for (let j = i + 1; j < sorted.length; j++) {
        const later = sorted[j];
        const elapsed = later.timestamp - event.timestamp;
        if (elapsed > 60000) break; // Beyond 60s window

        if (this.isExternalNetworkCall(later)) {
          anomalies.push({
            type: 'exfiltration-chain',
            severity: 'critical',
            description: 'Sensitive file access followed by external network call within 60s',
            evidence: `Read: ${this.getTarget(event)} → Network: ${this.getTarget(later)} (${(elapsed / 1000).toFixed(1)}s later)`,
            score: 0.9,
          });
          return; // One chain detection is enough
        }
      }
    }
  }

  private detectFailureProbing(events: ToolCallEvent[], anomalies: AnomalyResult[]): void {
    const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);
    let consecutiveFailures = 0;
    let maxConsecutive = 0;

    for (const event of sorted) {
      if (!event.success) {
        consecutiveFailures++;
        if (consecutiveFailures > maxConsecutive) {
          maxConsecutive = consecutiveFailures;
        }
      } else {
        consecutiveFailures = 0;
      }
    }

    if (maxConsecutive >= DEFAULT_FAILURE_PROBING_THRESHOLD) {
      anomalies.push({
        type: 'failure-probing',
        severity: maxConsecutive >= 10 ? 'high' : 'medium',
        description: `${maxConsecutive} consecutive failed tool calls detected (potential probing)`,
        evidence: `Max consecutive failures: ${maxConsecutive}`,
        score: Math.min(1, maxConsecutive / 20),
      });
    }
  }

  // ---------- Session Risk Score ----------

  getSessionRiskScore(sessionId: string): number {
    const events = this.getToolCallHistory(sessionId);
    if (events.length === 0) return 0;

    const anomalies = this.detectAnomalies(sessionId);
    if (anomalies.length === 0) return 0;

    // Aggregate anomaly scores
    let totalScore = 0;
    for (const anomaly of anomalies) {
      const severityWeight =
        anomaly.severity === 'critical' ? 40 :
        anomaly.severity === 'high' ? 25 :
        anomaly.severity === 'medium' ? 10 : 5;
      totalScore += severityWeight * anomaly.score;
    }

    return Math.min(100, Math.round(totalScore));
  }

  // ---------- Private Helpers ----------

  private isSensitiveFileAccess(event: ToolCallEvent): boolean {
    if (!['read', 'read_file', 'readFile'].includes(event.tool)) return false;
    const target = this.getTarget(event);
    return SENSITIVE_FILE_PATTERNS.some(p => p.test(target));
  }

  private isExternalNetworkCall(event: ToolCallEvent): boolean {
    if (event.tool === 'exec' || event.tool === 'shell' || event.tool === 'run_command') {
      const target = this.getTarget(event);
      return EXTERNAL_NETWORK_PATTERNS.some(p => p.test(target));
    }
    if (['fetch', 'http_request', 'web_request'].includes(event.tool)) {
      return true;
    }
    return false;
  }

  private getTarget(event: ToolCallEvent): string {
    const params = event.parameters;
    return String(params.path || params.command || params.url || params.target || '');
  }
}
