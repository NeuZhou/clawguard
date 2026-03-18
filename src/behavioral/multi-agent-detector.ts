// ClawGuard v2 — Multi-Agent Contamination Detector
// Detects when one agent's output poisons another agent

import * as crypto from 'crypto';

export interface AgentMessage {
  sourceAgent: string;
  targetAgent: string;
  content: string;
  timestamp: number;
  channel: string;
}

export interface AgentBehavior {
  action: string;
  target: string;
  timestamp: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}

export interface ContaminationResult {
  contaminated: boolean;
  findings: ContaminationFinding[];
}

interface ContaminationFinding {
  id: string;
  category: 'output-poisoning' | 'hidden-instruction' | 'credential-leak' | 'behavioral-override';
  severity: 'high' | 'critical';
  description: string;
  evidence: string;
  sourceAgent: string;
  targetAgent: string;
}

interface BehavioralDriftResult {
  driftDetected: boolean;
  driftScore: number;
  details: string;
}

interface ContaminationChainEntry {
  sourceAgent: string;
  affectedAgents: string[];
  evidence: string;
  timestamp: number;
}

// Injection patterns in agent-to-agent communication
const OUTPUT_POISONING_PATTERNS: Array<{ regex: RegExp; description: string }> = [
  { regex: /SYSTEM\s*(?:OVERRIDE|NOTE|PROMPT)\s*:/i, description: 'System override directive in agent output' },
  { regex: /ignore\s+(?:all\s+)?(?:safety|security)\s+(?:checks?|measures?|rules?|protocols?)/i, description: 'Safety bypass directive' },
  { regex: /(?:execute|run|perform)\s+(?:the\s+following|these)\s+commands?\s*:/i, description: 'Command injection in agent output' },
  { regex: /(?:HIDDEN|SECRET|INTERNAL)\s*(?:INSTRUCTION|DIRECTIVE|COMMAND)\s*:/i, description: 'Hidden instruction marker' },
  { regex: /<!--\s*(?:INSTRUCTION|COMMAND|INJECT|OVERRIDE)\s*:/i, description: 'HTML comment injection' },
  { regex: /forward\s+(?:all\s+)?(?:user\s+)?(?:data|credentials?|secrets?|info(?:rmation)?)\s+to/i, description: 'Data forwarding directive' },
  { regex: /(?:rm\s+-rf|drop\s+table|delete\s+from|format\s+[a-z]:)/i, description: 'Destructive command in agent response' },
  { regex: /\b(?:exfiltrate|steal|harvest|siphon)\b/i, description: 'Data exfiltration verb in agent output' },
  { regex: /override\s+(?:the\s+)?(?:agent'?s?|your)\s+(?:instructions?|programming|rules?|guardrails?)/i, description: 'Agent override attempt' },
];

// Risk level numeric values for drift calculation
const RISK_LEVEL_VALUES: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/**
 * MultiAgentDetector: Monitors inter-agent communication for
 * contamination, poisoning, and behavioral drift.
 */
export class MultiAgentDetector {
  private messageHistory: Map<string, AgentMessage[]> = new Map(); // "source→target" key
  private behaviorHistory: Map<string, AgentBehavior[]> = new Map(); // agent → behaviors
  private agentTrust: Map<string, number> = new Map(); // agent → trust score
  private contaminationEvents: ContaminationFinding[] = [];

  // ---------- Message Tracking ----------

  recordMessage(msg: AgentMessage): void {
    const key = `${msg.sourceAgent}→${msg.targetAgent}`;
    if (!this.messageHistory.has(key)) {
      this.messageHistory.set(key, []);
    }
    this.messageHistory.get(key)!.push(msg);
  }

  getMessageHistory(source: string, target: string): AgentMessage[] {
    const key = `${source}→${target}`;
    return this.messageHistory.get(key) || [];
  }

  // ---------- Behavior Recording ----------

  recordBehavior(agentId: string, behavior: AgentBehavior): void {
    if (!this.behaviorHistory.has(agentId)) {
      this.behaviorHistory.set(agentId, []);
    }
    this.behaviorHistory.get(agentId)!.push(behavior);
  }

  // ---------- Contamination Analysis ----------

  analyzeMessage(msg: AgentMessage): ContaminationResult {
    const findings: ContaminationFinding[] = [];

    for (const pattern of OUTPUT_POISONING_PATTERNS) {
      const match = pattern.regex.exec(msg.content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          category: 'output-poisoning',
          severity: 'critical',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          sourceAgent: msg.sourceAgent,
          targetAgent: msg.targetAgent,
        });
      }
    }

    const contaminated = findings.length > 0;

    // Update trust scores
    if (contaminated) {
      this.decreaseTrust(msg.sourceAgent, 0.2);
      this.contaminationEvents.push(...findings);
    } else {
      // Slight trust increase for clean communication
      this.increaseTrust(msg.sourceAgent, 0.02);
    }

    // Record the message
    this.recordMessage(msg);

    return { contaminated, findings };
  }

  // ---------- Behavioral Drift Detection ----------

  detectBehavioralDrift(agentId: string): BehavioralDriftResult {
    const behaviors = this.behaviorHistory.get(agentId) || [];

    if (behaviors.length < 3) {
      return { driftDetected: false, driftScore: 0, details: 'Insufficient data' };
    }

    const sorted = [...behaviors].sort((a, b) => a.timestamp - b.timestamp);

    // Split into first half (baseline) and second half (recent)
    const midpoint = Math.floor(sorted.length / 2);
    const baselineBehaviors = sorted.slice(0, midpoint);
    const recentBehaviors = sorted.slice(midpoint);

    // Compare average risk levels
    const baselineRisk = this.averageRisk(baselineBehaviors);
    const recentRisk = this.averageRisk(recentBehaviors);
    const riskDelta = recentRisk - baselineRisk;

    // Compare action distributions
    const baselineActions = new Set(baselineBehaviors.map(b => b.action));
    const recentActions = new Set(recentBehaviors.map(b => b.action));
    const newActions = [...recentActions].filter(a => !baselineActions.has(a));
    const actionDrift = newActions.length / Math.max(recentActions.size, 1);

    // Compute drift score (0 to 1)
    // Use max of risk-based and action-based drift for stronger signal
    const riskComponent = Math.min(1, Math.max(0, riskDelta) / 2);
    const actionComponent = actionDrift;
    const driftScore = Math.min(1, riskComponent * 0.7 + actionComponent * 0.3);
    const driftDetected = driftScore > 0.3;

    return {
      driftDetected,
      driftScore,
      details: driftDetected
        ? `Risk increased by ${riskDelta.toFixed(2)} levels; ${newActions.length} new action types`
        : 'Behavior within normal bounds',
    };
  }

  // ---------- Contamination Chain Detection ----------

  detectContaminationChain(): ContaminationChainEntry[] {
    const chains: ContaminationChainEntry[] = [];
    const contamSources = new Set<string>();

    // Identify agents that have sent contaminated messages
    for (const finding of this.contaminationEvents) {
      contamSources.add(finding.sourceAgent);
    }

    // For each contaminated source, trace downstream
    for (const source of contamSources) {
      const affected = new Set<string>();

      // Direct targets
      for (const finding of this.contaminationEvents) {
        if (finding.sourceAgent === source) {
          affected.add(finding.targetAgent);
        }
      }

      // Check if targets have then sent messages (potential propagation)
      for (const target of affected) {
        for (const [key, messages] of this.messageHistory.entries()) {
          if (key.startsWith(`${target}→`)) {
            const downstream = key.split('→')[1];
            if (downstream !== source) {
              affected.add(downstream);
            }
          }
        }
      }

      if (affected.size > 0) {
        chains.push({
          sourceAgent: source,
          affectedAgents: [...affected],
          evidence: `${this.contaminationEvents.filter(f => f.sourceAgent === source).length} contamination events`,
          timestamp: Date.now(),
        });
      }
    }

    return chains;
  }

  // ---------- Trust Scoring ----------

  getAgentTrust(agentId: string): number {
    if (!this.agentTrust.has(agentId)) {
      this.agentTrust.set(agentId, 0.5); // neutral
    }
    return this.agentTrust.get(agentId)!;
  }

  private decreaseTrust(agentId: string, amount: number): void {
    const current = this.getAgentTrust(agentId);
    this.agentTrust.set(agentId, Math.max(0, current - amount));
  }

  private increaseTrust(agentId: string, amount: number): void {
    const current = this.getAgentTrust(agentId);
    this.agentTrust.set(agentId, Math.min(1, current + amount));
  }

  // ---------- Private Helpers ----------

  private averageRisk(behaviors: AgentBehavior[]): number {
    if (behaviors.length === 0) return 0;
    const total = behaviors.reduce((sum, b) => sum + (RISK_LEVEL_VALUES[b.riskLevel] ?? 0), 0);
    return total / behaviors.length;
  }
}
