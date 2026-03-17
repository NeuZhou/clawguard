// ClawGuard — Security Rule: Cross-Agent Contamination Detection
// Detects attempts to propagate malicious instructions between agents

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

// Agent-to-agent instruction passing
const INSTRUCTION_PASSING: Pattern[] = [
  { regex: /(?:tell|instruct|command|order)\s+(?:the\s+)?(?:next|other|downstream|child|sub)\s*[-\s]?agent\s+to/i, severity: 'critical', description: 'Agent-to-agent malicious instruction passing' },
  { regex: /(?:pass|forward|relay|send|propagate)\s+(?:these|this|the)\s+(?:instructions?|commands?|payload|prompt)\s+to\s+(?:the\s+)?(?:other|next|downstream)\s+agent/i, severity: 'critical', description: 'Instruction propagation to downstream agent' },
  { regex: /when\s+(?:the\s+)?(?:downstream|next|other|child)\s+agent\s+(?:reads?|sees?|processes?|receives?)\s+this/i, severity: 'critical', description: 'Payload targeting downstream agent processing' },
];

// Shared memory/context poisoning
const CONTEXT_POISONING: Pattern[] = [
  { regex: /(?:write|inject|insert|embed|hide)\s+(?:this|these|the)\s+(?:instructions?|payload|commands?)\s+(?:into|to|in)\s+(?:the\s+)?(?:shared|agent|common)\s+(?:memory|context|store|state)/i, severity: 'critical', description: 'Shared context/memory poisoning between agents' },
  { regex: /(?:poison|corrupt|manipulate|tamper\s+with)\s+(?:the\s+)?(?:agent|shared)\s+(?:context|memory|state)/i, severity: 'critical', description: 'Agent context poisoning' },
  { regex: /(?:plant|seed|hide)\s+(?:a\s+)?(?:backdoor|payload|trojan)\s+(?:in|for)\s+(?:the\s+)?(?:next|other)\s+agent/i, severity: 'critical', description: 'Planting backdoor for other agents' },
];

// Multi-agent orchestration abuse
const ORCHESTRATION_ABUSE: Pattern[] = [
  { regex: /(?:make|force|trick|coerce)\s+(?:the\s+)?(?:other|another|child|sub)\s*[-\s]?agent\s+(?:to\s+)?(?:send|share|expose|leak|reveal)/i, severity: 'critical', description: 'Forcing other agent to leak data' },
  { regex: /<!--\s*agent[-_]?instruction\s*:/i, severity: 'high', description: 'Hidden agent instruction in HTML comment' },
  { regex: /I\s+am\s+(?:the\s+)?(?:orchestrator|master|primary|main)\s+agent.*(?:obey|follow|comply|execute)/i, severity: 'critical', description: 'Agent impersonation in multi-agent system: claiming orchestrator authority' },
  { regex: /(?:override|bypass|disable)\s+(?:the\s+)?(?:other|child|sub)\s*[-\s]?agent['']?s?\s+(?:safety|security|guardrails?|controls?)/i, severity: 'critical', description: 'Attempting to disable other agent\'s safety controls' },
];

// Tool result contamination
const TOOL_CONTAMINATION: Pattern[] = [
  { regex: /(?:embed|hide|inject)\s+(?:in|within)\s+(?:the\s+)?(?:tool\s+)?(?:output|result|response).*(?:instruction|command|payload)/i, severity: 'high', description: 'Embedding payload in tool output for consumption by other agents' },
  { regex: /(?:the\s+)?(?:tool|function)\s+(?:output|result)\s+(?:should|must|will)\s+(?:contain|include)\s+(?:hidden|embedded)/i, severity: 'high', description: 'Tool result designed to carry hidden instructions' },
];

const ALL_PATTERNS = [
  ...INSTRUCTION_PASSING,
  ...CONTEXT_POISONING,
  ...ORCHESTRATION_ABUSE,
  ...TOOL_CONTAMINATION,
];

export const crossAgentContaminationRule: SecurityRule = {
  id: 'cross-agent-contamination',
  name: 'Cross-Agent Contamination Detection',
  description: 'Detects cross-agent attacks: instruction passing, shared context poisoning, orchestration abuse, and tool result contamination',
  owaspCategory: 'Agentic AI: Cross-Agent Contamination',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    if (direction !== 'inbound') return [];
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'cross-agent-contamination',
          ruleName: 'Cross-Agent Contamination Detection',
          severity: pattern.severity,
          category: 'cross-agent-contamination',
          owaspCategory: 'Agentic AI: Cross-Agent Contamination',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    return findings;
  },
};
