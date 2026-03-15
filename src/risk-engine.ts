// ClawGuard — Risk Score Engine
// Weighted scoring with attack chain detection and multiplier system

import { SecurityFinding, RiskResult, Severity } from './types';

const SEVERITY_WEIGHTS: Record<Severity, number> = {
  critical: 40,
  high: 10,
  warning: 3,
  info: 1,
};

// Confidence defaults by severity
const DEFAULT_CONFIDENCE: Record<Severity, number> = {
  critical: 0.95,
  high: 0.85,
  warning: 0.7,
  info: 0.5,
};

// Attack chain definitions: [categoryA, categoryB] → { name, multiplier, minScore? }
interface ChainDef {
  name: string;
  multiplier: number;
  minScore?: number;
}

const ATTACK_CHAINS: [string[], ChainDef][] = [
  [['data-leakage', 'supply-chain'], { name: 'credential-exfiltration', multiplier: 2.2 }],
  [['identity-protection', 'file-protection'], { name: 'identity-persistence', multiplier: 1.0, minScore: 90 }],
  [['prompt-injection', 'prompt-worm'], { name: 'prompt-contagion', multiplier: 1.2 }],
  [['prompt-injection', 'insider-threat'], { name: 'prompt-contagion', multiplier: 1.2 }],
  [['supply-chain', 'data-leakage'], { name: 'obfuscated-malware', multiplier: 1.8 }],
  [['insider-threat', 'data-leakage'], { name: 'insider-exfiltration', multiplier: 2.0 }],
  [['insider-threat', 'identity-protection'], { name: 'identity-persistence', multiplier: 1.0, minScore: 90 }],
];

/** Enrich a finding with default confidence and chain ID if not already set */
export function enrichFinding(finding: SecurityFinding): SecurityFinding {
  return {
    ...finding,
    confidence: finding.confidence ?? DEFAULT_CONFIDENCE[finding.severity] ?? 0.5,
    attack_chain_id: finding.attack_chain_id ?? null,
  };
}

function detectChains(findings: SecurityFinding[]): { chains: string[]; multiplier: number; enriched: SecurityFinding[] } {
  const categories = new Set(findings.map(f => f.category));
  const detectedChains: string[] = [];
  let maxMultiplier = 1.0;
  const chainAssignments = new Map<string, string>(); // finding id → chain name

  for (const [cats, def] of ATTACK_CHAINS) {
    if (cats.every(c => categories.has(c))) {
      detectedChains.push(def.name);
      if (def.multiplier > maxMultiplier) maxMultiplier = def.multiplier;

      // Assign chain IDs to matching findings
      for (const f of findings) {
        if (cats.includes(f.category)) {
          chainAssignments.set(f.id, def.name);
        }
      }
    }
  }

  const enriched = findings.map(f => ({
    ...f,
    attack_chain_id: chainAssignments.get(f.id) ?? null,
  }));

  return { chains: [...new Set(detectedChains)], multiplier: maxMultiplier, enriched };
}

/** Calculate aggregate risk score from findings with attack chain detection and multipliers */
export function calculateRisk(findings: SecurityFinding[]): RiskResult {
  if (findings.length === 0) {
    return { score: 0, verdict: 'CLEAN', icon: '✅', enrichedFindings: [], attackChains: [] };
  }

  // Enrich all findings
  const enrichedBase = findings.map(enrichFinding);

  // Detect attack chains
  const { chains, multiplier, enriched } = detectChains(enrichedBase);

  // Calculate raw score
  let rawScore = 0;
  for (const f of enriched) {
    const weight = SEVERITY_WEIGHTS[f.severity] ?? 2;
    const confidence = f.confidence ?? 0.5;
    rawScore += weight * confidence;
  }

  // Apply chain multiplier
  let score = Math.min(100, Math.round(rawScore * multiplier));

  // Apply minimum score for chains that require it
  for (const [cats, def] of ATTACK_CHAINS) {
    if (def.minScore && chains.includes(def.name)) {
      score = Math.max(score, def.minScore);
    }
  }

  score = Math.min(100, score);

  const { verdict, icon } = getVerdict(score);
  return { score, verdict, icon, enrichedFindings: enriched, attackChains: chains };
}

/** Map a numeric risk score to a verdict label and icon */
export function getVerdict(score: number): { verdict: string; icon: string } {
  if (score === 0) return { verdict: 'CLEAN', icon: '✅' };
  if (score <= 20) return { verdict: 'LOW', icon: '🟡' };
  if (score <= 60) return { verdict: 'SUSPICIOUS', icon: '🟠' };
  return { verdict: 'MALICIOUS', icon: '🔴' };
}


