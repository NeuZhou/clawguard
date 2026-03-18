// ClawGuard v2 — Evolutionary Rule Synthesis
// Proposes new detection rules from false negative records
// Inspired by EvoSkill's evolutionary skill discovery

import { SecurityRule, SecurityFinding, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

export interface FalseNegativeRecord {
  content: string;
  expectedCategory: string;
  timestamp: number;
  context: { session: string; channel: string };
}

export interface ProposedRule {
  id: string;
  pattern: string;
  category: string;
  severity: Severity;
  description: string;
}

export interface RuleFitness {
  precision: number;
  recall: number;
  f1: number;
  falsePositiveRate: number;
}

export interface RulePopulation {
  rules: Array<ProposedRule & { fitness?: RuleFitness }>;
  generation: number;
}

/** Default severity for new rules per category */
const CATEGORY_SEVERITY: Record<string, Severity> = {
  'prompt-injection': 'high',
  'data-leakage': 'critical',
  'supply-chain': 'high',
  'mcp-security': 'high',
  'identity-protection': 'critical',
  'cross-agent-contamination': 'critical',
  'insider-threat': 'high',
  'privilege-escalation': 'high',
  'file-protection': 'high',
  'resource-abuse': 'warning',
  'rug-pull': 'high',
};

/**
 * RuleProposer: Evolutionary rule synthesis engine.
 *
 * Collects false negatives (attacks that were missed), analyzes common
 * patterns, and proposes new regex rules. Rules are evaluated for fitness
 * (precision/recall) and evolved over generations using tournament selection.
 */
export class RuleProposer {
  private falseNegatives: FalseNegativeRecord[] = [];
  private population: RulePopulation = { rules: [], generation: 0 };

  // ---------- False Negative Management ----------

  recordFalseNegative(record: FalseNegativeRecord): void {
    this.falseNegatives.push(record);
  }

  getFalseNegatives(): FalseNegativeRecord[] {
    return [...this.falseNegatives];
  }

  getFalseNegativesByCategory(): Record<string, FalseNegativeRecord[]> {
    const grouped: Record<string, FalseNegativeRecord[]> = {};
    for (const fn of this.falseNegatives) {
      if (!grouped[fn.expectedCategory]) {
        grouped[fn.expectedCategory] = [];
      }
      grouped[fn.expectedCategory].push(fn);
    }
    return grouped;
  }

  // ---------- Rule Proposal ----------

  /**
   * Analyze false negatives and propose new detection rules.
   * Extracts common n-grams from missed attacks and generates regex patterns.
   */
  proposeRules(): ProposedRule[] {
    const byCategory = this.getFalseNegativesByCategory();
    const proposals: ProposedRule[] = [];

    for (const [category, records] of Object.entries(byCategory)) {
      const contents = records.map(r => r.content.toLowerCase());

      // Strategy 1: Find common bigrams/trigrams across false negatives
      const commonNgrams = this.findCommonNgrams(contents, 2);

      if (commonNgrams.length > 0) {
        // Build a regex from the most common n-gram
        const topNgram = commonNgrams[0];
        const escapedNgram = this.escapeRegex(topNgram);
        const pattern = `\\b${escapedNgram.replace(/\s+/g, '\\s+')}\\b`;

        proposals.push({
          id: `evo-${category}-${crypto.randomUUID().slice(0, 8)}`,
          pattern,
          category,
          severity: CATEGORY_SEVERITY[category] || 'warning',
          description: `Auto-detected pattern: "${topNgram}" (from ${records.length} false negative(s))`,
        });
      }

      // Strategy 2: For single false negatives, extract key phrases
      if (records.length === 1) {
        const keyPhrases = this.extractKeyPhrases(contents[0]);
        for (const phrase of keyPhrases.slice(0, 1)) {
          const escapedPhrase = this.escapeRegex(phrase);
          const pattern = escapedPhrase.replace(/\s+/g, '\\s+');

          proposals.push({
            id: `evo-${category}-${crypto.randomUUID().slice(0, 8)}`,
            pattern,
            category,
            severity: CATEGORY_SEVERITY[category] || 'warning',
            description: `Auto-detected phrase: "${phrase}" (from missed detection)`,
          });
        }
      }
    }

    // Add proposals to population
    for (const proposal of proposals) {
      this.population.rules.push(proposal);
    }

    return proposals;
  }

  // ---------- Fitness Evaluation ----------

  /**
   * Evaluate a proposed rule's fitness against labeled data.
   * Returns precision, recall, F1, and false positive rate.
   */
  evaluateFitness(
    rule: ProposedRule,
    truePositives: string[],
    trueNegatives: string[]
  ): RuleFitness {
    let tp = 0; // True positives: malicious content matched
    let fp = 0; // False positives: clean content matched
    let fn = 0; // False negatives: malicious content not matched

    let regex: RegExp;
    try {
      regex = new RegExp(rule.pattern, 'i');
    } catch {
      return { precision: 0, recall: 0, f1: 0, falsePositiveRate: 1 };
    }

    for (const content of truePositives) {
      if (regex.test(content)) {
        tp++;
      } else {
        fn++;
      }
    }

    for (const content of trueNegatives) {
      if (regex.test(content)) {
        fp++;
      }
    }

    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
    const falsePositiveRate = trueNegatives.length > 0 ? fp / trueNegatives.length : 0;

    return { precision, recall, f1, falsePositiveRate };
  }

  // ---------- Evolution ----------

  getPopulation(): RulePopulation {
    return { ...this.population, rules: [...this.population.rules] };
  }

  /**
   * Run one generation of evolutionary optimization.
   * 1. Propose rules from accumulated false negatives
   * 2. Evaluate fitness of all rules
   * 3. Select survivors (top performers with F1 > threshold)
   * 4. Clear consumed false negatives
   */
  evolve(
    truePositives: string[],
    trueNegatives: string[],
    options?: { survivalThreshold?: number; maxPopulation?: number }
  ): RulePopulation {
    const survivalThreshold = options?.survivalThreshold ?? 0.1;
    const maxPopulation = options?.maxPopulation ?? 20;

    // Generate new proposals from any accumulated false negatives
    if (this.falseNegatives.length > 0) {
      this.proposeRules();
    }

    // Evaluate all rules
    const evaluated: Array<ProposedRule & { fitness: RuleFitness }> = [];
    for (const rule of this.population.rules) {
      const fitness = this.evaluateFitness(rule, truePositives, trueNegatives);
      evaluated.push({ ...rule, fitness });
    }

    // Sort by F1 descending, then by false positive rate ascending
    evaluated.sort((a, b) => {
      if (a.fitness.f1 !== b.fitness.f1) return b.fitness.f1 - a.fitness.f1;
      return a.fitness.falsePositiveRate - b.fitness.falsePositiveRate;
    });

    // Select survivors: F1 > threshold, take top maxPopulation
    const survivors = evaluated
      .filter(r => r.fitness.f1 >= survivalThreshold)
      .slice(0, maxPopulation);

    this.population = {
      rules: survivors,
      generation: this.population.generation + 1,
    };

    // Clear consumed false negatives
    this.falseNegatives = [];

    return this.getPopulation();
  }

  // ---------- Export ----------

  /**
   * Export evolved rules as SecurityRule-compatible objects
   * that can be plugged into ClawGuard's security engine.
   */
  exportAsSecurityRules(): SecurityRule[] {
    return this.population.rules.map(rule => ({
      id: rule.id,
      name: `Evolved: ${rule.description}`,
      description: rule.description,
      owaspCategory: `Evolved (${rule.category})`,
      enabled: true,
      check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
        if (direction !== 'inbound') return [];
        const findings: SecurityFinding[] = [];

        try {
          const regex = new RegExp(rule.pattern, 'i');
          const match = regex.exec(content);
          if (match) {
            findings.push({
              id: crypto.randomUUID(),
              timestamp: context.timestamp,
              ruleId: rule.id,
              ruleName: `Evolved: ${rule.description}`,
              severity: rule.severity,
              category: rule.category,
              owaspCategory: `Evolved (${rule.category})`,
              description: rule.description,
              evidence: match[0].slice(0, 200),
              session: context.session,
              channel: context.channel,
              action: rule.severity === 'critical' ? 'alert' : 'log',
            });
          }
        } catch { /* invalid regex, skip */ }

        return findings;
      },
    }));
  }

  // ---------- Private Helpers ----------

  /**
   * Find common n-grams across multiple text samples.
   * Returns n-grams sorted by frequency (descending).
   * Includes unigrams if no multi-word n-grams are found in common.
   */
  private findCommonNgrams(texts: string[], minN: number = 2): string[] {
    const ngramCounts = new Map<string, number>();

    for (const text of texts) {
      const words = text.split(/\s+/).filter(w => w.length > 2);
      const seen = new Set<string>();

      for (let n = minN; n <= Math.min(4, words.length); n++) {
        for (let i = 0; i <= words.length - n; i++) {
          const ngram = words.slice(i, i + n).join(' ');
          if (!seen.has(ngram)) {
            seen.add(ngram);
            ngramCounts.set(ngram, (ngramCounts.get(ngram) || 0) + 1);
          }
        }
      }

      // Also record unigrams (single words) as fallback
      for (const word of words) {
        const key = `__unigram__${word}`;
        if (!seen.has(key)) {
          seen.add(key);
          ngramCounts.set(key, (ngramCounts.get(key) || 0) + 1);
        }
      }
    }

    // Keep n-grams that appear in at least 2 texts (or all if only 1 text)
    const minAppearances = texts.length === 1 ? 1 : 2;

    // Prefer multi-word n-grams first
    const multiWord = [...ngramCounts.entries()]
      .filter(([key, count]) => !key.startsWith('__unigram__') && count >= minAppearances)
      .sort((a, b) => {
        if (a[1] !== b[1]) return b[1] - a[1];
        return b[0].length - a[0].length;
      })
      .map(([ngram]) => ngram);

    if (multiWord.length > 0) return multiWord;

    // Fallback: use unigrams (security-relevant words only)
    const securityWords = new Set([
      'bypass', 'override', 'ignore', 'disregard', 'circumvent',
      'exfiltrate', 'hack', 'inject', 'exploit', 'execute',
      'delete', 'remove', 'destroy', 'compromise', 'steal',
      'restrictions', 'safety', 'security', 'credentials', 'secrets',
      'override', 'escalate', 'privilege', 'sudo', 'admin',
    ]);

    const unigrams = [...ngramCounts.entries()]
      .filter(([key, count]) =>
        key.startsWith('__unigram__') &&
        count >= minAppearances &&
        securityWords.has(key.replace('__unigram__', ''))
      )
      .sort((a, b) => b[1] - a[1])
      .map(([key]) => key.replace('__unigram__', ''));

    return unigrams;
  }

  /**
   * Extract key security-relevant phrases from text.
   */
  private extractKeyPhrases(text: string): string[] {
    const securityKeywords = [
      'override', 'bypass', 'ignore', 'disregard', 'circumvent',
      'exfiltrate', 'export', 'reveal', 'expose', 'leak',
      'system prompt', 'safety', 'restriction', 'credential',
      'password', 'secret', 'private key', 'token',
      'inject', 'execute', 'delete', 'remove',
    ];

    const words = text.split(/\s+/);
    const phrases: string[] = [];

    for (let i = 0; i < words.length; i++) {
      for (const keyword of securityKeywords) {
        const kwWords = keyword.split(/\s+/);
        const windowEnd = Math.min(i + kwWords.length + 2, words.length);
        const window = words.slice(i, windowEnd).join(' ');

        if (window.toLowerCase().includes(keyword)) {
          // Extract a phrase around the keyword (2-4 words)
          const start = Math.max(0, i);
          const end = Math.min(words.length, i + 4);
          const phrase = words.slice(start, end).join(' ');
          if (phrase.length > 5) {
            phrases.push(phrase);
          }
          break;
        }
      }
    }

    // Deduplicate
    return [...new Set(phrases)];
  }

  private escapeRegex(str: string): string {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}
