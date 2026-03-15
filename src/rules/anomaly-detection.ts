// OpenClaw Watch — Security Rule: Anomaly Detection

import { SecurityFinding, SecurityRule, Direction, RuleContext } from '../types';
import * as crypto from 'crypto';

export const anomalyDetectionRule: SecurityRule = {
  id: 'anomaly-detection',
  name: 'Anomaly Detection',
  description: 'Detects behavioral anomalies: rapid-fire messages, cost spikes, loops, token bombs, marathons',
  owaspCategory: 'LLM02: Insecure Output / Operational',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const now = context.timestamp;

    // Rapid-fire: >10 messages in 60 seconds from same channel
    const recentInbound = context.recentMessages.filter(
      m => m.direction === 'inbound' && m.channel === context.channel && now - m.timestamp < 60_000
    );
    if (recentInbound.length > 10) {
      findings.push({
        id: crypto.randomUUID(), timestamp: now,
        ruleId: 'anomaly-detection', ruleName: 'Anomaly Detection',
        severity: 'warning', category: 'anomaly', owaspCategory: 'Operational',
        description: `Rapid-fire: ${recentInbound.length} inbound messages in 60s`,
        session: context.session, channel: context.channel, action: 'alert',
      });
    }

    // Token bomb: single message >50,000 estimated tokens
    const estimatedTokens = Math.ceil(content.length / 4);
    if (estimatedTokens > 50_000) {
      findings.push({
        id: crypto.randomUUID(), timestamp: now,
        ruleId: 'anomaly-detection', ruleName: 'Anomaly Detection',
        severity: 'high', category: 'anomaly', owaspCategory: 'LLM01',
        description: `Token bomb: ~${estimatedTokens} tokens in single message`,
        session: context.session, channel: context.channel, action: 'alert',
      });
    }

    // Loop detection: repeated similar content >5 times in 2 minutes
    const twoMinAgo = now - 120_000;
    const recentSent = context.recentMessages.filter(
      m => m.direction === direction && m.timestamp > twoMinAgo
    );
    const contentSig = content.slice(0, 100);
    const similar = recentSent.filter(m => m.content.slice(0, 100) === contentSig);
    if (similar.length > 5) {
      findings.push({
        id: crypto.randomUUID(), timestamp: now,
        ruleId: 'anomaly-detection', ruleName: 'Anomaly Detection',
        severity: 'high', category: 'anomaly', owaspCategory: 'Operational',
        description: `Loop detected: ${similar.length} similar messages in 2 minutes`,
        session: context.session, channel: context.channel, action: 'alert',
      });
    }

    // Session marathon: >4 hours continuous activity
    if (context.sessionInfo && now - context.sessionInfo.startedAt > 4 * 3600_000) {
      const hours = ((now - context.sessionInfo.startedAt) / 3600_000).toFixed(1);
      findings.push({
        id: crypto.randomUUID(), timestamp: now,
        ruleId: 'anomaly-detection', ruleName: 'Anomaly Detection',
        severity: 'info', category: 'anomaly', owaspCategory: 'Operational',
        description: `Session marathon: active for ${hours} hours`,
        session: context.session, channel: context.channel, action: 'log',
      });
    }

    // Cost spike: session cost >$5 in recent window
    if (context.sessionInfo && context.sessionInfo.estimatedCostUsd > 5) {
      findings.push({
        id: crypto.randomUUID(), timestamp: now,
        ruleId: 'anomaly-detection', ruleName: 'Anomaly Detection',
        severity: 'warning', category: 'anomaly', owaspCategory: 'Operational',
        description: `Cost spike: session cost $${context.sessionInfo.estimatedCostUsd.toFixed(2)}`,
        session: context.session, channel: context.channel, action: 'alert',
      });
    }

    // Sub-agent cascade detection: look for spawn patterns in recent messages
    const fiveMinAgo = now - 300_000;
    const recentMsgs = context.recentMessages.filter(m => m.timestamp > fiveMinAgo);
    const spawnCount = recentMsgs.filter(m =>
      /subagent|sub-agent|spawn|child\s+agent/i.test(m.content)
    ).length;
    if (spawnCount > 5) {
      findings.push({
        id: crypto.randomUUID(), timestamp: now,
        ruleId: 'anomaly-detection', ruleName: 'Anomaly Detection',
        severity: 'high', category: 'anomaly', owaspCategory: 'Operational',
        description: `Sub-agent cascade: ${spawnCount} spawn events in 5 minutes`,
        session: context.session, channel: context.channel, action: 'alert',
      });
    }

    // Infinite retry loop: same error repeated >3 times in 2 minutes
    const twoMinMsgs = context.recentMessages.filter(
      m => m.timestamp > twoMinAgo && /error|failed|exception|retry/i.test(m.content)
    );
    if (twoMinMsgs.length > 3) {
      const errorSigs = twoMinMsgs.map(m => m.content.slice(0, 80));
      const counts: Record<string, number> = {};
      for (const sig of errorSigs) {
        counts[sig] = (counts[sig] || 0) + 1;
      }
      for (const [sig, count] of Object.entries(counts)) {
        if (count > 3) {
          findings.push({
            id: crypto.randomUUID(), timestamp: now,
            ruleId: 'anomaly-detection', ruleName: 'Anomaly Detection',
            severity: 'high', category: 'anomaly', owaspCategory: 'Operational',
            description: `Infinite retry loop: same error repeated ${count} times in 2 minutes`,
            evidence: sig.slice(0, 200),
            session: context.session, channel: context.channel, action: 'alert',
          });
        }
      }
    }

    // Recursive sub-agent spawn depth detection
    const depthMatch = /depth\s*[=:]\s*(\d+)/i.exec(content);
    if (depthMatch && parseInt(depthMatch[1], 10) > 3) {
      findings.push({
        id: crypto.randomUUID(), timestamp: now,
        ruleId: 'anomaly-detection', ruleName: 'Anomaly Detection',
        severity: 'critical', category: 'anomaly', owaspCategory: 'Operational',
        description: `Recursive sub-agent spawn: depth ${depthMatch[1]} exceeds limit of 3`,
        evidence: depthMatch[0],
        session: context.session, channel: context.channel, action: 'alert',
      });
    }

    // Disk space bomb: detect large write patterns in recent messages
    const writePatterns = recentMsgs.filter(m =>
      /(?:writing|wrote|saved|created)\s+\d+\s*(?:MB|GB|bytes)/i.test(m.content)
    );
    let totalMb = 0;
    for (const m of writePatterns) {
      const sizeMatch = /(\d+(?:\.\d+)?)\s*(MB|GB|bytes)/i.exec(m.content);
      if (sizeMatch) {
        const val = parseFloat(sizeMatch[1]);
        const unit = sizeMatch[2].toUpperCase();
        if (unit === 'GB') totalMb += val * 1024;
        else if (unit === 'MB') totalMb += val;
        else totalMb += val / (1024 * 1024);
      }
    }
    if (totalMb > 100) {
      findings.push({
        id: crypto.randomUUID(), timestamp: now,
        ruleId: 'anomaly-detection', ruleName: 'Anomaly Detection',
        severity: 'high', category: 'anomaly', owaspCategory: 'Operational',
        description: `Disk space bomb: ~${totalMb.toFixed(0)}MB written in 5 minutes`,
        session: context.session, channel: context.channel, action: 'alert',
      });
    }

    // Network flood: >50 HTTP requests in 1 minute
    const oneMinAgo = now - 60_000;
    const recentOneMin = context.recentMessages.filter(m => m.timestamp > oneMinAgo);
    const httpCount = recentOneMin.filter(m =>
      /https?:\/\/|web_fetch|curl\s|wget\s|fetch\s*\(/i.test(m.content)
    ).length;
    if (httpCount > 50) {
      findings.push({
        id: crypto.randomUUID(), timestamp: now,
        ruleId: 'anomaly-detection', ruleName: 'Anomaly Detection',
        severity: 'high', category: 'anomaly', owaspCategory: 'Operational',
        description: `Network flood: ${httpCount} HTTP requests in 1 minute`,
        session: context.session, channel: context.channel, action: 'alert',
      });
    }

    return findings;
  },
};
