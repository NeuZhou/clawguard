// ClawGuard — Runtime Protection Tests
// Tests for AnomalyDetector, CostTracker, and Dashboard Generator

import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import { AnomalyDetector, ToolCall } from '../src/anomaly-detector';
import { CostTracker } from '../src/cost-tracker';
import { generateDashboard, DashboardData, writeDashboard, loadDashboardData } from '../src/dashboard';

// ========================
// Anomaly Detector Tests
// ========================

describe('AnomalyDetector', () => {
  let detector: AnomalyDetector;

  beforeEach(() => {
    detector = new AnomalyDetector({ windowMs: 60_000, anomalyThreshold: 30 });
  });

  it('should start untrained', () => {
    assert.equal(detector.isTrained, false);
  });

  it('should train on normal traces', () => {
    const traces: ToolCall[][] = [
      [
        { tool: 'read', timestamp: 1000 },
        { tool: 'edit', timestamp: 2000 },
        { tool: 'exec', timestamp: 3000 },
      ],
    ];
    detector.train(traces);
    assert.equal(detector.isTrained, true);
    assert.deepEqual(detector.getKnownTools().sort(), ['edit', 'exec', 'read']);
  });

  it('should detect unknown tools', () => {
    detector.train([[{ tool: 'read', timestamp: 1000 }, { tool: 'edit', timestamp: 2000 }]]);
    const result = detector.detect({ tool: 'dangerous_tool', timestamp: 3000 });
    assert.ok(result.reasons.some(r => r.type === 'unknown_tool'));
    assert.ok(result.score > 0);
  });

  it('should not flag known tools', () => {
    detector.train([[{ tool: 'read', timestamp: 1000 }, { tool: 'edit', timestamp: 2000 }]]);
    const result = detector.detect({ tool: 'read', timestamp: 3000 });
    assert.ok(!result.reasons.some(r => r.type === 'unknown_tool'));
  });

  it('should detect unusual sequences', () => {
    detector.train([
      [{ tool: 'read', timestamp: 1000 }, { tool: 'edit', timestamp: 2000 }, { tool: 'exec', timestamp: 3000 }],
    ]);
    // First call sets up recent history
    detector.detect({ tool: 'exec', timestamp: 4000 });
    // exec → read was never seen (only read→edit, edit→exec)
    const result = detector.detect({ tool: 'read', timestamp: 5000 });
    assert.ok(result.reasons.some(r => r.type === 'unusual_sequence'));
  });

  it('should not flag normal sequences', () => {
    detector.train([
      [{ tool: 'read', timestamp: 1000 }, { tool: 'edit', timestamp: 2000 }],
    ]);
    detector.detect({ tool: 'read', timestamp: 3000 });
    const result = detector.detect({ tool: 'edit', timestamp: 4000 });
    assert.ok(!result.reasons.some(r => r.type === 'unusual_sequence'));
  });

  it('should detect burst activity', () => {
    const now = Date.now();
    for (let i = 0; i < 16; i++) {
      detector.detect({ tool: 'exec', timestamp: now + i * 100 });
    }
    const result = detector.detect({ tool: 'exec', timestamp: now + 1700 });
    assert.ok(result.reasons.some(r => r.type === 'burst_detected'));
  });

  it('should return score 0 for normal behavior without training', () => {
    const result = detector.detect({ tool: 'read', timestamp: Date.now() });
    assert.equal(result.score, 0);
    assert.equal(result.anomalous, false);
  });

  it('should reset runtime state', () => {
    detector.detect({ tool: 'read', timestamp: Date.now() });
    detector.reset();
    // After reset, no recent calls
    const result = detector.detect({ tool: 'read', timestamp: Date.now() });
    assert.ok(!result.reasons.some(r => r.type === 'unusual_sequence'));
  });

  it('should detect time anomalies with sufficient training data', () => {
    const traces: ToolCall[][] = [];
    for (let i = 0; i < 5; i++) {
      traces.push([{ tool: 'read', timestamp: i * 1000 }]);
    }
    detector.train(traces);
    // 3 AM timestamp
    const ts = new Date();
    ts.setHours(3, 0, 0, 0);
    const result = detector.detect({ tool: 'read', timestamp: ts.getTime() });
    assert.ok(result.reasons.some(r => r.type === 'time_anomaly'));
  });

  it('should handle empty training data', () => {
    detector.train([]);
    assert.equal(detector.isTrained, true);
    assert.deepEqual(detector.getKnownTools(), []);
  });

  it('should handle multiple anomaly types at once', () => {
    detector.train([
      [{ tool: 'read', timestamp: 1000 }, { tool: 'edit', timestamp: 2000 }],
      [{ tool: 'read', timestamp: 1000 }, { tool: 'edit', timestamp: 2000 }],
      [{ tool: 'read', timestamp: 1000 }, { tool: 'edit', timestamp: 2000 }],
      [{ tool: 'read', timestamp: 1000 }, { tool: 'edit', timestamp: 2000 }],
      [{ tool: 'read', timestamp: 1000 }, { tool: 'edit', timestamp: 2000 }],
    ]);
    // Unknown tool at unusual time
    const ts = new Date();
    ts.setHours(3, 0, 0, 0);
    detector.detect({ tool: 'read', timestamp: ts.getTime() - 1000 });
    const result = detector.detect({ tool: 'malware', timestamp: ts.getTime() });
    assert.ok(result.reasons.length >= 2);
    assert.ok(result.anomalous);
  });

  it('should cap score at 100', () => {
    detector.train([
      [{ tool: 'a', timestamp: 100 }, { tool: 'b', timestamp: 200 }],
      [{ tool: 'a', timestamp: 100 }, { tool: 'b', timestamp: 200 }],
      [{ tool: 'a', timestamp: 100 }, { tool: 'b', timestamp: 200 }],
      [{ tool: 'a', timestamp: 100 }, { tool: 'b', timestamp: 200 }],
      [{ tool: 'a', timestamp: 100 }, { tool: 'b', timestamp: 200 }],
    ]);
    const ts = new Date();
    ts.setHours(3, 0, 0, 0);
    const now = ts.getTime();
    // Generate burst of unknown tools
    for (let i = 0; i < 20; i++) {
      detector.detect({ tool: 'evil' + i, timestamp: now + i * 100 });
    }
    const result = detector.detect({ tool: 'evil99', timestamp: now + 2100 });
    assert.ok(result.score <= 100);
  });
});

// ========================
// Cost Tracker Tests
// ========================

describe('CostTracker', () => {
  let tracker: CostTracker;

  beforeEach(() => {
    tracker = new CostTracker('agent-1');
  });

  it('should track a call and return cost', () => {
    const cost = tracker.trackCall({ model: 'gpt-4o', tokens: 1_000_000 });
    // gpt-4o output rate: $10/1M tokens
    assert.equal(cost, 10.0);
    assert.equal(tracker.size, 1);
  });

  it('should track input cost correctly', () => {
    const cost = tracker.trackCall({ model: 'gpt-4o', tokens: 1_000_000, direction: 'inbound' });
    // gpt-4o input rate: $2.50/1M tokens
    assert.equal(cost, 2.5);
  });

  it('should set and check budgets', () => {
    tracker.setBudget('agent-1', 5.0);
    tracker.trackCall({ model: 'gpt-4o', tokens: 100_000, agentId: 'agent-1' });
    assert.equal(tracker.isOverBudget('agent-1'), false);
    const budget = tracker.getBudget('agent-1');
    assert.equal(budget.limit, 5.0);
    assert.ok(budget.remaining > 0);
    assert.ok(budget.utilization < 1);
  });

  it('should detect over-budget agents', () => {
    tracker.setBudget('agent-1', 0.001);
    tracker.trackCall({ model: 'gpt-4o', tokens: 1_000_000, agentId: 'agent-1' });
    assert.equal(tracker.isOverBudget('agent-1'), true);
  });

  it('should return false for over-budget when no budget set', () => {
    tracker.trackCall({ model: 'gpt-4o', tokens: 1_000_000, agentId: 'agent-1' });
    assert.equal(tracker.isOverBudget('agent-1'), false);
  });

  it('should generate a report', () => {
    tracker.trackCall({ model: 'gpt-4o', tokens: 1000, agentId: 'a1' });
    tracker.trackCall({ model: 'claude-sonnet-4', tokens: 2000, agentId: 'a2' });
    const report = tracker.getReport();
    assert.ok(report.totalSpent > 0);
    assert.ok(report.totalTokens === 3000);
    assert.ok('gpt-4o' in report.byModel);
    assert.ok('claude-sonnet-4' in report.byModel);
    assert.ok('a1' in report.byAgent);
    assert.ok('a2' in report.byAgent);
  });

  it('should report over-budget agents', () => {
    tracker.setBudget('a1', 0.0001);
    tracker.trackCall({ model: 'gpt-4o', tokens: 1_000_000, agentId: 'a1' });
    const report = tracker.getReport();
    assert.ok(report.overBudgetAgents.includes('a1'));
  });

  it('should report top expensive agents', () => {
    tracker.trackCall({ model: 'gpt-4o', tokens: 1_000_000, agentId: 'big-spender' });
    tracker.trackCall({ model: 'gpt-4o-mini', tokens: 100, agentId: 'frugal' });
    const report = tracker.getReport();
    assert.equal(report.topExpensive[0].agentId, 'big-spender');
  });

  it('should track by hour', () => {
    tracker.trackCall({ model: 'gpt-4o', tokens: 1000, timestamp: new Date('2025-01-01T10:00:00Z').getTime() });
    tracker.trackCall({ model: 'gpt-4o', tokens: 1000, timestamp: new Date('2025-01-01T10:30:00Z').getTime() });
    const report = tracker.getReport();
    assert.ok('2025-01-01T10' in report.byHour);
  });

  it('should clear tracked data', () => {
    tracker.trackCall({ model: 'gpt-4o', tokens: 1000 });
    tracker.clear();
    assert.equal(tracker.size, 0);
    assert.equal(tracker.getReport().totalSpent, 0);
  });

  it('should handle GitHub Copilot models as free', () => {
    const cost = tracker.trackCall({ model: 'github-copilot/claude-opus-4', tokens: 1_000_000 });
    assert.equal(cost, 0);
  });

  it('should get budget with Infinity limit when not set', () => {
    const budget = tracker.getBudget('no-budget-agent');
    assert.equal(budget.limit, Infinity);
    assert.equal(budget.utilization, 0);
  });

  it('should trackText and estimate tokens', () => {
    const cost = tracker.trackText('gpt-4o', 'Hello world, this is a test.');
    assert.ok(cost > 0);
    assert.equal(tracker.size, 1);
  });
});

// ========================
// Dashboard Generator Tests
// ========================

describe('Dashboard Generator', () => {
  it('should generate valid HTML', () => {
    const html = generateDashboard({});
    assert.ok(html.includes('<!DOCTYPE html>'));
    assert.ok(html.includes('ClawGuard Security Dashboard'));
    assert.ok(html.includes('</html>'));
  });

  it('should include finding counts', () => {
    const data: DashboardData = {
      findings: [
        { id: '1', timestamp: Date.now(), ruleId: 'test', ruleName: 'Test', severity: 'critical', category: 'test', description: 'Bad thing', action: 'block', confidence: 1 },
        { id: '2', timestamp: Date.now(), ruleId: 'test', ruleName: 'Test', severity: 'high', category: 'test', description: 'Less bad', action: 'alert', confidence: 0.8 },
      ],
    };
    const html = generateDashboard(data);
    assert.ok(html.includes('>1</div>')); // critical count
    assert.ok(html.includes('Bad thing'));
  });

  it('should include cost data', () => {
    const data: DashboardData = {
      costs: [
        { model: 'gpt-4o', tokens: 1000, cost: 0.01, agentId: 'a1', timestamp: Date.now() },
      ],
    };
    const html = generateDashboard(data);
    assert.ok(html.includes('$0.01'));
    assert.ok(html.includes('gpt-4o'));
  });

  it('should include anomaly data', () => {
    const data: DashboardData = {
      anomalies: [
        { tool: 'exec', score: 75, reasons: ['Unknown tool'], timestamp: Date.now() },
      ],
    };
    const html = generateDashboard(data);
    assert.ok(html.includes('exec'));
    assert.ok(html.includes('75'));
  });

  it('should escape HTML in data', () => {
    const data: DashboardData = {
      findings: [
        { id: '1', timestamp: Date.now(), ruleId: '<script>', ruleName: 'XSS', severity: 'critical', category: 'test', description: '<img onerror=alert(1)>', action: 'block', confidence: 1 },
      ],
    };
    const html = generateDashboard(data);
    assert.ok(!html.includes('<script>'));
    assert.ok(html.includes('&lt;script&gt;'));
  });

  it('should write dashboard to file', () => {
    const tmpFile = path.join(process.cwd(), '_test_dashboard.html');
    try {
      writeDashboard({}, tmpFile);
      assert.ok(fs.existsSync(tmpFile));
      const content = fs.readFileSync(tmpFile, 'utf-8');
      assert.ok(content.includes('ClawGuard'));
    } finally {
      if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
    }
  });

  it('should load and generate from JSON file', () => {
    const tmpData = path.join(process.cwd(), '_test_data.json');
    const tmpOut = path.join(process.cwd(), '_test_out.html');
    try {
      const data: DashboardData = { findings: [], costs: [], anomalies: [] };
      fs.writeFileSync(tmpData, JSON.stringify(data));
      const loaded = loadDashboardData(tmpData);
      writeDashboard(loaded, tmpOut);
      assert.ok(fs.existsSync(tmpOut));
    } finally {
      if (fs.existsSync(tmpData)) fs.unlinkSync(tmpData);
      if (fs.existsSync(tmpOut)) fs.unlinkSync(tmpOut);
    }
  });

  it('should handle empty data gracefully', () => {
    const html = generateDashboard({ findings: [], costs: [], anomalies: [], auditEvents: [] });
    assert.ok(html.includes('No findings'));
    assert.ok(html.includes('No anomalies'));
    assert.ok(html.includes('No cost data'));
  });
});
