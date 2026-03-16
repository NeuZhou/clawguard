// ClawGuard — Dashboard Generator
// Generate a self-contained HTML security dashboard from audit/cost/anomaly data

import * as fs from 'fs';
import { AuditEvent, SecurityFinding } from './types';

export interface DashboardData {
  auditEvents?: AuditEvent[];
  findings?: SecurityFinding[];
  costs?: { model: string; tokens: number; cost: number; agentId: string; timestamp: number }[];
  anomalies?: { tool: string; score: number; reasons: string[]; timestamp: number }[];
  generatedAt?: number;
}

export function generateDashboard(data: DashboardData): string {
  const now = data.generatedAt ?? Date.now();
  const findings = data.findings ?? [];
  const costs = data.costs ?? [];
  const anomalies = data.anomalies ?? [];
  const auditEvents = data.auditEvents ?? [];

  // Compute stats
  const totalFindings = findings.length;
  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const highCount = findings.filter(f => f.severity === 'high').length;
  const warningCount = findings.filter(f => f.severity === 'warning').length;
  const blockedCount = findings.filter(f => f.action === 'block').length;
  const totalCost = costs.reduce((s, c) => s + c.cost, 0);
  const totalAnomalies = anomalies.length;
  const totalAuditEvents = auditEvents.length;

  // Cost by model
  const costByModel: Record<string, number> = {};
  for (const c of costs) {
    costByModel[c.model] = (costByModel[c.model] || 0) + c.cost;
  }

  // Findings by category
  const findingsByCategory: Record<string, number> = {};
  for (const f of findings) {
    findingsByCategory[f.category] = (findingsByCategory[f.category] || 0) + 1;
  }

  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  const findingsRows = findings.slice(0, 50).map(f => {
    const icon = f.severity === 'critical' ? '🔴' : f.severity === 'high' ? '🟠' : f.severity === 'warning' ? '🟡' : '🔵';
    return `<tr><td>${icon} ${esc(f.severity)}</td><td>${esc(f.ruleId)}</td><td>${esc(f.description)}</td><td>${esc(f.action)}</td></tr>`;
  }).join('\n');

  const anomalyRows = anomalies.slice(0, 30).map(a =>
    `<tr><td>${esc(a.tool)}</td><td>${a.score}</td><td>${esc(a.reasons.join('; '))}</td><td>${new Date(a.timestamp).toISOString()}</td></tr>`
  ).join('\n');

  const costModelRows = Object.entries(costByModel)
    .sort((a, b) => b[1] - a[1])
    .map(([model, cost]) => `<tr><td>${esc(model)}</td><td>$${cost.toFixed(4)}</td></tr>`)
    .join('\n');

  const categoryRows = Object.entries(findingsByCategory)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, count]) => `<tr><td>${esc(cat)}</td><td>${count}</td></tr>`)
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>🛡️ ClawGuard Security Dashboard</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 24px; }
  h1 { color: #58a6ff; margin-bottom: 8px; }
  .subtitle { color: #8b949e; margin-bottom: 24px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 32px; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }
  .card .value { font-size: 2em; font-weight: bold; }
  .card .label { color: #8b949e; font-size: 0.9em; margin-top: 4px; }
  .card.critical .value { color: #f85149; }
  .card.high .value { color: #d29922; }
  .card.warning .value { color: #e3b341; }
  .card.cost .value { color: #3fb950; }
  .card.anomaly .value { color: #bc8cff; }
  .section { margin-bottom: 32px; }
  .section h2 { color: #58a6ff; margin-bottom: 12px; border-bottom: 1px solid #30363d; padding-bottom: 8px; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid #21262d; }
  th { background: #0d1117; color: #8b949e; font-weight: 600; }
  tr:hover { background: #1c2128; }
  .footer { color: #484f58; text-align: center; margin-top: 40px; font-size: 0.85em; }
</style>
</head>
<body>
<h1>🛡️ ClawGuard Security Dashboard</h1>
<p class="subtitle">Generated: ${new Date(now).toISOString()}</p>

<div class="cards">
  <div class="card critical"><div class="value">${criticalCount}</div><div class="label">Critical</div></div>
  <div class="card high"><div class="value">${highCount}</div><div class="label">High</div></div>
  <div class="card warning"><div class="value">${warningCount}</div><div class="label">Warnings</div></div>
  <div class="card"><div class="value">${blockedCount}</div><div class="label">Blocked</div></div>
  <div class="card anomaly"><div class="value">${totalAnomalies}</div><div class="label">Anomalies</div></div>
  <div class="card cost"><div class="value">$${totalCost.toFixed(2)}</div><div class="label">Total Cost</div></div>
  <div class="card"><div class="value">${totalAuditEvents}</div><div class="label">Audit Events</div></div>
  <div class="card"><div class="value">${totalFindings}</div><div class="label">Total Findings</div></div>
</div>

<div class="section">
<h2>📊 Findings by Category</h2>
<table><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>
${categoryRows || '<tr><td colspan="2">No findings</td></tr>'}
</tbody></table>
</div>

<div class="section">
<h2>🔍 Security Findings (Top 50)</h2>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Description</th><th>Action</th></tr></thead><tbody>
${findingsRows || '<tr><td colspan="4">No findings</td></tr>'}
</tbody></table>
</div>

<div class="section">
<h2>🔮 Anomalies</h2>
<table><thead><tr><th>Tool</th><th>Score</th><th>Reasons</th><th>Time</th></tr></thead><tbody>
${anomalyRows || '<tr><td colspan="4">No anomalies detected</td></tr>'}
</tbody></table>
</div>

<div class="section">
<h2>💰 Cost by Model</h2>
<table><thead><tr><th>Model</th><th>Cost</th></tr></thead><tbody>
${costModelRows || '<tr><td colspan="2">No cost data</td></tr>'}
</tbody></table>
</div>

<div class="footer">
  ClawGuard v1.0 — AI Agent Security & Observability Platform
</div>
</body>
</html>`;
}

/** Load dashboard data from a JSON file */
export function loadDashboardData(filePath: string): DashboardData {
  const raw = fs.readFileSync(filePath, 'utf-8');
  return JSON.parse(raw) as DashboardData;
}

/** Generate and write dashboard HTML to a file */
export function writeDashboard(data: DashboardData, outputPath: string): void {
  const html = generateDashboard(data);
  fs.writeFileSync(outputPath, html, 'utf-8');
}
