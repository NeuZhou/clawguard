// Carapace — Dashboard Hook
// HTTP server with REST API and SSE

import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { store } from '../../src/store';
import { getSecurityScore, getRuleStatuses } from '../../src/security-engine';
import { verifyChain } from '../../src/integrity';
import { getAllModelPricing } from '../../src/cost-engine';
import { WatchMessage, SecurityFinding, OverviewStats, CostBreakdown } from '../../src/types';

let server: http.Server | null = null;
const sseClients: Set<http.ServerResponse> = new Set();

// SSE broadcast
export function broadcastSSE(eventType: string, data: unknown): void {
  const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const client of sseClients) {
    try { client.write(payload); } catch { sseClients.delete(client); }
  }
}

function getOverview(): OverviewStats {
  const sessions = store.getAllSessions();
  const activeSessions = sessions.filter(s => Date.now() - s.lastActivityAt < 300_000);
  const costToday = store.getCostToday();
  const alertCount = store.getSecurityAlertCount();
  const allMessages = store.getMessages(10000, 0);

  // Build 24h sparkline (24 buckets)
  const now = Date.now();
  const buckets = new Array(24).fill(0);
  for (const msg of allMessages) {
    const hoursAgo = (now - msg.timestamp) / 3_600_000;
    if (hoursAgo < 24) {
      const bucket = 23 - Math.floor(hoursAgo);
      buckets[bucket]++;
    }
  }

  let health: 'healthy' | 'warnings' | 'critical' = 'healthy';
  const recentFindings = store.getRecentFindings(10);
  if (recentFindings.some(f => f.severity === 'critical' && Date.now() - f.timestamp < 3_600_000)) health = 'critical';
  else if (recentFindings.some(f => f.severity === 'high' && Date.now() - f.timestamp < 3_600_000)) health = 'warnings';

  return {
    totalMessages: allMessages.length,
    activeSessions: activeSessions.length,
    costToday,
    securityAlerts: alertCount,
    uptimeMs: Date.now() - (globalStartupTime || Date.now()),
    health,
    recentActivity: buckets,
  };
}

function getCostBreakdown(): CostBreakdown {
  const messages = store.getMessages(10000, 0);
  const now = new Date();
  const dayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  const weekStart = dayStart - (now.getDay() * 86_400_000);
  const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).getTime();

  let daily = 0, weekly = 0, monthly = 0;
  const byModel: Record<string, number> = {};
  const bySession: Record<string, number> = {};

  for (const msg of messages) {
    if (msg.timestamp >= dayStart) daily += msg.estimatedCostUsd;
    if (msg.timestamp >= weekStart) weekly += msg.estimatedCostUsd;
    if (msg.timestamp >= monthStart) monthly += msg.estimatedCostUsd;

    const model = msg.model || 'unknown';
    byModel[model] = (byModel[model] || 0) + msg.estimatedCostUsd;
    bySession[msg.session] = (bySession[msg.session] || 0) + msg.estimatedCostUsd;
  }

  // Projection: extrapolate daily rate to full month
  const daysThisMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0).getDate();
  const dayOfMonth = now.getDate();
  const projection = dayOfMonth > 0 ? (monthly / dayOfMonth) * daysThisMonth : 0;

  return { daily, weekly, monthly, byModel, bySession, projection };
}

function jsonResponse(res: http.ServerResponse, data: unknown, status = 200): void {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
  res.end(JSON.stringify(data));
}

function handleApi(req: http.IncomingMessage, res: http.ServerResponse): boolean {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const p = url.pathname;
  const method = req.method || 'GET';

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return true;
  }

  if (!p.startsWith('/api/')) return false;

  switch (p) {
    case '/api/overview':
      jsonResponse(res, getOverview());
      return true;

    case '/api/messages': {
      const limit = parseInt(url.searchParams.get('limit') || '50');
      const offset = parseInt(url.searchParams.get('offset') || '0');
      const session = url.searchParams.get('session') || undefined;
      jsonResponse(res, store.getMessages(limit, offset, session));
      return true;
    }

    case '/api/sessions':
      jsonResponse(res, store.getAllSessions());
      return true;

    case '/api/security':
      jsonResponse(res, store.getFindings(200));
      return true;

    case '/api/security/score':
      jsonResponse(res, { score: getSecurityScore(), rules: getRuleStatuses() });
      return true;

    case '/api/cost':
      jsonResponse(res, getCostBreakdown());
      return true;

    case '/api/cost/projection':
      jsonResponse(res, { projection: getCostBreakdown().projection });
      return true;

    case '/api/audit':
      jsonResponse(res, store.getAuditLog(200));
      return true;

    case '/api/audit/verify':
      jsonResponse(res, verifyChain());
      return true;

    case '/api/rules':
      jsonResponse(res, getRuleStatuses());
      return true;

    case '/api/rules/toggle': {
      if (method !== 'POST') { jsonResponse(res, { error: 'POST required' }, 405); return true; }
      let body = '';
      req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
      req.on('end', () => {
        try {
          const { ruleId, enabled } = JSON.parse(body);
          const config = store.getConfig();
          if (enabled && !config.security.enabledRules.includes(ruleId)) {
            config.security.enabledRules.push(ruleId);
          } else if (!enabled) {
            config.security.enabledRules = config.security.enabledRules.filter((r: string) => r !== ruleId);
          }
          store.setConfig(config);
          jsonResponse(res, { ok: true, enabledRules: config.security.enabledRules });
        } catch { jsonResponse(res, { error: 'Invalid JSON' }, 400); }
      });
      return true;
    }

    case '/api/config': {
      if (method === 'GET') {
        jsonResponse(res, store.getConfig());
        return true;
      }
      if (method === 'POST') {
        let body = '';
        req.on('data', (chunk: Buffer) => { body += chunk.toString(); });
        req.on('end', () => {
          try {
            const partial = JSON.parse(body);
            jsonResponse(res, store.updateConfig(partial));
          } catch { jsonResponse(res, { error: 'Invalid JSON' }, 400); }
        });
        return true;
      }
      jsonResponse(res, { error: 'Method not allowed' }, 405);
      return true;
    }

    case '/api/stream': {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
      });
      res.write(`event: connected\ndata: ${JSON.stringify({ time: Date.now() })}\n\n`);
      sseClients.add(res);
      req.on('close', () => { sseClients.delete(res); });
      return true;
    }

    case '/api/models':
      jsonResponse(res, getAllModelPricing());
      return true;

    default:
      // Export endpoints
      if (p.startsWith('/api/export/')) {
        const format = p.split('/').pop();
        if (format === 'json') {
          const data = {
            messages: store.getMessages(10000, 0),
            sessions: store.getAllSessions(),
            security: store.getFindings(10000),
            audit: store.getAuditLog(10000),
          };
          res.writeHead(200, {
            'Content-Type': 'application/json',
            'Content-Disposition': 'attachment; filename="carapace-export.json"',
          });
          res.end(JSON.stringify(data, null, 2));
          return true;
        }
        if (format === 'csv') {
          const messages = store.getMessages(10000, 0);
          const header = 'timestamp,direction,session,channel,tokens,cost_usd,model\n';
          const rows = messages.map((m: WatchMessage) =>
            `${new Date(m.timestamp).toISOString()},${m.direction},${m.session},${m.channel},${m.estimatedTokens},${m.estimatedCostUsd.toFixed(6)},${m.model || ''}`
          ).join('\n');
          res.writeHead(200, {
            'Content-Type': 'text/csv',
            'Content-Disposition': 'attachment; filename="carapace-messages.csv"',
          });
          res.end(header + rows);
          return true;
        }
      }
      jsonResponse(res, { error: 'Not found' }, 404);
      return true;
  }
}

let globalStartupTime = 0;

interface HookEvent {
  type?: string;
}

export default function handler(event: HookEvent): void {
  if (event.type !== 'gateway:startup') return;
  globalStartupTime = Date.now();

  const config = store.getConfig();
  if (!config.dashboard.enabled) return;

  const port = config.dashboard.port;
  const publicDir = path.join(__dirname, 'public');

  server = http.createServer((req, res) => {
    // API routes
    if (handleApi(req, res)) return;

    // Serve static files
    const urlPath = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`).pathname;
    const filePath = urlPath === '/' ? path.join(publicDir, 'index.html') : path.join(publicDir, urlPath);

    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath);
      const contentTypes: Record<string, string> = {
        '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
        '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png',
      };
      res.writeHead(200, { 'Content-Type': contentTypes[ext] || 'application/octet-stream' });
      fs.createReadStream(filePath).pipe(res);
    } else {
      // SPA fallback
      const indexPath = path.join(publicDir, 'index.html');
      if (fs.existsSync(indexPath)) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        fs.createReadStream(indexPath).pipe(res);
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    }
  });

  server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      console.warn(`[Carapace] Dashboard port ${port} is in use. Dashboard disabled.`);
    } else {
      console.warn(`[Carapace] Dashboard error: ${err.message}`);
    }
  });

  server.listen(port, () => {
    console.log(`[Carapace] Dashboard: http://localhost:${port}`);
  });
}

