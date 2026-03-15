import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { getMessages, getAlerts, getSessions, getStats } from '../../src/store.js';
import { getDashboardStats, getCostBreakdown } from '../../src/analyzer.js';
import type { HookEvent } from '../../src/types.js';

const PORT = 3001;
let serverStarted = false;
const sseClients: Set<ServerResponse> = new Set();

function getUIPath(): string {
  try {
    const __dirname = dirname(fileURLToPath(import.meta.url));
    return join(__dirname, 'ui', 'index.html');
  } catch {
    return join(process.cwd(), 'hooks', 'dashboard', 'ui', 'index.html');
  }
}

function json(res: ServerResponse, data: unknown, status = 200): void {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
  });
  res.end(JSON.stringify(data));
}

function handleRequest(req: IncomingMessage, res: ServerResponse): void {
  const url = new URL(req.url || '/', `http://localhost:${PORT}`);
  const path = url.pathname;

  // CORS
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET',
      'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end();
    return;
  }

  try {
    if (path === '/' || path === '/index.html') {
      const html = readFileSync(getUIPath(), 'utf-8');
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(html);
      return;
    }

    if (path === '/api/stats') return json(res, getDashboardStats());
    if (path === '/api/messages') {
      const limit = parseInt(url.searchParams.get('limit') || '50');
      const offset = parseInt(url.searchParams.get('offset') || '0');
      return json(res, getMessages(limit, offset));
    }
    if (path === '/api/sessions') return json(res, getSessions());
    if (path === '/api/security') return json(res, getAlerts(100));
    if (path === '/api/cost') return json(res, getCostBreakdown());

    if (path === '/api/stream') {
      res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*',
      });
      res.write('data: {"type":"connected"}\n\n');
      sseClients.add(res);
      req.on('close', () => sseClients.delete(res));
      return;
    }

    res.writeHead(404);
    res.end('Not Found');
  } catch (err) {
    console.error('[openclaw-watch/dashboard]', err);
    res.writeHead(500);
    res.end('Internal Server Error');
  }
}

// Broadcast updates to SSE clients every 5s
function startBroadcast(): void {
  setInterval(() => {
    if (sseClients.size === 0) return;
    const data = JSON.stringify({ type: 'update', stats: getDashboardStats() });
    for (const client of sseClients) {
      try {
        client.write(`data: ${data}\n\n`);
      } catch {
        sseClients.delete(client);
      }
    }
  }, 5000).unref();
}

const handler = async (_event: HookEvent) => {
  if (serverStarted) return;
  serverStarted = true;

  try {
    const server = createServer(handleRequest);

    server.on('error', (err: NodeJS.ErrnoException) => {
      if (err.code === 'EADDRINUSE') {
        console.warn(`[openclaw-watch] Dashboard port ${PORT} is already in use. Dashboard disabled.`);
      } else {
        console.error('[openclaw-watch] Dashboard server error:', err);
      }
    });

    server.listen(PORT, () => {
      console.log(`[openclaw-watch] 📊 Dashboard running at http://localhost:${PORT}`);
      startBroadcast();
    });

    if (server.unref) server.unref();
  } catch (err) {
    console.error('[openclaw-watch] Failed to start dashboard:', err);
  }
};

export default handler;
