import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { MessageRecord, SecurityAlert, SessionEvent, StoreData } from './types.js';

const DATA_DIR = join(homedir(), '.openclaw', 'openclaw-watch');
const DATA_FILE = join(DATA_DIR, 'data.json');
const RETENTION_MS = 7 * 24 * 3600_000; // 7 days
const FLUSH_INTERVAL = 10_000; // 10 seconds

let data: StoreData = {
  messages: [],
  securityAlerts: [],
  sessionEvents: [],
  stats: {
    totalMessages: 0,
    totalTokensEstimated: 0,
    totalAlerts: 0,
    firstSeen: Date.now(),
    lastActivity: Date.now(),
    pendingResponses: {},
  },
};

let dirty = false;
let flushTimer: ReturnType<typeof setInterval> | null = null;

function ensureDir(): void {
  if (!existsSync(DATA_DIR)) {
    mkdirSync(DATA_DIR, { recursive: true });
  }
}

function load(): void {
  ensureDir();
  if (existsSync(DATA_FILE)) {
    try {
      const raw = readFileSync(DATA_FILE, 'utf-8');
      const parsed = JSON.parse(raw);
      data = {
        messages: parsed.messages || [],
        securityAlerts: parsed.securityAlerts || [],
        sessionEvents: parsed.sessionEvents || [],
        stats: {
          totalMessages: parsed.stats?.totalMessages || 0,
          totalTokensEstimated: parsed.stats?.totalTokensEstimated || 0,
          totalAlerts: parsed.stats?.totalAlerts || 0,
          firstSeen: parsed.stats?.firstSeen || Date.now(),
          lastActivity: parsed.stats?.lastActivity || Date.now(),
          pendingResponses: parsed.stats?.pendingResponses || {},
        },
      };
    } catch {
      // Corrupted file, start fresh
    }
  }
}

function flush(): void {
  if (!dirty) return;
  try {
    ensureDir();
    writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf-8');
    dirty = false;
  } catch (err) {
    console.error('[openclaw-watch] Failed to flush data:', err);
  }
}

function cleanup(): void {
  const cutoff = Date.now() - RETENTION_MS;
  data.messages = data.messages.filter((m) => m.timestamp > cutoff);
  data.securityAlerts = data.securityAlerts.filter((a) => a.timestamp > cutoff);
  data.sessionEvents = data.sessionEvents.filter((e) => e.timestamp > cutoff);
  dirty = true;
}

export function init(): void {
  load();
  cleanup();
  flush();
  if (!flushTimer) {
    flushTimer = setInterval(() => {
      cleanup();
      flush();
    }, FLUSH_INTERVAL);
    if (flushTimer.unref) flushTimer.unref();
  }
}

export function addMessage(msg: MessageRecord): void {
  data.messages.push(msg);
  data.stats.totalMessages++;
  data.stats.totalTokensEstimated += msg.estimatedTokens;
  data.stats.lastActivity = Date.now();
  dirty = true;
}

export function addAlert(alert: SecurityAlert): void {
  data.securityAlerts.push(alert);
  data.stats.totalAlerts++;
  dirty = true;
}

export function addSessionEvent(evt: SessionEvent): void {
  data.sessionEvents.push(evt);
  dirty = true;
}

export function setPendingResponse(sessionKey: string, ts: number): void {
  (data.stats.pendingResponses as Record<string, number>)[sessionKey] = ts;
  dirty = true;
}

export function getPendingResponse(sessionKey: string): number | undefined {
  return (data.stats.pendingResponses as Record<string, number>)[sessionKey];
}

export function clearPendingResponse(sessionKey: string): void {
  delete (data.stats.pendingResponses as Record<string, number>)[sessionKey];
  dirty = true;
}

export function getMessages(limit = 50, offset = 0): MessageRecord[] {
  const sorted = [...data.messages].sort((a, b) => b.timestamp - a.timestamp);
  return sorted.slice(offset, offset + limit);
}

export function getAlerts(limit = 50): SecurityAlert[] {
  return [...data.securityAlerts].sort((a, b) => b.timestamp - a.timestamp).slice(0, limit);
}

export function getSessions(): Record<string, { messageCount: number; lastActivity: number }> {
  const sessions: Record<string, { messageCount: number; lastActivity: number }> = {};
  for (const msg of data.messages) {
    if (!sessions[msg.sessionKey]) {
      sessions[msg.sessionKey] = { messageCount: 0, lastActivity: 0 };
    }
    sessions[msg.sessionKey].messageCount++;
    sessions[msg.sessionKey].lastActivity = Math.max(sessions[msg.sessionKey].lastActivity, msg.timestamp);
  }
  return sessions;
}

export function getStats() {
  return { ...data.stats };
}

export function getRawData(): StoreData {
  return data;
}

export function forceFlush(): void {
  dirty = true;
  flush();
}

// Initialize on import
init();
