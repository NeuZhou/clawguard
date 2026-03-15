// ClawGuard — Storage Engine
// Pure JSON/JSONL file storage, zero native deps

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as zlib from 'zlib';
import {
  WatchMessage, SecurityFinding, AuditEvent, SessionInfo,
  WatchConfig, DEFAULT_CONFIG,
} from './types';

const DATA_DIR = path.join(os.homedir(), '.openclaw', 'ClawGuard');

function ensureDir(dir: string): void {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function dataPath(file: string): string {
  ensureDir(DATA_DIR);
  return path.join(DATA_DIR, file);
}

function appendJsonl(file: string, record: unknown): void {
  const p = dataPath(file);
  try {
    fs.appendFileSync(p, JSON.stringify(record) + '\n');
  } catch {
    // retry once
    try { fs.appendFileSync(p, JSON.stringify(record) + '\n'); } catch { /* give up */ }
  }
}

function readJsonl<T>(file: string, limit = 500, offset = 0): T[] {
  const p = dataPath(file);
  if (!fs.existsSync(p)) return [];
  try {
    const lines = fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean);
    const start = Math.max(0, offset);
    return lines.slice(start, start + limit).map(l => JSON.parse(l) as T);
  } catch {
    return [];
  }
}

function readJsonlAll<T>(file: string): T[] {
  const p = dataPath(file);
  if (!fs.existsSync(p)) return [];
  try {
    return fs.readFileSync(p, 'utf-8').split('\n').filter(Boolean).map(l => JSON.parse(l) as T);
  } catch {
    return [];
  }
}

function readJson<T>(file: string, fallback: T): T {
  const p = dataPath(file);
  if (!fs.existsSync(p)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(p, 'utf-8')) as T;
  } catch {
    return fallback;
  }
}

function writeJson(file: string, data: unknown): void {
  const p = dataPath(file);
  try {
    fs.writeFileSync(p, JSON.stringify(data, null, 2));
  } catch {
    try { fs.writeFileSync(p, JSON.stringify(data, null, 2)); } catch { /* give up */ }
  }
}

function rotateIfNeeded(file: string, maxMb: number): void {
  const p = dataPath(file);
  if (!fs.existsSync(p)) return;
  try {
    const stats = fs.statSync(p);
    if (stats.size > maxMb * 1024 * 1024) {
      const date = new Date().toISOString().slice(0, 10);
      const base = file.replace('.jsonl', '');
      const rotated = `${base}-${date}.jsonl.gz`;
      const content = fs.readFileSync(p);
      const compressed = zlib.gzipSync(content);
      fs.writeFileSync(dataPath(rotated), compressed);
      fs.writeFileSync(p, '');
    }
  } catch { /* ignore rotation errors */ }
}

// In-memory caches for hot data
let sessionsCache: Record<string, SessionInfo> = {};
let configCache: WatchConfig | null = null;
let flushTimer: ReturnType<typeof setInterval> | null = null;
let dirty = false;

function startFlush(): void {
  if (flushTimer) return;
  flushTimer = setInterval(() => {
    if (dirty) {
      writeJson('sessions.json', sessionsCache);
      dirty = false;
    }
  }, 30_000);
  if (flushTimer.unref) flushTimer.unref();
}

export const store = {
  init(): void {
    ensureDir(DATA_DIR);
    sessionsCache = readJson<Record<string, SessionInfo>>('sessions.json', {});
    configCache = null;
    startFlush();
  },

  // Messages
  appendMessage(msg: WatchMessage): void {
    appendJsonl('messages.jsonl', msg);
    rotateIfNeeded('messages.jsonl', store.getConfig().retention.maxFileSizeMb);
  },

  getMessages(limit = 50, offset = 0, session?: string): WatchMessage[] {
    const all = readJsonl<WatchMessage>('messages.jsonl', 10000, 0);
    let filtered = session ? all.filter(m => m.session === session) : all;
    // Return most recent first
    filtered = filtered.reverse();
    return filtered.slice(offset, offset + limit);
  },

  getRecentMessages(count: number): WatchMessage[] {
    const all = readJsonlAll<WatchMessage>('messages.jsonl');
    return all.slice(-count);
  },

  // Security findings
  appendFinding(finding: SecurityFinding): void {
    appendJsonl('security.jsonl', finding);
  },

  getFindings(limit = 100): SecurityFinding[] {
    return readJsonlAll<SecurityFinding>('security.jsonl').reverse().slice(0, limit);
  },

  getRecentFindings(count: number): SecurityFinding[] {
    return readJsonlAll<SecurityFinding>('security.jsonl').slice(-count);
  },

  // Audit
  appendAudit(event: AuditEvent): void {
    appendJsonl('audit.jsonl', event);
  },

  getAuditLog(limit = 200): AuditEvent[] {
    return readJsonlAll<AuditEvent>('audit.jsonl').reverse().slice(0, limit);
  },

  getAllAuditEvents(): AuditEvent[] {
    return readJsonlAll<AuditEvent>('audit.jsonl');
  },

  // Sessions
  getSession(id: string): SessionInfo | undefined {
    return sessionsCache[id];
  },

  upsertSession(info: SessionInfo): void {
    sessionsCache[info.id] = info;
    dirty = true;
  },

  getAllSessions(): SessionInfo[] {
    return Object.values(sessionsCache);
  },

  // Config
  getConfig(): WatchConfig {
    if (!configCache) {
      configCache = readJson<WatchConfig>('config.json', DEFAULT_CONFIG);
    }
    return configCache;
  },

  setConfig(cfg: WatchConfig): void {
    configCache = cfg;
    writeJson('config.json', cfg);
  },

  updateConfig(partial: Partial<WatchConfig>): WatchConfig {
    const cfg = { ...store.getConfig(), ...partial };
    store.setConfig(cfg);
    return cfg;
  },

  // Stats helpers
  getMessageCountToday(): number {
    const dayStart = new Date();
    dayStart.setHours(0, 0, 0, 0);
    const ts = dayStart.getTime();
    return readJsonlAll<WatchMessage>('messages.jsonl').filter(m => m.timestamp >= ts).length;
  },

  getCostToday(): number {
    const dayStart = new Date();
    dayStart.setHours(0, 0, 0, 0);
    const ts = dayStart.getTime();
    return readJsonlAll<WatchMessage>('messages.jsonl')
      .filter(m => m.timestamp >= ts)
      .reduce((sum, m) => sum + m.estimatedCostUsd, 0);
  },

  getSecurityAlertCount(): number {
    const dayStart = new Date();
    dayStart.setHours(0, 0, 0, 0);
    const ts = dayStart.getTime();
    return readJsonlAll<SecurityFinding>('security.jsonl').filter(f => f.timestamp >= ts).length;
  },

  getDataDir(): string {
    return DATA_DIR;
  },

  flush(): void {
    writeJson('sessions.json', sessionsCache);
    dirty = false;
  },

  shutdown(): void {
    if (flushTimer) {
      clearInterval(flushTimer);
      flushTimer = null;
    }
    store.flush();
  },
};


