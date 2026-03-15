// Carapace — Collector Hook
// Collects all agent activity into the store

import * as crypto from 'crypto';
import { store } from '../../src/store';
import { estimateTokens, calculateCost } from '../../src/cost-engine';
import { createAuditEvent, initIntegrity } from '../../src/integrity';
import { WatchMessage, SessionInfo, Direction } from '../../src/types';

let startupTime = 0;
const pendingLatency: Record<string, number> = {};

function getSessionId(event: HookEvent): string {
  return event.session?.id || event.sessionId || 'unknown';
}

function getChannel(event: HookEvent): string {
  return event.channel?.name || event.channel?.id || event.channelId || 'unknown';
}

function getModel(event: HookEvent): string | undefined {
  return event.model || event.session?.model || undefined;
}

function getContent(event: HookEvent): string {
  if (typeof event.content === 'string') return event.content;
  if (event.message && typeof event.message === 'string') return event.message;
  if (event.messages && Array.isArray(event.messages)) {
    return event.messages.map((m: { content?: string }) => m.content || '').join('\n');
  }
  return '';
}

interface HookEvent {
  type?: string;
  session?: { id?: string; model?: string };
  sessionId?: string;
  channel?: { name?: string; id?: string };
  channelId?: string;
  model?: string;
  content?: string;
  message?: string;
  messages?: { content?: string; role?: string }[];
  metadata?: Record<string, unknown>;
}

function recordMessage(event: HookEvent, direction: Direction): void {
  const content = getContent(event);
  const session = getSessionId(event);
  const channel = getChannel(event);
  const model = getModel(event);
  const tokens = estimateTokens(content);
  const cost = calculateCost(tokens, direction, model);

  let latencyMs: number | undefined;
  if (direction === 'outbound' && pendingLatency[session]) {
    latencyMs = Date.now() - pendingLatency[session];
    delete pendingLatency[session];
  }
  if (direction === 'inbound') {
    pendingLatency[session] = Date.now();
  }

  const msg: WatchMessage = {
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    direction,
    session,
    channel,
    content: content.slice(0, 5000), // Cap stored content
    estimatedTokens: tokens,
    estimatedCostUsd: cost,
    model,
    latencyMs,
  };

  store.appendMessage(msg);

  // Update session info
  const existing = store.getSession(session);
  const sessionInfo: SessionInfo = existing || {
    id: session,
    channel,
    startedAt: Date.now(),
    lastActivityAt: Date.now(),
    messageCount: 0,
    estimatedTokens: 0,
    estimatedCostUsd: 0,
    securityFindings: 0,
    model,
  };
  sessionInfo.lastActivityAt = Date.now();
  sessionInfo.messageCount += 1;
  sessionInfo.estimatedTokens += tokens;
  sessionInfo.estimatedCostUsd += cost;
  if (model) sessionInfo.model = model;
  store.upsertSession(sessionInfo);
}

// Hook handler — called by OpenClaw for each event
export default function handler(event: HookEvent): void {
  const eventType = event.type || '';

  switch (eventType) {
    case 'gateway:startup':
      startupTime = Date.now();
      store.init();
      initIntegrity();
      createAuditEvent('system', 'Gateway started — Carapace collector active');
      break;

    case 'message:received':
      recordMessage(event, 'inbound');
      createAuditEvent('message', 'Message received', getSessionId(event));
      break;

    case 'message:sent':
      recordMessage(event, 'outbound');
      createAuditEvent('message', 'Message sent', getSessionId(event));
      break;

    case 'message:preprocessed':
      // Track but don't count as separate message
      createAuditEvent('preprocess', 'Message preprocessed', getSessionId(event));
      break;

    case 'command:new':
      createAuditEvent('session', 'New session started', getSessionId(event));
      break;

    case 'command:reset':
      createAuditEvent('session', 'Session reset', getSessionId(event));
      break;

    case 'command:stop':
      createAuditEvent('session', 'Session stopped', getSessionId(event));
      store.flush();
      break;

    case 'session:compact:before':
      createAuditEvent('session', 'Context compaction starting', getSessionId(event));
      break;

    case 'session:compact:after':
      createAuditEvent('session', 'Context compaction completed', getSessionId(event));
      break;

    default:
      // Unknown event type — still log it
      if (eventType) {
        createAuditEvent('unknown', `Unknown event: ${eventType}`, getSessionId(event));
      }
      break;
  }
}

export { startupTime };

