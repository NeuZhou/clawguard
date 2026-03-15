// OpenClaw Watch — Integrity Engine (SHA-256 Hash Chain)

import * as crypto from 'crypto';
import { AuditEvent } from './types';
import { store } from './store';

let prevHash = '0000000000000000000000000000000000000000000000000000000000000000';

function sha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

export function createAuditEvent(type: string, detail: string, session?: string, metadata?: Record<string, unknown>): AuditEvent {
  const id = crypto.randomUUID();
  const timestamp = Date.now();
  const payload = JSON.stringify({ id, timestamp, type, detail, session, metadata });
  const hash = sha256(prevHash + payload);
  const event: AuditEvent = { id, timestamp, type, detail, session, prevHash, hash, metadata };
  prevHash = hash;
  store.appendAudit(event);
  return event;
}

export function verifyChain(): { valid: boolean; total: number; brokenAt?: number } {
  const events = store.getAllAuditEvents();
  if (events.length === 0) return { valid: true, total: 0 };

  let currentPrev = '0000000000000000000000000000000000000000000000000000000000000000';
  for (let i = 0; i < events.length; i++) {
    const e = events[i];
    if (e.prevHash !== currentPrev) {
      return { valid: false, total: events.length, brokenAt: i };
    }
    const payload = JSON.stringify({ id: e.id, timestamp: e.timestamp, type: e.type, detail: e.detail, session: e.session, metadata: e.metadata });
    const expectedHash = sha256(currentPrev + payload);
    if (e.hash !== expectedHash) {
      return { valid: false, total: events.length, brokenAt: i };
    }
    currentPrev = e.hash;
  }
  return { valid: true, total: events.length };
}

export function initIntegrity(): void {
  const events = store.getAllAuditEvents();
  if (events.length > 0) {
    prevHash = events[events.length - 1].hash;
  }
}
