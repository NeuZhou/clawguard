// ClawGuard — Audit Logger
// Tamper-resistant hash-chained audit logging for MCP tool calls

import { createHash } from 'node:crypto';
import { AuditEvent } from './types';

export interface AuditFilter {
  type?: string;
  session?: string;
  since?: number;
  until?: number;
  limit?: number;
}

export class AuditLogger {
  private entries: AuditEvent[] = [];
  private lastHash = '0000000000000000000000000000000000000000000000000000000000000000';

  /** Compute SHA-256 hash for an audit entry */
  private computeHash(event: Omit<AuditEvent, 'hash'>): string {
    const data = JSON.stringify({
      id: event.id,
      timestamp: event.timestamp,
      type: event.type,
      detail: event.detail,
      session: event.session,
      prevHash: event.prevHash,
      metadata: event.metadata,
    });
    return createHash('sha256').update(data).digest('hex');
  }

  /** Generate a unique ID */
  private generateId(): string {
    const ts = Date.now().toString(36);
    const rand = Math.random().toString(36).slice(2, 8);
    return `audit_${ts}_${rand}`;
  }

  /** Log an audit event with hash chaining */
  log(event: Pick<AuditEvent, 'type' | 'detail' | 'session' | 'metadata'>): AuditEvent {
    const entry: AuditEvent = {
      id: this.generateId(),
      timestamp: Date.now(),
      type: event.type,
      detail: event.detail,
      session: event.session,
      prevHash: this.lastHash,
      hash: '',
      metadata: event.metadata,
    };
    entry.hash = this.computeHash(entry);
    this.lastHash = entry.hash;
    this.entries.push(entry);
    return entry;
  }

  /** Verify the integrity of the entire audit chain */
  verify(): boolean {
    if (this.entries.length === 0) return true;

    let expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';
    for (const entry of this.entries) {
      if (entry.prevHash !== expectedPrevHash) return false;
      const computed = this.computeHash(entry);
      if (entry.hash !== computed) return false;
      expectedPrevHash = entry.hash;
    }
    return true;
  }

  /** Query audit events with filters */
  query(filters: AuditFilter): AuditEvent[] {
    let results = [...this.entries];

    if (filters.type) {
      results = results.filter(e => e.type === filters.type);
    }
    if (filters.session) {
      results = results.filter(e => e.session === filters.session);
    }
    if (filters.since !== undefined) {
      results = results.filter(e => e.timestamp >= filters.since!);
    }
    if (filters.until !== undefined) {
      results = results.filter(e => e.timestamp <= filters.until!);
    }
    if (filters.limit !== undefined) {
      results = results.slice(0, filters.limit);
    }
    return results;
  }

  /** Export audit log in various formats */
  export(format: 'json' | 'csv' | 'siem'): string {
    if (format === 'json') {
      return JSON.stringify(this.entries, null, 2);
    }

    if (format === 'csv') {
      const header = 'id,timestamp,type,detail,session,prevHash,hash';
      const rows = this.entries.map(e =>
        [e.id, e.timestamp, e.type, `"${e.detail.replace(/"/g, '""')}"`, e.session || '', e.prevHash, e.hash].join(',')
      );
      return [header, ...rows].join('\n');
    }

    if (format === 'siem') {
      // CEF (Common Event Format) style for SIEM ingestion
      return this.entries.map(e =>
        `CEF:0|ClawGuard|AuditLog|1.0|${e.type}|${e.detail}|1|ts=${e.timestamp} session=${e.session || 'none'} hash=${e.hash}`
      ).join('\n');
    }

    throw new Error(`Unknown export format: ${format}`);
  }

  /** Get total number of entries */
  get size(): number {
    return this.entries.length;
  }

  /** Get the last hash in the chain */
  get chainHead(): string {
    return this.lastHash;
  }

  /** Clear all entries (for testing) */
  clear(): void {
    this.entries = [];
    this.lastHash = '0000000000000000000000000000000000000000000000000000000000000000';
  }
}
