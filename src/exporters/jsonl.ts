// OpenClaw Watch — JSONL Exporter

import * as fs from 'fs';
import * as path from 'path';
import { SecurityFinding, AuditEvent, WatchMessage } from '../types';

export function exportJsonl(data: (WatchMessage | SecurityFinding | AuditEvent)[], filePath: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const content = data.map(d => JSON.stringify(d)).join('\n') + '\n';
  fs.writeFileSync(filePath, content);
}

export function formatJsonlLine(record: unknown): string {
  return JSON.stringify(record);
}
