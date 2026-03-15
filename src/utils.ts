import { randomBytes } from 'node:crypto';

export function generateId(): string {
  return randomBytes(8).toString('hex');
}

export function estimateTokens(text: string): number {
  if (!text) return 0;
  const words = text.split(/\s+/).filter(Boolean).length;
  return Math.ceil(words * 1.3);
}

export function truncate(str: string, max = 200): string {
  if (!str || str.length <= max) return str || '';
  return str.slice(0, max) + '…';
}

export function dayKey(ts: number): string {
  return new Date(ts).toISOString().slice(0, 10);
}

export function hoursAgo(hours: number): number {
  return Date.now() - hours * 3600_000;
}
