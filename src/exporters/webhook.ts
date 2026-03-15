// OpenClaw Watch — Webhook Exporter

import * as https from 'https';
import * as http from 'http';
import * as crypto from 'crypto';
import { SecurityFinding } from '../types';

export function sendWebhook(finding: SecurityFinding, url: string, secret: string): void {
  try {
    const payload = JSON.stringify({
      event: 'security_finding',
      timestamp: new Date(finding.timestamp).toISOString(),
      finding,
    });

    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const transport = isHttps ? https : http;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload).toString(),
      'User-Agent': 'OpenClaw-Watch/2.0',
    };

    if (secret) {
      const signature = crypto.createHmac('sha256', secret).update(payload).digest('hex');
      headers['X-Watch-Signature'] = `sha256=${signature}`;
    }

    const req = transport.request({
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers,
    }, () => { /* response ignored */ });

    req.on('error', () => { /* ignore webhook errors */ });
    req.write(payload);
    req.end();
  } catch { /* ignore */ }
}
