// ClawGuard — Syslog Exporter (RFC 5424 format, UDP)

import * as dgram from 'dgram';
import { SecurityFinding } from '../types';

const SEVERITY_MAP: Record<string, number> = {
  critical: 2, // Critical
  high: 3,     // Error
  warning: 4,  // Warning
  info: 6,     // Informational
};

export function sendToSyslog(finding: SecurityFinding, host: string, port: number): void {
  const severity = SEVERITY_MAP[finding.severity] ?? 6;
  const facility = 16; // local0
  const priority = facility * 8 + severity;
  const timestamp = new Date(finding.timestamp).toISOString();
  const hostname = 'ClawGuard';
  const appName = 'security';
  const msgId = finding.ruleId;

  // RFC 5424 format
  const msg = `<${priority}>1 ${timestamp} ${hostname} ${appName} - ${msgId} - ${finding.description}${finding.evidence ? ` | evidence: ${finding.evidence}` : ''}`;

  const client = dgram.createSocket('udp4');
  const buffer = Buffer.from(msg);
  client.send(buffer, 0, buffer.length, port, host, () => {
    client.close();
  });
}

// CEF format for SIEM integration
export function formatCEF(finding: SecurityFinding): string {
  const severityNum = SEVERITY_MAP[finding.severity] ?? 5;
  const cefSeverity = Math.max(0, 10 - severityNum);
  return `CEF:0|OpenClaw|Watch|2.0|${finding.ruleId}|${finding.description}|${cefSeverity}|src=${finding.channel || 'unknown'} cat=${finding.category} cs1=${finding.owaspCategory || 'N/A'} cs1Label=OWASP msg=${finding.evidence || 'N/A'}`;
}


