// ClawGuard — MCP Firewall: Console Dashboard
// Real-time display of blocked/allowed calls

import { ProxyEvent, DashboardStats } from './types';
import { McpFirewallProxy } from './proxy';

// ── Formatters ──

function severityIcon(severity: string): string {
  switch (severity) {
    case 'critical': return '🔴';
    case 'high': return '🟠';
    case 'warning': return '🟡';
    case 'info': return '🔵';
    default: return '⚪';
  }
}

function actionIcon(action: string): string {
  switch (action) {
    case 'block': return '🚫';
    case 'approve': return '⏳';
    case 'modify': return '🔧';
    case 'forward': return '✅';
    default: return '❓';
  }
}

function directionArrow(direction: string): string {
  return direction === 'client-to-server' ? '→' : '←';
}

function pad(str: string, len: number): string {
  return str.length >= len ? str.slice(0, len) : str + ' '.repeat(len - str.length);
}

function formatTimestamp(ts: number): string {
  const d = new Date(ts);
  return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}`;
}

// ── Dashboard ──

export class FirewallDashboard {
  private proxy: McpFirewallProxy;
  private refreshInterval: ReturnType<typeof setInterval> | null = null;
  private eventBuffer: ProxyEvent[] = [];
  private maxBufferSize = 100;

  constructor(proxy: McpFirewallProxy) {
    this.proxy = proxy;
  }

  /**
   * Start the dashboard and listen for proxy events.
   */
  start(): void {
    // Attach event listener
    this.proxy.onEvent((event) => {
      this.eventBuffer.push(event);
      if (this.eventBuffer.length > this.maxBufferSize) {
        this.eventBuffer.shift();
      }
      this.renderEvent(event);
    });

    this.renderHeader();

    // Periodic stats refresh
    this.refreshInterval = setInterval(() => {
      this.renderStats();
    }, 5000);
  }

  /**
   * Stop the dashboard.
   */
  stop(): void {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }

  /**
   * Render the dashboard header.
   */
  private renderHeader(): void {
    const header = `
╔═══════════════════════════════════════════════════════════════╗
║           🛡️  ClawGuard MCP Firewall Dashboard               ║
║                    Real-time Traffic Monitor                  ║
╚═══════════════════════════════════════════════════════════════╝
`;
    process.stdout.write(header);
    process.stdout.write('\n' + '─'.repeat(63) + '\n');
    process.stdout.write(
      `${pad('TIME', 8)} ${pad('DIR', 3)} ${pad('SERVER', 15)} ${pad('METHOD', 20)} ${pad('ACTION', 8)} DETAILS\n`
    );
    process.stdout.write('─'.repeat(63) + '\n');
  }

  /**
   * Render a single proxy event.
   */
  private renderEvent(event: ProxyEvent): void {
    const time = formatTimestamp(event.timestamp);
    const dir = directionArrow(event.direction);
    const server = pad(event.server, 15);
    const method = pad(event.method || '—', 20);
    const action = `${actionIcon(event.action)} ${pad(event.action, 7)}`;

    let details = '';
    if (event.findings.length > 0) {
      const topFinding = event.findings[0];
      details = `${severityIcon(topFinding.severity)} ${topFinding.description.slice(0, 60)}`;
      if (event.findings.length > 1) {
        details += ` (+${event.findings.length - 1} more)`;
      }
    }

    const latency = event.latencyMs !== undefined ? ` [${event.latencyMs}ms]` : '';

    process.stdout.write(`${time} ${dir}  ${server} ${method} ${action} ${details}${latency}\n`);
  }

  /**
   * Render summary statistics.
   */
  renderStats(): void {
    const stats = this.proxy.getStats();
    const summary = [
      '',
      '─'.repeat(63),
      `📊 Total: ${stats.totalMessages}  ✅ Allowed: ${stats.allowed}  🚫 Blocked: ${stats.blocked}  🔧 Modified: ${stats.modified}  ⏳ Pending: ${stats.pendingApproval}`,
    ];

    // Server breakdown
    const servers = Object.entries(stats.serverStats);
    if (servers.length > 0) {
      summary.push('   Servers:');
      for (const [server, s] of servers) {
        summary.push(`     ${server}: ${s.calls} calls, ${s.blocked} blocked`);
      }
    }

    // Recent critical findings
    const criticals = stats.findings.filter(f => f.severity === 'critical').slice(-3);
    if (criticals.length > 0) {
      summary.push('   🔴 Recent Critical:');
      for (const f of criticals) {
        summary.push(`     ${f.description.slice(0, 70)}`);
      }
    }

    summary.push('─'.repeat(63));
    process.stdout.write(summary.join('\n') + '\n');
  }

  /**
   * Generate a snapshot of current dashboard state (for programmatic use).
   */
  getSnapshot(): DashboardStats {
    return this.proxy.getStats();
  }
}

/**
 * Format a proxy event as a one-line log string.
 */
export function formatEventLog(event: ProxyEvent): string {
  const time = new Date(event.timestamp).toISOString();
  const dir = event.direction === 'client-to-server' ? 'C→S' : 'S→C';
  const findings = event.findings.length > 0
    ? ` findings=${event.findings.length} maxSeverity=${event.findings.reduce((max, f) => {
        const order: Record<string, number> = { critical: 4, high: 3, warning: 2, info: 1 };
        return (order[f.severity] || 0) > (order[max] || 0) ? f.severity : max;
      }, 'info' as string)}`
    : '';
  return `[${time}] ${dir} server=${event.server} method=${event.method || 'N/A'} action=${event.action}${findings}`;
}
