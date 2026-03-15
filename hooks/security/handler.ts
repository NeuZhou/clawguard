// Carapace — Security Hook
// Real-time security scanning pipeline

import { store } from '../../src/store';
import { runSecurityScan, loadCustomRules } from '../../src/security-engine';
import { Direction, RuleContext } from '../../src/types';
import { sendToSyslog } from '../../src/exporters/syslog';
import { sendWebhook } from '../../src/exporters/webhook';

interface HookEvent {
  type?: string;
  session?: { id?: string; model?: string };
  sessionId?: string;
  channel?: { name?: string; id?: string };
  channelId?: string;
  content?: string;
  message?: string;
  messages?: { content?: string }[];
}

function getContent(event: HookEvent): string {
  if (typeof event.content === 'string') return event.content;
  if (event.message && typeof event.message === 'string') return event.message;
  if (event.messages && Array.isArray(event.messages)) {
    return event.messages.map((m: { content?: string }) => m.content || '').join('\n');
  }
  return '';
}

let customRulesInitialized = false;

export default function handler(event: HookEvent): void {
  const eventType = event.type || '';

  if (!customRulesInitialized) {
    const config = store.getConfig();
    loadCustomRules(config.security.customRulesDir);
    customRulesInitialized = true;
  }

  let direction: Direction;
  switch (eventType) {
    case 'message:received':
    case 'message:preprocessed':
      direction = 'inbound';
      break;
    case 'message:sent':
      direction = 'outbound';
      break;
    default:
      return;
  }

  const content = getContent(event);
  if (!content) return;

  const session = event.session?.id || event.sessionId || 'unknown';
  const channel = event.channel?.name || event.channel?.id || event.channelId || 'unknown';

  const context: RuleContext = {
    session,
    channel,
    timestamp: Date.now(),
    recentMessages: store.getRecentMessages(50),
    recentFindings: store.getRecentFindings(20),
    sessionInfo: store.getSession(session),
  };

  const findings = runSecurityScan(content, direction, context);

  // Update session security finding count
  if (findings.length > 0) {
    const sessionInfo = store.getSession(session);
    if (sessionInfo) {
      sessionInfo.securityFindings += findings.length;
      store.upsertSession(sessionInfo);
    }

    // Export findings
    const config = store.getConfig();
    for (const finding of findings) {
      if (config.exporters.syslog.enabled) {
        sendToSyslog(finding, config.exporters.syslog.host, config.exporters.syslog.port);
      }
      if (config.exporters.webhook.enabled && config.exporters.webhook.url) {
        sendWebhook(finding, config.exporters.webhook.url, config.exporters.webhook.secret);
      }
    }
  }
}

