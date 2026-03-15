import { addAlert } from '../../src/store.js';
import { scanAll } from '../../src/security.js';
import type { HookEvent } from '../../src/types.js';

const handler = async (event: HookEvent) => {
  const { action, sessionKey, context } = event;
  const content = context.content || '';

  if (!content) return;

  try {
    let direction: 'in' | 'out' = 'in';
    if (action === 'message:sent') direction = 'out';

    const alerts = scanAll(content, sessionKey, direction, context.from as string | undefined);

    for (const alert of alerts) {
      addAlert(alert);

      // Push critical/warning alerts to user
      if (alert.severity === 'critical') {
        event.messages.push(`🚨 [OpenClaw Watch] CRITICAL: ${alert.description}`);
      } else if (alert.severity === 'warning' && alert.type === 'prompt_injection') {
        event.messages.push(`⚠️ [OpenClaw Watch] ${alert.description}`);
      }
    }
  } catch (err) {
    console.error('[openclaw-watch/security]', err);
  }
};

export default handler;
