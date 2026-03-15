import { addMessage, addSessionEvent, setPendingResponse, getPendingResponse, clearPendingResponse } from '../../src/store.js';
import { generateId, estimateTokens } from '../../src/utils.js';
import type { HookEvent } from '../../src/types.js';

const handler = async (event: HookEvent) => {
  const { type, action, sessionKey, timestamp, context } = event;
  const now = timestamp?.getTime?.() || Date.now();

  try {
    if (action === 'message:received') {
      const content = context.content || '';
      addMessage({
        id: generateId(),
        direction: 'in',
        content: content.slice(0, 2000),
        from: context.from as string | undefined,
        channelId: context.channelId as string | undefined,
        sessionKey,
        timestamp: now,
        estimatedTokens: estimateTokens(content),
      });
      setPendingResponse(sessionKey, now);
    }

    if (action === 'message:sent') {
      const content = context.content || '';
      const pendingTs = getPendingResponse(sessionKey);
      addMessage({
        id: generateId(),
        direction: 'out',
        content: content.slice(0, 2000),
        to: context.to as string | undefined,
        channelId: context.channelId as string | undefined,
        sessionKey,
        timestamp: now,
        estimatedTokens: estimateTokens(content),
      });
      if (pendingTs) {
        clearPendingResponse(sessionKey);
      }
    }

    if (action === 'command:new') {
      addSessionEvent({ type: 'new', sessionKey, timestamp: now });
    }

    if (action === 'command:reset') {
      addSessionEvent({ type: 'reset', sessionKey, timestamp: now });
    }

    if (action === 'session:compact:after') {
      addSessionEvent({ type: 'compact', sessionKey, timestamp: now });
    }
  } catch (err) {
    console.error('[openclaw-watch/monitor]', err);
  }
};

export default handler;
