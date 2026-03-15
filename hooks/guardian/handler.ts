// ClawGuard — Guardian Hook
// Smart alerts and auto-control

import { checkCostBudget, checkHealthAlerts, checkSecurityAlert, setAlertSink } from '../../src/alert-engine';
import { store } from '../../src/store';

interface HookEvent {
  type?: string;
  messages?: unknown[];
  session?: { id?: string };
  sessionId?: string;
}

let initialized = false;
let healthCheckInterval: ReturnType<typeof setInterval> | null = null;

function ensureInit(event: HookEvent): void {
  if (initialized) return;
  initialized = true;

  // Set up alert sink to push messages into the event
  setAlertSink({
    pushMessage: (msgs: string[]) => {
      if (event.messages && Array.isArray(event.messages)) {
        for (const msg of msgs) {
          event.messages.push({ role: 'system', content: msg });
        }
      }
    },
    log: (msg: string) => {
      try {
        const { createAuditEvent } = require('../../src/integrity');
        createAuditEvent('alert', msg);
      } catch { /* ignore */ }
    },
  });

  // Periodic health check every 5 minutes
  healthCheckInterval = setInterval(() => {
    checkHealthAlerts();
  }, 300_000);
  if (healthCheckInterval.unref) healthCheckInterval.unref();

  // Daily budget reset at midnight
  const now = new Date();
  const msUntilMidnight = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1).getTime() - now.getTime();
  setTimeout(() => {
    const { resetDailyBudgetAlerts } = require('../../src/alert-engine');
    resetDailyBudgetAlerts();
    // Then every 24h
    setInterval(() => {
      resetDailyBudgetAlerts();
    }, 86_400_000).unref?.();
  }, msUntilMidnight).unref?.();
}

export default function handler(event: HookEvent): void {
  const eventType = event.type || '';
  ensureInit(event);

  switch (eventType) {
    case 'message:received':
    case 'message:sent':
      // Check cost budgets after each message
      checkCostBudget();

      // Check for any recent critical security findings
      const recentFindings = store.getRecentFindings(10);
      const criticalRecent = recentFindings.filter(
        f => Date.now() - f.timestamp < 5000 && (f.severity === 'critical' || f.severity === 'high')
      );
      if (criticalRecent.length > 0) {
        checkSecurityAlert(criticalRecent);
      }
      break;

    case 'command:new':
      // Nothing specific, just ensure init
      break;

    default:
      break;
  }
}


