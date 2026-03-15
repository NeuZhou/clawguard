// ClawGuard — Alert Engine

import { SecurityFinding, AlertState, WatchConfig, Severity } from './types';
import { store } from './store';

let alertState: AlertState = { lastAlertTime: {}, budgetAlerted: {} };

function canAlert(key: string, cooldownMs: number): boolean {
  const last = alertState.lastAlertTime[key] || 0;
  if (Date.now() - last < cooldownMs) return false;
  alertState.lastAlertTime[key] = Date.now();
  return true;
}

export interface AlertSink {
  pushMessage?: (messages: string[]) => void;
  log?: (msg: string) => void;
}

let sink: AlertSink = {};

export function setAlertSink(s: AlertSink): void {
  sink = s;
}

function emit(message: string): void {
  if (sink.pushMessage) sink.pushMessage([message]);
  if (sink.log) sink.log(message);
}

export function checkSecurityAlert(findings: SecurityFinding[]): void {
  const config = store.getConfig();
  const escalate = config.alerts.securityEscalate;

  for (const f of findings) {
    if (escalate.includes(f.severity) && f.action === 'alert') {
      const key = `security:${f.ruleId}:${f.severity}`;
      if (canAlert(key, config.alerts.cooldownMs)) {
        const emoji = f.severity === 'critical' ? '🚨' : '⚠️';
        emit(`${emoji} **Security Alert** [${f.severity.toUpperCase()}]\n${f.description}\nRule: ${f.ruleName} (${f.owaspCategory || 'N/A'})\n${f.evidence ? `Evidence: ${f.evidence}` : ''}`);
      }
    }
  }
}

export function checkCostBudget(): void {
  const config = store.getConfig();
  const costToday = store.getCostToday();
  const dailyBudget = config.budget.dailyUsd;

  for (const threshold of config.alerts.costThresholds) {
    const limit = dailyBudget * threshold;
    const key = `budget:daily:${threshold}`;
    if (costToday >= limit && !alertState.budgetAlerted[key]) {
      alertState.budgetAlerted[key] = true;
      const pct = Math.round(threshold * 100);
      if (threshold >= 1.0) {
        emit(`🚨 **Budget Exceeded!** Daily cost $${costToday.toFixed(2)} has exceeded $${dailyBudget} budget (${pct}%)\nConsider pausing non-essential tasks.`);
      } else {
        emit(`💰 **Budget Warning** Daily cost $${costToday.toFixed(2)} has reached ${pct}% of $${dailyBudget} budget`);
      }
    }
  }
}

export function checkHealthAlerts(): void {
  const sessions = store.getAllSessions();
  const config = store.getConfig();
  const now = Date.now();

  for (const session of sessions) {
    // Stuck agent detection
    const timeSinceActivity = now - session.lastActivityAt;
    if (timeSinceActivity > config.alerts.stuckTimeoutMs && session.messageCount > 0) {
      const key = `stuck:${session.id}`;
      if (canAlert(key, config.alerts.cooldownMs)) {
        const mins = Math.round(timeSinceActivity / 60_000);
        emit(`⚠️ **Stuck Agent?** Session ${session.id.slice(0, 8)} has had no activity for ${mins} minutes`);
      }
    }
  }
}

export function resetDailyBudgetAlerts(): void {
  alertState.budgetAlerted = {};
}

export function getAlertState(): AlertState {
  return { ...alertState };
}


