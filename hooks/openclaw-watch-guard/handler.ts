import * as path from 'path';
import * as fs from 'fs';

const handler = async (event: any) => {
  const content = event.context?.content;
  if (!content || typeof content !== 'string') return;

  const direction = event.action === 'received' ? 'inbound' : 'outbound';

  // Dynamic import of compiled rules
  const pkgRoot = path.resolve(__dirname, '..', '..');
  const rulesPath = path.join(pkgRoot, 'dist', 'src', 'rules', 'index.js');

  if (!fs.existsSync(rulesPath)) {
    console.error('[openclaw-watch-guard] Built rules not found. Run: npm run build');
    return;
  }

  try {
    const { builtinRules } = await import(rulesPath);
    const context = {
      session: event.sessionKey || 'unknown',
      channel: event.context?.channelId || 'unknown',
      timestamp: Date.now(),
      recentMessages: [],
      recentFindings: [],
    };

    const findings: any[] = [];
    for (const rule of builtinRules) {
      if (!rule.enabled) continue;
      try {
        const ruleFindings = rule.check(content, direction, context);
        findings.push(...ruleFindings);
      } catch { /* skip */ }
    }

    if (findings.length === 0) return;

    // Log findings
    const logDir = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.openclaw', 'openclaw-watch');
    if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
    const logFile = path.join(logDir, 'findings.jsonl');

    for (const f of findings) {
      fs.appendFileSync(logFile, JSON.stringify({ ...f, direction, messageFrom: event.context?.from }) + '\n');
    }

    // Alert user on critical/high findings
    const critical = findings.filter((f: any) => f.severity === 'critical' || f.severity === 'high');
    if (critical.length > 0) {
      const icon = direction === 'inbound' ? '🚨' : '⚠️';
      const summary = critical.map((f: any) => `• ${f.ruleName}: ${f.description}`).slice(0, 3).join('\n');
      const msg = `${icon} **OpenClaw Watch Alert** (${critical.length} ${direction} threat${critical.length > 1 ? 's' : ''}):\n${summary}`;
      event.messages.push(msg);
    }
  } catch (err) {
    console.error('[openclaw-watch-guard] Error:', err instanceof Error ? err.message : String(err));
  }
};

export default handler;
