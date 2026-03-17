import * as vscode from 'vscode';

/**
 * Security pattern for scanning — simplified version of ClawGuard rules
 * that runs entirely in the VS Code extension without requiring the full engine.
 */
interface SecurityPattern {
  id: string;
  severity: 'critical' | 'high' | 'warning' | 'info';
  pattern: RegExp;
  message: string;
}

const PATTERNS: SecurityPattern[] = [
  // Prompt injection
  { id: 'PROMPT-001', severity: 'critical', pattern: /ignore\s+(all\s+)?previous\s+instructions/gi, message: 'Prompt injection: "ignore previous instructions"' },
  { id: 'PROMPT-002', severity: 'critical', pattern: /you\s+are\s+now\s+(?:DAN|jailbroken|unrestricted)/gi, message: 'Prompt injection: jailbreak attempt' },
  { id: 'PROMPT-003', severity: 'high', pattern: /system\s*prompt\s*override/gi, message: 'Prompt injection: system prompt override' },
  { id: 'PROMPT-004', severity: 'high', pattern: /\bdo\s+anything\s+now\b/gi, message: 'Prompt injection: DAN pattern' },

  // API key / secret exposure
  { id: 'SECRET-001', severity: 'critical', pattern: /(?:sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-_]{20,})/g, message: 'Exposed API key or secret token' },
  { id: 'SECRET-002', severity: 'high', pattern: /(?:password|passwd|secret|token|api_key)\s*[:=]\s*["'][^"'\s]{8,}["']/gi, message: 'Hardcoded credential' },

  // Data leakage
  { id: 'DATA-001', severity: 'high', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, message: 'Potential SSN exposure' },
  { id: 'DATA-002', severity: 'warning', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/gi, message: 'Email address in content' },

  // Dangerous commands
  { id: 'CMD-001', severity: 'critical', pattern: /rm\s+-rf\s+[\/~]/g, message: 'Dangerous recursive delete command' },
  { id: 'CMD-002', severity: 'high', pattern: /curl\s+.*\|\s*(?:bash|sh|zsh)/g, message: 'Pipe-to-shell pattern (supply chain risk)' },
  { id: 'CMD-003', severity: 'high', pattern: /eval\s*\(\s*(?:fetch|require|import)/g, message: 'Dynamic code execution from remote source' },

  // Permission escalation
  { id: 'PERM-001', severity: 'high', pattern: /chmod\s+(?:777|a\+rwx)/g, message: 'Overly permissive file permissions' },
  { id: 'PERM-002', severity: 'warning', pattern: /sudo\s+.*--no-preserve-env/g, message: 'Sudo environment bypass' },
];

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, warning: 2, info: 3 };

export class ClawGuardDiagnostics implements vscode.Disposable {
  private diagnosticCollection: vscode.DiagnosticCollection;

  constructor() {
    this.diagnosticCollection = vscode.languages.createDiagnosticCollection('clawguard');
  }

  /**
   * Scan a document and return the number of findings.
   */
  scanDocument(doc: vscode.TextDocument): number {
    const config = vscode.workspace.getConfiguration('clawguard');
    const threshold = config.get<string>('severityThreshold', 'warning');
    const thresholdLevel = SEVERITY_ORDER[threshold] ?? 2;

    const diagnostics: vscode.Diagnostic[] = [];
    const text = doc.getText();

    for (const p of PATTERNS) {
      if (SEVERITY_ORDER[p.severity] > thresholdLevel) continue;

      // Reset regex lastIndex for global patterns
      p.pattern.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = p.pattern.exec(text)) !== null) {
        const startPos = doc.positionAt(match.index);
        const endPos = doc.positionAt(match.index + match[0].length);
        const range = new vscode.Range(startPos, endPos);

        const severity = p.severity === 'critical' || p.severity === 'high'
          ? vscode.DiagnosticSeverity.Error
          : p.severity === 'warning'
            ? vscode.DiagnosticSeverity.Warning
            : vscode.DiagnosticSeverity.Information;

        const diag = new vscode.Diagnostic(range, `🛡️ ${p.message}`, severity);
        diag.code = p.id;
        diag.source = 'ClawGuard';
        diagnostics.push(diag);
      }
    }

    this.diagnosticCollection.set(doc.uri, diagnostics);
    return diagnostics.length;
  }

  dispose(): void {
    this.diagnosticCollection.dispose();
  }
}
