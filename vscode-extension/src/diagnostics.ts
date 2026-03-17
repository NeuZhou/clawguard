import * as vscode from 'vscode';
import * as path from 'path';

interface SarifResult {
  ruleId?: string;
  level?: 'error' | 'warning' | 'note' | 'none';
  message?: { text?: string };
  locations?: Array<{
    physicalLocation?: {
      artifactLocation?: { uri?: string };
      region?: { startLine?: number; startColumn?: number; endLine?: number; endColumn?: number };
    };
  }>;
}

interface SarifRun {
  results?: SarifResult[];
}

interface SarifLog {
  runs?: SarifRun[];
}

const SEVERITY_ORDER = ['info', 'medium', 'high', 'critical'] as const;

function meetsThreshold(level: string, threshold: string): boolean {
  const map: Record<string, number> = { none: 0, note: 0, info: 0, warning: 1, medium: 1, error: 2, high: 2, critical: 3 };
  return (map[level] ?? 0) >= (map[threshold] ?? 0);
}

function toVsSeverity(level?: string): vscode.DiagnosticSeverity {
  switch (level) {
    case 'error': return vscode.DiagnosticSeverity.Error;
    case 'warning': return vscode.DiagnosticSeverity.Warning;
    default: return vscode.DiagnosticSeverity.Information;
  }
}

export function parseSarif(
  sarifJson: string,
  diagnosticCollection: vscode.DiagnosticCollection,
  workspaceRoot: string
): number {
  const threshold = vscode.workspace.getConfiguration('clawguard').get<string>('severityThreshold', 'medium');
  const sarif: SarifLog = JSON.parse(sarifJson);
  const fileMap = new Map<string, vscode.Diagnostic[]>();
  let count = 0;

  for (const run of sarif.runs ?? []) {
    for (const result of run.results ?? []) {
      const level = result.level ?? 'warning';
      if (!meetsThreshold(level, threshold)) continue;

      for (const loc of result.locations ?? []) {
        const phys = loc.physicalLocation;
        const uri = phys?.artifactLocation?.uri;
        if (!uri) continue;

        const filePath = uri.startsWith('file:///')
          ? vscode.Uri.parse(uri).fsPath
          : path.resolve(workspaceRoot, uri);

        const region = phys?.region;
        const startLine = Math.max((region?.startLine ?? 1) - 1, 0);
        const startCol = Math.max((region?.startColumn ?? 1) - 1, 0);
        const endLine = Math.max((region?.endLine ?? region?.startLine ?? 1) - 1, 0);
        const endCol = Math.max((region?.endColumn ?? 200) - 1, 0);

        const range = new vscode.Range(startLine, startCol, endLine, endCol);
        const diag = new vscode.Diagnostic(range, result.message?.text ?? result.ruleId ?? 'ClawGuard finding', toVsSeverity(level));
        diag.source = 'ClawGuard';
        diag.code = result.ruleId;

        const key = filePath;
        if (!fileMap.has(key)) fileMap.set(key, []);
        fileMap.get(key)!.push(diag);
        count++;
      }
    }
  }

  diagnosticCollection.clear();
  for (const [filePath, diags] of fileMap) {
    diagnosticCollection.set(vscode.Uri.file(filePath), diags);
  }

  return count;
}
