import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import { parseSarif } from './diagnostics';

let diagnosticCollection: vscode.DiagnosticCollection;
let statusBarItem: vscode.StatusBarItem;
let lastReport = '';

function getWorkspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

function setStatus(text: string, spinning = false) {
  statusBarItem.text = spinning ? `$(sync~spin) ${text}` : `$(shield) ${text}`;
}

function runClawguard(args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const proc = cp.execFile('npx', ['@neuzhou/clawguard', ...args], {
      cwd,
      maxBuffer: 10 * 1024 * 1024,
      shell: true,
    }, (err, stdout, stderr) => {
      // ClawGuard may exit non-zero when findings exist — that's fine
      if (err && !stdout) {
        reject(new Error(stderr || err.message));
      } else {
        resolve(stdout);
      }
    });
  });
}

async function scanWorkspace() {
  const root = getWorkspaceRoot();
  if (!root) {
    vscode.window.showWarningMessage('ClawGuard: No workspace folder open');
    return;
  }

  setStatus('Scanning…', true);
  try {
    const output = await runClawguard(['scan', '--format', 'sarif'], root);
    lastReport = output;
    const count = parseSarif(output, diagnosticCollection, root);
    setStatus(`${count} finding${count === 1 ? '' : 's'}`);
    if (count === 0) {
      vscode.window.showInformationMessage('ClawGuard: No issues found ✅');
    }
  } catch (e: any) {
    setStatus('Error');
    vscode.window.showErrorMessage(`ClawGuard scan failed: ${e.message}`);
  }
}

async function scanFile() {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    vscode.window.showWarningMessage('ClawGuard: No active file');
    return;
  }

  const root = getWorkspaceRoot();
  if (!root) return;

  const relPath = path.relative(root, editor.document.uri.fsPath);
  setStatus('Scanning file…', true);
  try {
    const output = await runClawguard(['scan', '--format', 'sarif', '--file', relPath], root);
    lastReport = output;
    const count = parseSarif(output, diagnosticCollection, root);
    setStatus(`${count} finding${count === 1 ? '' : 's'}`);
  } catch (e: any) {
    setStatus('Error');
    vscode.window.showErrorMessage(`ClawGuard scan failed: ${e.message}`);
  }
}

async function showReport() {
  if (!lastReport) {
    vscode.window.showInformationMessage('ClawGuard: No scan results yet. Run a scan first.');
    return;
  }
  const doc = await vscode.workspace.openTextDocument({
    content: lastReport,
    language: 'json',
  });
  await vscode.window.showTextDocument(doc);
}

export function activate(context: vscode.ExtensionContext) {
  diagnosticCollection = vscode.languages.createDiagnosticCollection('clawguard');

  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  statusBarItem.command = 'clawguard.scan';
  statusBarItem.tooltip = 'Click to scan workspace with ClawGuard';
  setStatus('ClawGuard');
  statusBarItem.show();

  context.subscriptions.push(
    diagnosticCollection,
    statusBarItem,
    vscode.commands.registerCommand('clawguard.scan', scanWorkspace),
    vscode.commands.registerCommand('clawguard.scanFile', scanFile),
    vscode.commands.registerCommand('clawguard.showReport', showReport),
  );

  // Auto-scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(() => {
      if (vscode.workspace.getConfiguration('clawguard').get<boolean>('autoScanOnSave')) {
        scanFile();
      }
    })
  );
}

export function deactivate() {
  diagnosticCollection?.dispose();
}
