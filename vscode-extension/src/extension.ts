import * as vscode from 'vscode';
import { ClawGuardDiagnostics } from './diagnostics';

let diagnosticsProvider: ClawGuardDiagnostics;

export function activate(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration('clawguard');
  if (!config.get<boolean>('enable', true)) return;

  diagnosticsProvider = new ClawGuardDiagnostics();
  context.subscriptions.push(diagnosticsProvider);

  // Scan all open text documents on activation
  for (const doc of vscode.workspace.textDocuments) {
    diagnosticsProvider.scanDocument(doc);
  }

  // Scan on open
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      diagnosticsProvider.scanDocument(doc);
    })
  );

  // Scan on save (if enabled)
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (config.get<boolean>('scanOnSave', true)) {
        diagnosticsProvider.scanDocument(doc);
      }
    })
  );

  // Scan on change (debounced)
  let changeTimer: ReturnType<typeof setTimeout> | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((e) => {
      if (changeTimer) clearTimeout(changeTimer);
      changeTimer = setTimeout(() => diagnosticsProvider.scanDocument(e.document), 500);
    })
  );

  // Manual scan commands
  context.subscriptions.push(
    vscode.commands.registerCommand('clawguard.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        diagnosticsProvider.scanDocument(editor.document);
        vscode.window.showInformationMessage('ClawGuard: Scan complete');
      }
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand('clawguard.scanWorkspace', async () => {
      const files = await vscode.workspace.findFiles(
        '**/*.{md,ts,js,json,yaml,yml,py,sh}',
        '**/node_modules/**',
        500
      );
      let count = 0;
      for (const uri of files) {
        const doc = await vscode.workspace.openTextDocument(uri);
        count += diagnosticsProvider.scanDocument(doc);
      }
      vscode.window.showInformationMessage(`ClawGuard: Found ${count} issue(s) in ${files.length} files`);
    })
  );

  console.log('ClawGuard extension activated');
}

export function deactivate(): void {
  if (diagnosticsProvider) {
    diagnosticsProvider.dispose();
  }
}
