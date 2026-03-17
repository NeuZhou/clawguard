# ClawGuard - AI Agent Security Scanner

> Detect risky AI agent tool calls directly in VS Code with inline diagnostics.

## Features

- **Workspace Scan** — Scan all files for risky AI agent patterns
- **File Scan** — Scan the active file on demand or automatically on save
- **Inline Diagnostics** — Findings appear as squiggly underlines with severity-appropriate colors (red for critical/high, yellow for medium, blue for info)
- **SARIF Report** — View raw SARIF output for CI/CD integration
- **Status Bar** — See scan status and finding count at a glance

## Screenshots

> _Coming soon — the extension is in scaffold/preview stage._
>
> - **Inline diagnostics**: Red underlines on dangerous `exec()` calls with hover details
> - **Status bar**: Shield icon showing "3 findings" after a scan
> - **Report view**: Full SARIF JSON output in a new editor tab

## Installation

This extension is not yet published to the VS Code Marketplace. To use it locally:

```bash
cd vscode-extension
npm install
npm run compile
```

Then press **F5** in VS Code to launch the Extension Development Host.

## Commands

| Command | Description |
|---------|-------------|
| `ClawGuard: Scan Workspace` | Scan all workspace files |
| `ClawGuard: Scan Current File` | Scan the active editor file |
| `ClawGuard: Show Report` | Open last scan's SARIF output |

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `clawguard.severityThreshold` | `medium` | Minimum severity to report (`info`, `medium`, `high`, `critical`) |
| `clawguard.customRulesPath` | `""` | Path to custom rules file |
| `clawguard.autoScanOnSave` | `false` | Auto-scan current file on save |

## Requirements

- Node.js 18+
- `@neuzhou/clawguard` (installed globally or via npx)

## License

MIT
