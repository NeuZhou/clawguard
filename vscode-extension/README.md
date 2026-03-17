# ClawGuard VS Code Extension

> 🛡️ AI Agent Security Scanner — see security threats as red wavy underlines in your editor.

## Features

- **Real-time scanning** — detects prompt injection, exposed secrets, data leakage, and dangerous commands
- **Red wavy underlines** — findings show as VS Code Diagnostics (errors/warnings)
- **Scan on save** — automatically scans when you save a file
- **Workspace scan** — scan all files in your workspace with one command

## Installation (Development)

```bash
cd vscode-extension
npm install
npm run compile
```

Then press `F5` in VS Code to launch the Extension Development Host.

## Commands

| Command | Description |
|---------|-------------|
| `ClawGuard: Scan Current File` | Scan the active file |
| `ClawGuard: Scan Workspace` | Scan all supported files in workspace |

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `clawguard.enable` | `true` | Enable/disable the extension |
| `clawguard.scanOnSave` | `true` | Auto-scan on file save |
| `clawguard.severityThreshold` | `warning` | Minimum severity to display |

## Supported File Types

`.md`, `.ts`, `.js`, `.json`, `.yaml`, `.yml`, `.py`, `.sh`

## What It Detects

- **Prompt injection** — "ignore previous instructions", jailbreak patterns
- **Exposed secrets** — API keys (OpenAI, AWS, GitHub), hardcoded credentials
- **Data leakage** — SSNs, email addresses in content
- **Dangerous commands** — `rm -rf /`, pipe-to-shell, dynamic eval
- **Permission issues** — chmod 777, sudo bypasses

## Architecture

The extension embeds a lightweight pattern matcher (no external dependencies).
For the full 285+ pattern engine, use the ClawGuard CLI: `clawguard scan <path>`.
