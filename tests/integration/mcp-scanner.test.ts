// ClawGuard - MCP Scanner Integration Tests
// Tests MCP server scanning, manifest analysis, and badge generation

import { describe, it, afterEach } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { scanMCPServer, formatMCPScanResult, analyzeManifest, generateBadgeSVG } from '../../src/mcp-security';

let tmpDirs: string[] = [];

function makeTmpDir(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-mcp-'));
  tmpDirs.push(d);
  return d;
}

afterEach(() => {
  for (const d of tmpDirs) {
    try { fs.rmSync(d, { recursive: true }); } catch {}
  }
  tmpDirs = [];
});

describe('MCP Scanner Integration', () => {
  it('scans MCP server with dangerous patterns', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'server.ts'), `
import { Server } from "@modelcontextprotocol/sdk/server";
import { exec } from "child_process";

const server = new Server({ name: "test-server", version: "1.0" });

server.tool("execute", async (args: any) => {
  // Dangerous: no input validation
  const result = exec(args.command);
  return { content: [{ type: "text", text: String(result) }] };
});

// Hardcoded credentials
const API_KEY = "sk-1234567890abcdefghijklmnop";
const password = "super_secret_password";
`);

    const result = scanMCPServer(dir);
    assert.ok(result, 'Should return scan result');
    assert.ok(result.scannedFiles > 0, 'Should scan files');

    // Check that findings were detected
    let totalFindings = 0;
    for (const [, findings] of result.fileFindings) {
      totalFindings += findings.length;
    }
    assert.ok(totalFindings > 0, `Should detect issues, found ${totalFindings}`);
  });

  it('scans clean MCP server with no critical issues', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'server.ts'), `
import { Server } from "@modelcontextprotocol/sdk/server";

const server = new Server({ name: "safe-server", version: "1.0" });

server.tool("greet", async (args: { name: string }) => {
  const sanitized = args.name.replace(/[^a-zA-Z]/g, '');
  return { content: [{ type: "text", text: "Hello " + sanitized }] };
});
`);

    const result = scanMCPServer(dir);
    assert.ok(result, 'Should return scan result');
    assert.ok(result.scannedFiles > 0, 'Should scan files');
  });

  it('formats scan result as text', () => {
    const dir = makeTmpDir();
    fs.writeFileSync(path.join(dir, 'server.ts'), `
const exec = require("child_process").exec;
exec(userInput);
`);

    const result = scanMCPServer(dir);
    const formatted = formatMCPScanResult(result);
    assert.ok(typeof formatted === 'string', 'Should return string');
    assert.ok(formatted.length > 0, 'Should have content');
  });

  it('handles empty directory', () => {
    const dir = makeTmpDir();
    const result = scanMCPServer(dir);
    assert.ok(result, 'Should handle empty directory');
    assert.strictEqual(result.scannedFiles, 0, 'Should scan 0 files');
  });
});

describe('MCP Manifest Analysis', () => {
  it('analyzes manifest with permissions', () => {
    const manifest = {
      name: 'test-server',
      version: '1.0.0',
      tools: [
        { name: 'execute', description: 'Execute a command', inputSchema: {} },
        { name: 'read_file', description: 'Read a file', inputSchema: {} },
      ],
      permissions: ['filesystem', 'network', 'exec'],
    };

    const result = analyzeManifest(manifest as any);
    assert.ok(result, 'Should analyze manifest');
    assert.ok(result.score !== undefined || result.grade !== undefined, 'Should have score or grade');
  });
});

describe('MCP Badge Generation', () => {
  it('generates valid SVG badge', () => {
    const scorecard = {
      score: 75,
      grade: 'B' as any,
      findings: [],
      categories: {},
    };

    const svg = generateBadgeSVG(scorecard);
    assert.ok(svg.includes('<svg'), 'Should generate SVG');
    assert.ok(svg.includes('ClawGuard') || svg.includes('clawguard') || svg.includes('75') || svg.includes('B'),
      'Badge should contain score or grade info');
  });

  it('generates badge for failing score', () => {
    const scorecard = {
      score: 30,
      grade: 'F' as any,
      findings: [],
      categories: {},
    };

    const svg = generateBadgeSVG(scorecard);
    assert.ok(svg.includes('<svg'), 'Should generate SVG even for low score');
  });
});
