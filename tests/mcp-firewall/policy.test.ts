// ClawGuard — Tests: MCP Firewall Policy Engine

import { describe, it, beforeEach } from 'node:test';
import * as assert from 'node:assert';
import {
  parseFirewallConfig,
  evaluateToolPolicy,
  shouldEnforce,
  recordDataFlow,
  getDataFlowLog,
  clearDataFlowLog,
  getDataFlowSummary,
  DEFAULT_FIREWALL_CONFIG,
} from '../../src/mcp-firewall/policy';
import { FirewallConfig } from '../../src/mcp-firewall/types';

// ── Config Parsing ──

describe('MCP Firewall Policy: Config Parsing', () => {
  it('parses a minimal config', () => {
    const config = parseFirewallConfig(`
firewall:
  mode: enforce
  defaults:
    policy: monitor
`);
    assert.strictEqual(config.mode, 'enforce');
    assert.strictEqual(config.defaults.policy, 'monitor');
  });

  it('parses full config with servers', () => {
    const config = parseFirewallConfig(`
firewall:
  mode: enforce
  transports:
    - type: stdio
    - type: sse
      port: 3100
  defaults:
    policy: monitor
  servers:
    - name: filesystem
      policy: approve-writes
      tools:
        read_file: { action: allow }
        write_file: { action: approve }
        delete_file: { action: block }
  detection:
    injection_scanning: true
    rug_pull_detection: true
    parameter_sanitization: true
    output_validation: true
  alerts:
    console: true
    webhook: null
`);
    assert.strictEqual(config.mode, 'enforce');
    assert.strictEqual(config.servers.length, 1);
    assert.strictEqual(config.servers[0].name, 'filesystem');
    assert.strictEqual(config.servers[0].policy, 'approve-writes');
    assert.strictEqual(config.servers[0].tools!['read_file'].action, 'allow');
    assert.strictEqual(config.servers[0].tools!['delete_file'].action, 'block');
    assert.strictEqual(config.detection.injection_scanning, true);
    assert.strictEqual(config.alerts.console, true);
    assert.strictEqual(config.alerts.webhook, null);
  });

  it('uses defaults for missing values', () => {
    const config = parseFirewallConfig('');
    assert.strictEqual(config.mode, DEFAULT_FIREWALL_CONFIG.mode);
    assert.strictEqual(config.defaults.policy, DEFAULT_FIREWALL_CONFIG.defaults.policy);
  });

  it('parses multiple servers', () => {
    const config = parseFirewallConfig(`
firewall:
  mode: monitor
  servers:
    - name: fs
      policy: approve-writes
    - name: db
      policy: block-destructive
`);
    assert.strictEqual(config.servers.length, 2);
    assert.strictEqual(config.servers[0].name, 'fs');
    assert.strictEqual(config.servers[1].name, 'db');
    assert.strictEqual(config.servers[1].policy, 'block-destructive');
  });

  it('parses alert with tool-level alert flag', () => {
    const config = parseFirewallConfig(`
firewall:
  mode: enforce
  servers:
    - name: db
      policy: block-destructive
      tools:
        drop_table: { action: block, alert: true }
`);
    assert.strictEqual(config.servers[0].tools!['drop_table'].action, 'block');
    assert.strictEqual(config.servers[0].tools!['drop_table'].alert, true);
  });
});

// ── Policy Evaluation ──

describe('MCP Firewall Policy: Evaluation', () => {
  const config: FirewallConfig = {
    mode: 'enforce',
    transports: [{ type: 'stdio' }],
    defaults: { policy: 'monitor' },
    servers: [
      {
        name: 'filesystem',
        policy: 'approve-writes',
        tools: {
          read_file: { action: 'allow' },
          write_file: { action: 'approve' },
          delete_file: { action: 'block' },
        },
      },
      {
        name: 'database',
        policy: 'block-destructive',
        tools: {
          query: { action: 'allow' },
          drop_table: { action: 'block', alert: true },
        },
      },
    ],
    detection: {
      injection_scanning: true,
      rug_pull_detection: true,
      parameter_sanitization: true,
      output_validation: true,
    },
    alerts: { console: true, webhook: null },
  };

  it('allows tool with explicit allow rule', () => {
    const d = evaluateToolPolicy(config, 'filesystem', 'read_file');
    assert.strictEqual(d.action, 'allow');
  });

  it('blocks tool with explicit block rule', () => {
    const d = evaluateToolPolicy(config, 'filesystem', 'delete_file');
    assert.strictEqual(d.action, 'block');
  });

  it('requires approval for tool with approve rule', () => {
    const d = evaluateToolPolicy(config, 'filesystem', 'write_file');
    assert.strictEqual(d.action, 'approve');
  });

  it('uses server policy for unlisted tools (approve-writes)', () => {
    // "rename_file" is not explicitly listed but has "write" hint
    // Under approve-writes policy, write-like tools need approval
    const d = evaluateToolPolicy(config, 'filesystem', 'rename_file');
    assert.strictEqual(d.action, 'approve');
  });

  it('uses server policy for read-like tools (approve-writes allows reads)', () => {
    const d = evaluateToolPolicy(config, 'filesystem', 'list_directory');
    assert.strictEqual(d.action, 'allow');
  });

  it('blocks destructive tool under block-destructive policy', () => {
    // "delete_record" not explicitly listed, but matches block-destructive pattern
    const d = evaluateToolPolicy(config, 'database', 'delete_record');
    assert.strictEqual(d.action, 'block');
  });

  it('allows non-destructive tool under block-destructive policy', () => {
    const d = evaluateToolPolicy(config, 'database', 'list_tables');
    assert.strictEqual(d.action, 'allow');
  });

  it('uses default policy for unknown servers', () => {
    const d = evaluateToolPolicy(config, 'unknown-server', 'some_tool');
    assert.strictEqual(d.action, 'log-only', 'Default monitor policy should log-only');
  });

  it('is case-insensitive for server names', () => {
    const d = evaluateToolPolicy(config, 'FileSystem', 'read_file');
    assert.strictEqual(d.action, 'allow');
  });

  it('allows everything when mode is disabled', () => {
    const disabledConfig: FirewallConfig = { ...config, mode: 'disabled' };
    const d = evaluateToolPolicy(disabledConfig, 'filesystem', 'delete_file');
    assert.strictEqual(d.action, 'allow');
  });
});

// ── shouldEnforce ──

describe('MCP Firewall Policy: shouldEnforce', () => {
  it('returns true for enforce mode', () => {
    assert.strictEqual(shouldEnforce({ ...DEFAULT_FIREWALL_CONFIG, mode: 'enforce' }), true);
  });

  it('returns false for monitor mode', () => {
    assert.strictEqual(shouldEnforce({ ...DEFAULT_FIREWALL_CONFIG, mode: 'monitor' }), false);
  });

  it('returns false for disabled mode', () => {
    assert.strictEqual(shouldEnforce({ ...DEFAULT_FIREWALL_CONFIG, mode: 'disabled' }), false);
  });
});

// ── Data Flow Tracking ──

describe('MCP Firewall Policy: Data Flow Tracking', () => {
  beforeEach(() => {
    clearDataFlowLog();
  });

  it('records a data flow entry', () => {
    recordDataFlow({
      server: 'fs',
      tool: 'read_file',
      direction: 'request',
      paramKeys: ['path'],
      blocked: false,
    });
    const log = getDataFlowLog();
    assert.strictEqual(log.length, 1);
    assert.strictEqual(log[0].server, 'fs');
    assert.strictEqual(log[0].tool, 'read_file');
  });

  it('generates unique IDs for entries', () => {
    recordDataFlow({ server: 'a', tool: 't', direction: 'request', blocked: false });
    recordDataFlow({ server: 'b', tool: 't', direction: 'request', blocked: false });
    const log = getDataFlowLog();
    assert.notStrictEqual(log[0].id, log[1].id);
  });

  it('returns summary by server', () => {
    recordDataFlow({ server: 'fs', tool: 'read', direction: 'request', blocked: false });
    recordDataFlow({ server: 'fs', tool: 'write', direction: 'request', blocked: true });
    recordDataFlow({ server: 'db', tool: 'query', direction: 'response', blocked: false });
    const summary = getDataFlowSummary();
    assert.strictEqual(summary['fs'].requests, 2);
    assert.strictEqual(summary['fs'].blocked, 1);
    assert.strictEqual(summary['db'].responses, 1);
  });

  it('limits log entries', () => {
    const log = getDataFlowLog(5);
    assert.ok(log.length <= 5);
  });
});
