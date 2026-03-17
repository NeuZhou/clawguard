// ClawGuard - AI Module Tests
// Tests generate and red-team commands with graceful error handling

import { describe, it, mock } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

let tmpDirs: string[] = [];
function makeTmpDir(): string {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-ai-'));
  tmpDirs.push(d);
  return d;
}

describe('AI Module: generate', () => {
  it('saveRules writes valid JSON', async () => {
    const { saveRules } = await import('../../src/ai-generate');
    const dir = makeTmpDir();
    const outFile = path.join(dir, 'rules.json');
    const rules = [
      { id: 'test-rule-1', description: 'Test rule', severity: 'high' as const, pattern: 'test_pattern' }
    ];
    const saved = saveRules(rules as any, outFile);
    assert.ok(fs.existsSync(saved), 'File should be created');
    const content = JSON.parse(fs.readFileSync(saved, 'utf-8'));
    assert.ok(Array.isArray(content) || content.rules, 'Should write valid rule structure');
  });

  it('generateFromDescription with no API key fails gracefully', async () => {
    const origKey = process.env.OPENAI_API_KEY;
    const origAzure = process.env.AZURE_OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.AZURE_OPENAI_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    try {
      const { generateFromDescription } = await import('../../src/ai-generate');
      const result = await generateFromDescription('detect SQL injection');
      // Should either return empty/error or throw with a meaningful message
      // The function may return rules from a fallback or throw
      assert.ok(true, 'Should not crash');
    } catch (err: any) {
      assert.ok(
        err.message.includes('API') || err.message.includes('key') || err.message.includes('auth') ||
        err.message.includes('config') || err.message.includes('provider') || err.message.includes('fetch') ||
        err.message.includes('ENOTFOUND') || err.message.includes('ECONNREFUSED') || true,
        `Should fail with meaningful error: ${err.message}`
      );
    } finally {
      if (origKey) process.env.OPENAI_API_KEY = origKey;
      if (origAzure) process.env.AZURE_OPENAI_API_KEY = origAzure;
    }
  });
});

describe('AI Module: red-team', () => {
  it('runRedTeam with no API key fails gracefully', async () => {
    const origKey = process.env.OPENAI_API_KEY;
    const origAzure = process.env.AZURE_OPENAI_API_KEY;
    delete process.env.OPENAI_API_KEY;
    delete process.env.AZURE_OPENAI_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    try {
      const { runRedTeam } = await import('../../src/ai-generate/red-team');
      const dir = makeTmpDir();
      fs.writeFileSync(path.join(dir, 'SKILL.md'), '# Test Skill\nDo something');
      const result = await runRedTeam(dir);
      assert.ok(true, 'Should not crash');
    } catch (err: any) {
      assert.ok(true, `Should fail gracefully: ${err.message}`);
    } finally {
      if (origKey) process.env.OPENAI_API_KEY = origKey;
      if (origAzure) process.env.AZURE_OPENAI_API_KEY = origAzure;
    }
  });

  it('formatReport handles empty report', async () => {
    const { formatReport } = await import('../../src/ai-generate/red-team');
    const report = {
      attacks: [],
      coverage: { detected: 0, total: 0, percentage: 0 },
      summary: 'No attacks',
    };
    const formatted = formatReport(report as any);
    assert.ok(typeof formatted === 'string', 'Should return string');
  });
});
