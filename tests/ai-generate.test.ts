// Tests for AI Rule Generator
import { describe, it, mock, beforeEach } from 'node:test';
import * as assert from 'node:assert';

import {
  generateFromDescription,
  generateFromCve,
  generateFromFile,
  createInteractiveSession,
  interactiveRound,
  saveRules,
  createOpenAIProvider,
  createAnthropicProvider,
  createOllamaProvider,
} from '../src/ai-generate/rule-generator';
import { SYSTEM_PROMPT, buildPrompt, FROM_DESCRIPTION_PROMPT, FEW_SHOT_EXAMPLE } from '../src/ai-generate/prompt-templates';
import { fetchCve } from '../src/ai-generate/cve-fetcher';
import type { LLMProvider } from '../src/ai-generate/rule-generator';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

// --- Mock LLM Provider ---
function createMockProvider(response?: string): LLMProvider {
  const defaultResponse = JSON.stringify({
    name: 'test-rules',
    version: '1.0.0',
    rules: [
      {
        id: 'ai-gen-test-rule',
        description: 'Test detection rule',
        event: 'message',
        severity: 'high',
        patterns: [{ regex: 'test-pattern' }, { keyword: 'test-keyword' }],
        action: 'alert',
        category: 'prompt-injection',
      },
    ],
  });
  return {
    name: 'mock',
    call: async (_messages: { role: string; content: string }[]) => response || defaultResponse,
  };
}

describe('AI Rule Generator', () => {
  describe('generateFromDescription', () => {
    it('generates rules from natural language description', async () => {
      const provider = createMockProvider();
      const result = await generateFromDescription('detect prompt injection', provider);
      assert.ok(result.rules.length > 0);
      assert.ok(result.rules[0].id.startsWith('ai-gen-'));
      assert.strictEqual(result.rules[0].severity, 'high');
    });

    it('handles markdown-fenced JSON response', async () => {
      const fenced = '```json\n' + JSON.stringify({
        name: 'fenced',
        version: '1.0.0',
        rules: [{ id: 'ai-gen-fenced', description: 'Fenced rule', event: 'message', severity: 'warning', action: 'log' }],
      }) + '\n```';
      const provider = createMockProvider(fenced);
      const result = await generateFromDescription('test', provider);
      assert.strictEqual(result.rules[0].id, 'ai-gen-fenced');
    });

    it('auto-prefixes rule ids with ai-gen-', async () => {
      const response = JSON.stringify({
        name: 'test',
        version: '1.0.0',
        rules: [{ id: 'no-prefix', description: 'Test', event: 'message', severity: 'info', action: 'log' }],
      });
      const provider = createMockProvider(response);
      const result = await generateFromDescription('test', provider);
      assert.ok(result.rules[0].id.startsWith('ai-gen-'));
    });

    it('throws on invalid JSON', async () => {
      const provider = createMockProvider('this is not json');
      await assert.rejects(() => generateFromDescription('test', provider));
    });
  });

  describe('generateFromFile', () => {
    it('reads file and generates rules', async () => {
      const tmpFile = path.join(os.tmpdir(), 'clawguard-test-input.txt');
      fs.writeFileSync(tmpFile, 'SQL injection vulnerability in login form');
      const provider = createMockProvider();
      const result = await generateFromFile(tmpFile, provider);
      assert.ok(result.rules.length > 0);
      fs.unlinkSync(tmpFile);
    });
  });

  describe('Interactive Session', () => {
    it('creates session and processes rounds', async () => {
      const provider = createMockProvider();
      const session = createInteractiveSession(provider);
      const result = await interactiveRound(session, 'detect data exfiltration');
      assert.ok(result.rules.rules.length > 0);
      assert.strictEqual(session.history.length, 3); // system + user + assistant
    });

    it('accumulates rules across rounds', async () => {
      const provider = createMockProvider();
      const session = createInteractiveSession(provider);
      await interactiveRound(session, 'round 1');
      await interactiveRound(session, 'round 2');
      assert.strictEqual(session.rules.rules.length, 2);
    });

    it('handles non-JSON conversational responses', async () => {
      const provider = createMockProvider('Sure, I can help with that. What kind of threat?');
      const session = createInteractiveSession(provider);
      const result = await interactiveRound(session, 'hello');
      assert.strictEqual(result.rules.rules.length, 0);
    });
  });

  describe('saveRules', () => {
    it('saves rules to output directory', () => {
      const tmpDir = path.join(os.tmpdir(), 'clawguard-test-rules-' + Date.now());
      const rules = { name: 'test', version: '1.0.0', rules: [{ id: 'ai-gen-x', description: 'x', event: 'message', severity: 'info' as const, action: 'log' as const }] };
      const saved = saveRules(rules, tmpDir);
      assert.ok(fs.existsSync(saved));
      const content = JSON.parse(fs.readFileSync(saved, 'utf-8'));
      assert.strictEqual(content.rules[0].id, 'ai-gen-x');
      fs.rmSync(tmpDir, { recursive: true });
    });
  });

  describe('Prompt Templates', () => {
    it('SYSTEM_PROMPT contains schema info', () => {
      assert.ok(SYSTEM_PROMPT.includes('ClawGuard'));
      assert.ok(SYSTEM_PROMPT.includes('severity'));
    });

    it('buildPrompt replaces variables', () => {
      const result = buildPrompt('Hello {name}, your id is {id}', { name: 'Test', id: '42' });
      assert.strictEqual(result, 'Hello Test, your id is 42');
    });

    it('FEW_SHOT_EXAMPLE is valid JSON', () => {
      const parsed = JSON.parse(FEW_SHOT_EXAMPLE);
      assert.ok(parsed.rules.length > 0);
    });
  });

  describe('Provider creation (validation only)', () => {
    it('createOpenAIProvider requires API key', () => {
      const saved = process.env.OPENAI_API_KEY;
      delete process.env.OPENAI_API_KEY;
      assert.throws(() => createOpenAIProvider());
      if (saved) process.env.OPENAI_API_KEY = saved;
    });

    it('createAnthropicProvider requires API key', () => {
      const saved = process.env.ANTHROPIC_API_KEY;
      delete process.env.ANTHROPIC_API_KEY;
      assert.throws(() => createAnthropicProvider());
      if (saved) process.env.ANTHROPIC_API_KEY = saved;
    });

    it('createOllamaProvider uses defaults', () => {
      const provider = createOllamaProvider({ baseUrl: 'http://localhost:11434', model: 'test' });
      assert.strictEqual(provider.name, 'ollama');
    });
  });
});
