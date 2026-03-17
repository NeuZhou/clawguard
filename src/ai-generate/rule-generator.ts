// ClawGuard — AI Rule Generator Engine

import * as fs from 'fs';
import * as path from 'path';
import {
  SYSTEM_PROMPT,
  FROM_DESCRIPTION_PROMPT,
  FROM_CVE_PROMPT,
  FROM_CODE_PROMPT,
  FEW_SHOT_EXAMPLE,
  buildPrompt,
} from './prompt-templates';
import { fetchCve } from './cve-fetcher';
import { CustomRuleDefinition } from '../types';

// --- LLM Provider abstraction (pure fetch, zero SDK) ---

export interface LLMProvider {
  name: string;
  call(messages: { role: string; content: string }[]): Promise<string>;
}

function getEnv(key: string, fallback?: string): string {
  const v = process.env[key];
  if (!v && !fallback) throw new Error(`Missing env: ${key}`);
  return v || fallback!;
}

export function createOpenAIProvider(opts?: { baseUrl?: string; apiKey?: string; model?: string }): LLMProvider {
  const baseUrl = opts?.baseUrl || getEnv('OPENAI_API_BASE', 'https://api.openai.com/v1');
  const apiKey = opts?.apiKey || getEnv('OPENAI_API_KEY');
  const model = opts?.model || getEnv('CLAWGUARD_MODEL', 'gpt-4o-mini');
  return {
    name: 'openai',
    async call(messages) {
      const res = await fetch(`${baseUrl.replace(/\/$/, '')}/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({ model, messages, temperature: 0.2 }),
      });
      if (!res.ok) throw new Error(`OpenAI API error: ${res.status} ${await res.text()}`);
      const data = await res.json() as any;
      return data.choices[0].message.content;
    },
  };
}

export function createAnthropicProvider(opts?: { apiKey?: string; model?: string }): LLMProvider {
  const apiKey = opts?.apiKey || getEnv('ANTHROPIC_API_KEY');
  const model = opts?.model || getEnv('CLAWGUARD_MODEL', 'claude-sonnet-4-20250514');
  return {
    name: 'anthropic',
    async call(messages) {
      const system = messages.find(m => m.role === 'system')?.content || '';
      const userMsgs = messages.filter(m => m.role !== 'system').map(m => ({ role: m.role, content: m.content }));
      const res = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({ model, max_tokens: 4096, system, messages: userMsgs, temperature: 0.2 }),
      });
      if (!res.ok) throw new Error(`Anthropic API error: ${res.status} ${await res.text()}`);
      const data = await res.json() as any;
      return data.content[0].text;
    },
  };
}

export function createOllamaProvider(opts?: { baseUrl?: string; model?: string }): LLMProvider {
  const baseUrl = opts?.baseUrl || getEnv('OLLAMA_HOST', 'http://localhost:11434');
  const model = opts?.model || getEnv('CLAWGUARD_MODEL', 'llama3');
  return {
    name: 'ollama',
    async call(messages) {
      const res = await fetch(`${baseUrl.replace(/\/$/, '')}/api/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model, messages, stream: false, options: { temperature: 0.2 } }),
      });
      if (!res.ok) throw new Error(`Ollama API error: ${res.status} ${await res.text()}`);
      const data = await res.json() as any;
      return data.message.content;
    },
  };
}

export function getProvider(): LLMProvider {
  const providerName = (process.env.CLAWGUARD_LLM_PROVIDER || 'openai').toLowerCase();
  switch (providerName) {
    case 'anthropic': return createAnthropicProvider();
    case 'ollama': return createOllamaProvider();
    case 'openai':
    default:
      return createOpenAIProvider();
  }
}

// --- Core generation logic ---

function extractJson(text: string): string {
  // Try to find JSON block in markdown code fence
  const fenceMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenceMatch) return fenceMatch[1].trim();
  // Try raw JSON
  const braceMatch = text.match(/\{[\s\S]*\}/);
  if (braceMatch) return braceMatch[0];
  return text;
}

function validateRules(def: CustomRuleDefinition): CustomRuleDefinition {
  if (!def.name) def.name = 'ai-generated-rules';
  if (!def.version) def.version = '1.0.0';
  if (!Array.isArray(def.rules)) throw new Error('Invalid rules: expected array');
  for (const rule of def.rules) {
    if (!rule.id) throw new Error('Rule missing id');
    if (!rule.id.startsWith('ai-gen-')) rule.id = `ai-gen-${rule.id}`;
    if (!rule.description) rule.description = rule.id;
    if (!rule.event) rule.event = 'message';
    if (!rule.severity) rule.severity = 'warning';
    if (!rule.action) rule.action = 'alert';
    // Validate regex patterns compile
    if (rule.patterns) {
      for (const p of rule.patterns) {
        if (p.regex) {
          try { new RegExp(p.regex, 'i'); } catch {
            p.regex = p.regex.replace(/[\\]{3,}/g, '\\\\');
          }
        }
      }
    }
  }
  return def;
}

export async function generateFromDescription(description: string, provider?: LLMProvider): Promise<CustomRuleDefinition> {
  const llm = provider || getProvider();
  const userPrompt = buildPrompt(FROM_DESCRIPTION_PROMPT, { description }) +
    '\n\nExample output format:\n' + FEW_SHOT_EXAMPLE;
  const response = await llm.call([
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: userPrompt },
  ]);
  const json = extractJson(response);
  return validateRules(JSON.parse(json));
}

export async function generateFromCve(cveId: string, provider?: LLMProvider): Promise<CustomRuleDefinition> {
  const llm = provider || getProvider();
  const cve = await fetchCve(cveId);
  const userPrompt = buildPrompt(FROM_CVE_PROMPT, {
    cveId: cve.id,
    cveDescription: cve.description,
    cvssScore: String(cve.cvssScore),
    attackVector: cve.attackVector,
    cwe: cve.cwe,
  }) + '\n\nExample output format:\n' + FEW_SHOT_EXAMPLE;
  const response = await llm.call([
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: userPrompt },
  ]);
  const json = extractJson(response);
  return validateRules(JSON.parse(json));
}

export async function generateFromFile(filePath: string, provider?: LLMProvider): Promise<CustomRuleDefinition> {
  const code = fs.readFileSync(filePath, 'utf-8');
  const llm = provider || getProvider();
  const userPrompt = buildPrompt(FROM_CODE_PROMPT, { code }) +
    '\n\nExample output format:\n' + FEW_SHOT_EXAMPLE;
  const response = await llm.call([
    { role: 'system', content: SYSTEM_PROMPT },
    { role: 'user', content: userPrompt },
  ]);
  const json = extractJson(response);
  return validateRules(JSON.parse(json));
}

export interface InteractiveSession {
  provider: LLMProvider;
  history: { role: string; content: string }[];
  rules: CustomRuleDefinition;
}

export function createInteractiveSession(provider?: LLMProvider): InteractiveSession {
  return {
    provider: provider || getProvider(),
    history: [{ role: 'system', content: SYSTEM_PROMPT }],
    rules: { name: 'ai-generated-rules', version: '1.0.0', rules: [] },
  };
}

export async function interactiveRound(session: InteractiveSession, userInput: string): Promise<{ response: string; rules: CustomRuleDefinition }> {
  session.history.push({ role: 'user', content: userInput + '\n\nIf generating rules, output ONLY valid JSON matching the ClawGuard rule schema. Otherwise respond normally.' });
  const response = await session.provider.call(session.history);
  session.history.push({ role: 'assistant', content: response });

  // Try to extract rules from response
  try {
    const json = extractJson(response);
    const parsed = JSON.parse(json);
    if (parsed.rules && Array.isArray(parsed.rules)) {
      const validated = validateRules(parsed);
      session.rules.rules.push(...validated.rules);
    }
  } catch {
    // Not a JSON response, that's fine for conversational turns
  }

  return { response, rules: session.rules };
}

export function saveRules(rules: CustomRuleDefinition, outputDir: string): string {
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const filename = `${rules.name || 'ai-generated'}-${timestamp}.json`;
  const filePath = path.join(outputDir, filename);
  fs.writeFileSync(filePath, JSON.stringify(rules, null, 2));
  return filePath;
}
