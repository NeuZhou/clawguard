// ClawGuard — Cost Calculation Engine

export interface ModelPricing {
  input: number;  // USD per 1M tokens
  output: number; // USD per 1M tokens
}

const MODEL_PRICING: Record<string, ModelPricing> = {
  // OpenAI
  'gpt-4o': { input: 2.50, output: 10.00 },
  'gpt-4o-mini': { input: 0.15, output: 0.60 },
  'gpt-4-turbo': { input: 10.00, output: 30.00 },
  'gpt-4': { input: 30.00, output: 60.00 },
  'gpt-3.5-turbo': { input: 0.50, output: 1.50 },
  'o1': { input: 15.00, output: 60.00 },
  'o1-mini': { input: 3.00, output: 12.00 },
  'o1-pro': { input: 150.00, output: 600.00 },
  'o3': { input: 10.00, output: 40.00 },
  'o3-mini': { input: 1.10, output: 4.40 },
  'o4-mini': { input: 1.10, output: 4.40 },
  // Anthropic
  'claude-opus-4': { input: 15.00, output: 75.00 },
  'claude-sonnet-4': { input: 3.00, output: 15.00 },
  'claude-3.5-sonnet': { input: 3.00, output: 15.00 },
  'claude-3.5-haiku': { input: 0.80, output: 4.00 },
  'claude-3-opus': { input: 15.00, output: 75.00 },
  'claude-3-sonnet': { input: 3.00, output: 15.00 },
  'claude-3-haiku': { input: 0.25, output: 1.25 },
  // Google
  'gemini-2.0-pro': { input: 1.25, output: 5.00 },
  'gemini-2.0-flash': { input: 0.10, output: 0.40 },
  'gemini-1.5-pro': { input: 1.25, output: 5.00 },
  'gemini-1.5-flash': { input: 0.075, output: 0.30 },
  // Meta
  'llama-3.3-70b': { input: 0.60, output: 0.60 },
  'llama-3.1-405b': { input: 3.00, output: 3.00 },
  'llama-3.1-70b': { input: 0.60, output: 0.60 },
  // DeepSeek
  'deepseek-v3': { input: 0.27, output: 1.10 },
  'deepseek-r1': { input: 0.55, output: 2.19 },
  // Mistral
  'mistral-large': { input: 2.00, output: 6.00 },
  'mistral-medium': { input: 2.70, output: 8.10 },
  'mistral-small': { input: 0.20, output: 0.60 },
  // GitHub Copilot (included in subscription)
  'github-copilot/claude-opus-4': { input: 0, output: 0 },
  'github-copilot/claude-opus-4.6': { input: 0, output: 0 },
  'github-copilot/claude-sonnet-4': { input: 0, output: 0 },
  'github-copilot/claude-3.5-sonnet': { input: 0, output: 0 },
  'github-copilot/gpt-4o': { input: 0, output: 0 },
  'github-copilot/gpt-4o-mini': { input: 0, output: 0 },
  'github-copilot/o3-mini': { input: 0, output: 0 },
};

export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

export function getModelPricing(model: string): ModelPricing {
  // Direct match
  if (MODEL_PRICING[model]) return MODEL_PRICING[model];
  // Partial match (e.g., "gpt-4o-2024-08-06" → "gpt-4o")
  for (const key of Object.keys(MODEL_PRICING)) {
    if (model.startsWith(key) || model.includes(key)) {
      return MODEL_PRICING[key];
    }
  }
  // Default: assume mid-range
  return { input: 1.00, output: 3.00 };
}

export function calculateCost(tokens: number, direction: 'inbound' | 'outbound', model?: string): number {
  const pricing = getModelPricing(model || 'gpt-4o');
  const rate = direction === 'inbound' ? pricing.input : pricing.output;
  return (tokens / 1_000_000) * rate;
}

export function getAllModelPricing(): Record<string, ModelPricing> {
  return { ...MODEL_PRICING };
}


