// ClawGuard — AI Rule Generator barrel export
export { generateFromDescription, generateFromCve, generateFromFile, createInteractiveSession, interactiveRound, saveRules, getProvider, createOpenAIProvider, createAnthropicProvider, createOllamaProvider } from './rule-generator';
export type { LLMProvider, InteractiveSession } from './rule-generator';
export { fetchCve } from './cve-fetcher';
export type { CveDetail } from './cve-fetcher';
export { SYSTEM_PROMPT, FROM_DESCRIPTION_PROMPT, FROM_CVE_PROMPT, FROM_CODE_PROMPT, RED_TEAM_ANALYZE_PROMPT, RED_TEAM_GENERATE_RULES_PROMPT, FEW_SHOT_EXAMPLE, buildPrompt } from './prompt-templates';
export { runRedTeam, runBuiltinAttacks, formatReport, BUILTIN_ATTACKS } from './red-team';
export type { AttackTemplate, RedTeamResult, RedTeamReport } from './red-team';
