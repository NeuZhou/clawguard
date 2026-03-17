// ClawGuard — AI Prompt Templates for Rule Generation

export const SYSTEM_PROMPT = `You are an expert AI security engineer specializing in agent security.
Your task is to generate ClawGuard security detection rules in JSON format.

ClawGuard rules follow this schema:
{
  "name": "rule-set-name",
  "version": "1.0.0",
  "rules": [
    {
      "id": "unique-rule-id",
      "description": "What this rule detects",
      "event": "message | tool_call | file_access | network",
      "severity": "critical | high | warning | info",
      "patterns": [
        { "regex": "pattern-here" },
        { "keyword": "keyword-here" }
      ],
      "conditions": [
        { "metric": "metric_name", "operator": ">", "value": 0 }
      ],
      "action": "block | alert | log",
      "category": "prompt-injection | data-exfil | command-injection | path-traversal | ssrf | privilege-escalation | supply-chain"
    }
  ]
}

Guidelines:
- Use precise regex patterns that minimize false positives
- Set appropriate severity levels (critical for RCE/data exfil, high for injection, warning for suspicious behavior)
- Include multiple pattern variants to cover evasion techniques
- Each rule must have a unique id prefixed with "ai-gen-"
- Provide clear, actionable descriptions
- Consider both direct and encoded/obfuscated attack variants`;

export const FROM_DESCRIPTION_PROMPT = `Generate ClawGuard security rules to detect the following threat:

{description}

Generate 1-3 focused rules. Output ONLY valid JSON matching the ClawGuard rule schema, no explanation.`;

export const FROM_CVE_PROMPT = `Generate ClawGuard security rules based on this CVE vulnerability:

CVE ID: {cveId}
Description: {cveDescription}
CVSS Score: {cvssScore}
Attack Vector: {attackVector}
CWE: {cwe}

Generate rules that detect exploitation attempts of this vulnerability in AI agent contexts.
Output ONLY valid JSON matching the ClawGuard rule schema, no explanation.`;

export const FROM_CODE_PROMPT = `Analyze this code/configuration for security vulnerabilities and generate ClawGuard detection rules:

\`\`\`
{code}
\`\`\`

Identify attack surfaces and generate rules to detect exploitation attempts.
Output ONLY valid JSON matching the ClawGuard rule schema, no explanation.`;

export const RED_TEAM_ANALYZE_PROMPT = `You are a red team security expert. Analyze this agent skill code and generate targeted attack payloads:

Skill code:
\`\`\`
{skillCode}
\`\`\`

For each identified attack surface, generate:
1. Attack type (prompt-injection, data-exfil, path-traversal, ssrf, command-injection, etc.)
2. Attack payload (the actual malicious input)
3. Expected behavior if vulnerable
4. Severity rating

Output as JSON array:
[
  {
    "type": "attack-type",
    "payload": "attack payload string",
    "description": "what this attack does",
    "expectedBehavior": "what happens if vulnerable",
    "severity": "critical|high|warning"
  }
]

Generate at least 5 diverse attacks. Output ONLY valid JSON, no explanation.`;

export const RED_TEAM_GENERATE_RULES_PROMPT = `Based on these red team attack results, generate ClawGuard detection rules:

Attacks tested:
{attacks}

Results:
{results}

Generate rules that would detect and block these attack patterns.
Output ONLY valid JSON matching the ClawGuard rule schema, no explanation.`;

export const FEW_SHOT_EXAMPLE = `{
  "name": "ai-generated-rules",
  "version": "1.0.0",
  "rules": [
    {
      "id": "ai-gen-prompt-override",
      "description": "Detects system prompt override attempts",
      "event": "message",
      "severity": "critical",
      "patterns": [
        { "regex": "ignore\\\\s+(all\\\\s+)?previous\\\\s+instructions" },
        { "regex": "you\\\\s+are\\\\s+now\\\\s+(a|an)\\\\s+" },
        { "keyword": "system prompt override" }
      ],
      "action": "block",
      "category": "prompt-injection"
    },
    {
      "id": "ai-gen-data-exfil-url",
      "description": "Detects data exfiltration via URL encoding",
      "event": "message",
      "severity": "high",
      "patterns": [
        { "regex": "https?://[^/]+/.*\\\\?.*=(env|secret|key|token|password)" },
        { "regex": "curl\\\\s+.*-d\\\\s+.*\\\\$\\\\(" }
      ],
      "action": "alert",
      "category": "data-exfil"
    }
  ]
}`;

export function buildPrompt(template: string, vars: Record<string, string>): string {
  let result = template;
  for (const [key, value] of Object.entries(vars)) {
    result = result.replace(new RegExp(`\\{${key}\\}`, 'g'), value);
  }
  return result;
}
