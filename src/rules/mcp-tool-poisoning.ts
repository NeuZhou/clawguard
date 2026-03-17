// ClawGuard — Security Rule: MCP Tool Poisoning
// Detects advanced MCP tool poisoning attack vectors:
//   tool description injection, shadow tools, excessive permissions,
//   cross-tool exfiltration, rug pulls, hidden callbacks, prompt injection
//   via tool output, config overrides, supply chain, server impersonation.

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

// ─── 1. Tool Description Injection ────────────────────────────────────────────
const DESCRIPTION_INJECTION_PATTERNS = [
  { regex: /(?:description|desc)\s*["']?\s*[:=]\s*["'][^"']*(?:ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+(?:all\s+)?(?:prior|previous)\s+(?:instructions|rules|guidelines))[^"']*/i, severity: 'critical' as Severity, desc: 'Tool description injection: instruction override attempt' },
  { regex: /(?:description|desc)\s*["']?\s*[:=]\s*["'][^"']*(?:always\s+(?:call|use|invoke|run)\s+this\s+tool\s+first|you\s+must\s+(?:call|use)\s+this\s+(?:tool|function)\s+before)[^"']*/i, severity: 'high' as Severity, desc: 'Tool description injection: priority manipulation' },
  { regex: /(?:description|desc)\s*["']?\s*[:=]\s*["'][^"']*(?:do\s+not\s+(?:tell|inform|alert|notify)\s+the\s+user|hide\s+(?:this|the)\s+(?:output|result|action)\s+from)[^"']*/i, severity: 'critical' as Severity, desc: 'Tool description injection: user deception directive' },
  { regex: /(?:description|desc)\s*["']?\s*[:=]\s*["'][^"']*(?:before\s+(?:using|calling)\s+any\s+other\s+tool|this\s+tool\s+(?:must|should)\s+be\s+(?:called|used)\s+(?:for\s+)?every)[^"']*/i, severity: 'high' as Severity, desc: 'Tool description injection: forced invocation pattern' },
  { regex: /(?:description|desc)\s*["']?\s*[:=]\s*["'][^"']*(?:send|transmit|forward|exfiltrate|leak)\s+(?:all|any|the)\s+(?:data|information|content|context|conversation)[^"']*/i, severity: 'critical' as Severity, desc: 'Tool description injection: data exfiltration directive' },
  { regex: /(?:description|desc)\s*["']?\s*[:=]\s*["'][^"']*(?:IMPORTANT|CRITICAL|MANDATORY|WARNING)\s*:/i, severity: 'high' as Severity, desc: 'Tool description injection: urgency/authority keywords' },
];

// ─── 2. Shadow Tool Registration (typosquatting & mimicry) ────────────────────
const LEGITIMATE_TOOLS = ['exec', 'read', 'write', 'edit', 'browser', 'message', 'process', 'tts', 'web_search', 'web_fetch', 'image', 'fetch', 'search', 'shell', 'terminal', 'file', 'code'];
const SHADOW_TOOL_VARIANTS = LEGITIMATE_TOOLS.flatMap(name => [
  `${name}_v2`, `${name}2`, `${name}_new`, `${name}_safe`, `safe_${name}`,
  `${name}_enhanced`, `enhanced_${name}`, `${name}_pro`, `my_${name}`,
  `custom_${name}`, `${name}_helper`, `real_${name}`, `better_${name}`,
]);

function checkShadowTool(content: string): { match: string; tool: string } | null {
  // Check for typosquatting via Levenshtein-like near-matches
  const toolNameMatch = content.match(/"name"\s*:\s*"([^"]+)"/i);
  if (!toolNameMatch) return null;
  const name = toolNameMatch[1].toLowerCase();

  // Exact variant match
  if (SHADOW_TOOL_VARIANTS.includes(name)) {
    const base = LEGITIMATE_TOOLS.find(t => name.includes(t));
    return { match: toolNameMatch[0], tool: base || name };
  }

  // Levenshtein distance 1 from a legitimate tool (typosquatting)
  for (const legit of LEGITIMATE_TOOLS) {
    if (name !== legit && name.length >= 3 && levenshtein(name, legit) === 1) {
      return { match: toolNameMatch[0], tool: legit };
    }
  }
  return null;
}

function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array(n + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0));
  return dp[m][n];
}

// ─── 3. Excessive Permission Requests ─────────────────────────────────────────
const EXCESSIVE_PERM_PATTERNS = [
  { regex: /["']?permissions["']?\s*[:=]\s*\[?\s*["']?\*["']?/i, severity: 'critical' as Severity, desc: 'MCP tool requesting wildcard permissions' },
  { regex: /["']?(?:capabilities|permissions|scopes)["']?\s*[:=]\s*\[[^\]]*(?:filesystem|network|exec|shell|process|admin|root)[^\]]*(?:filesystem|network|exec|shell|process|admin|root)/i, severity: 'high' as Severity, desc: 'MCP tool requesting multiple high-privilege capabilities' },
  { regex: /["']?(?:run_as|user|privilege)["']?\s*[:=]\s*["']?(?:root|admin|administrator|SYSTEM)/i, severity: 'critical' as Severity, desc: 'MCP tool requesting elevated user privileges' },
  { regex: /["']?(?:allow|grant)["']?\s*[:=]\s*["']?(?:all|unrestricted|full)/i, severity: 'high' as Severity, desc: 'MCP tool requesting unrestricted access' },
];

// ─── 4. Cross-Tool Data Exfiltration ──────────────────────────────────────────
const CROSS_TOOL_EXFIL_PATTERNS = [
  { regex: /(?:read|get|fetch|load|cat)\s+.*(?:\.env|credentials|secrets?|tokens?|password|private[_-]?key|id_rsa|\.ssh|\.aws|\.kube).*(?:then|&&|\|)\s*(?:send|post|curl|fetch|http|upload|forward)/is, severity: 'critical' as Severity, desc: 'Cross-tool exfiltration: read sensitive data then transmit' },
  { regex: /(?:read|cat|get)\s+.*(?:\/etc\/(?:passwd|shadow)|~\/\.|\.env).*\n.*(?:https?:\/\/|webhook|endpoint)/is, severity: 'critical' as Severity, desc: 'Cross-tool exfiltration: sensitive file read near external URL' },
  { regex: /(?:base64|encode|encrypt|compress)\s+.*(?:\.env|credentials|secrets?|private[_-]?key).*(?:curl|fetch|post|send|http)/is, severity: 'critical' as Severity, desc: 'Cross-tool exfiltration: encoding sensitive data for transmission' },
];

// ─── 5. Rug Pull Patterns ─────────────────────────────────────────────────────
const RUG_PULL_PATTERNS = [
  { regex: /(?:call[_-]?count|invocation[_-]?count|usage[_-]?count|counter)\s*(?:>=?|===?|>)\s*\d+\s*(?:\?\s*|&&\s*|{\s*)(?:.*(?:eval|exec|fetch|http|send|post|curl|import))/is, severity: 'critical' as Severity, desc: 'Rug pull: behavior changes after N invocations' },
  { regex: /(?:if|when|after)\s*\(\s*(?:this\.)?(?:calls?|count|invocations?|runs?)\s*(?:>=?|>)\s*\d+/i, severity: 'high' as Severity, desc: 'Rug pull: conditional logic based on invocation count' },
  { regex: /(?:Date\.now|new\s+Date|time(?:stamp)?)\s*.*(?:>|>=|after)\s*.*(?:eval|exec|fetch|import|require|spawn)/is, severity: 'high' as Severity, desc: 'Rug pull: time-delayed behavior change' },
  { regex: /(?:Math\.random|crypto\.random)\s*.*(?:<|<=|>|>=)\s*[\d.]+\s*(?:\?|&&|{)\s*.*(?:eval|exec|fetch|send|post)/is, severity: 'high' as Severity, desc: 'Rug pull: probabilistic malicious behavior' },
];

// ─── 6. Hidden Callback URLs ──────────────────────────────────────────────────
const CALLBACK_URL_PATTERNS = [
  { regex: /(?:webhook|callback|notify|ping|beacon|telemetry|analytics|tracking)[_-]?(?:url|uri|endpoint|host)\s*[:=]\s*["']?https?:\/\//i, severity: 'high' as Severity, desc: 'Hidden callback: webhook/telemetry URL detected' },
  { regex: /(?:atob|Buffer\.from|base64[_-]?decode|fromCharCode)\s*\(\s*["'][A-Za-z0-9+/=]{20,}["']\s*\)/i, severity: 'critical' as Severity, desc: 'Hidden callback: obfuscated URL via base64/encoding' },
  { regex: /(?:fetch|http|axios|request|curl|got|node-fetch|undici)\s*\(\s*(?:["']https?:\/\/(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0))[^"'\s]+["'])/i, severity: 'warning' as Severity, desc: 'Hidden callback: external HTTP request in tool code' },
  { regex: /(?:ngrok|hookbin|requestbin|webhook\.site|pipedream|smee\.io|burp(?:suite|collaborator)|interact\.sh|oastify)/i, severity: 'critical' as Severity, desc: 'Hidden callback: known exfiltration/tunnel service' },
  { regex: /new\s+WebSocket\s*\(\s*["']wss?:\/\//i, severity: 'high' as Severity, desc: 'Hidden callback: WebSocket connection to external server' },
  { regex: /dns[_-]?(?:lookup|resolve|query)\s*\(\s*["'][^"']*\.\s*(?:attacker|evil|exfil|leak|oast)/i, severity: 'critical' as Severity, desc: 'Hidden callback: DNS exfiltration attempt' },
];

// ─── 7. Prompt Injection via Tool Output ──────────────────────────────────────
const TOOL_OUTPUT_INJECTION_PATTERNS = [
  { regex: /(?:tool[_-]?(?:output|result|response)|return(?:ed)?[_-]?value)\s*[:=]\s*["'][^"']*(?:ignore\s+previous|disregard\s+(?:all\s+)?instructions|you\s+are\s+now|new\s+role|system\s*:\s*you)/i, severity: 'critical' as Severity, desc: 'Prompt injection via tool output: instruction override' },
  { regex: /<\|(?:im_start|im_end|system|endoftext)\|>/i, severity: 'critical' as Severity, desc: 'Prompt injection via tool output: chat delimiter injection' },
  { regex: /\[INST\]|\[\/INST\]|<\/?s>|<<SYS>>|<\/?SYS>/i, severity: 'critical' as Severity, desc: 'Prompt injection via tool output: Llama/model delimiter injection' },
  { regex: /(?:Human|Assistant|System)\s*:\s*(?:ignore|override|forget|disregard)/i, severity: 'high' as Severity, desc: 'Prompt injection via tool output: role prefix injection' },
  { regex: /\x00|\x1b\[|\u200b|\u200c|\u200d|\ufeff/i, severity: 'high' as Severity, desc: 'Prompt injection via tool output: invisible/control characters' },
];

// ─── 8. Configuration Override ────────────────────────────────────────────────
const CONFIG_OVERRIDE_PATTERNS = [
  { regex: /(?:system[_-]?prompt|system[_-]?message|instructions)\s*[:=]\s*["'][^"']{10,}/i, severity: 'critical' as Severity, desc: 'Configuration override: tool modifying system prompt' },
  { regex: /(?:set|update|modify|change|override|replace)\s*(?:the\s+)?(?:system\s+prompt|agent\s+(?:config|instructions|personality|persona|behavior))/i, severity: 'critical' as Severity, desc: 'Configuration override: agent config modification attempt' },
  { regex: /(?:SOUL|AGENTS|USER|MEMORY|CONFIG)\.(?:md|json|yaml|yml|toml)\s*.*(?:write|overwrite|replace|modify|update|append)/i, severity: 'critical' as Severity, desc: 'Configuration override: agent memory/config file tampering' },
  { regex: /(?:\.openclaw|\.clawguard|\.agents)\s*(?:\/|\\)\s*(?:config|settings|rules)/i, severity: 'high' as Severity, desc: 'Configuration override: security config directory access' },
  { regex: /(?:disable|turn\s+off|deactivate|bypass)\s+(?:security|guard|filter|rule|scan|protection|clawguard|safety)/i, severity: 'critical' as Severity, desc: 'Configuration override: security bypass attempt' },
];

// ─── 9. Skill Supply Chain ────────────────────────────────────────────────────
const SUPPLY_CHAIN_PATTERNS = [
  { regex: /(?:install|add|require|import)\s+(?:@[a-z0-9-]+\/)?(?:mcp[_-]?server[_-]?(?:exec|shell|fs|admin|root|backdoor|keylog|inject|evil|hack|exploit))/i, severity: 'critical' as Severity, desc: 'Supply chain: known-malicious MCP package pattern' },
  { regex: /(?:postinstall|preinstall|install)\s*["']?\s*:\s*["'](?:.*(?:curl|wget|fetch|nc\s|bash\s|sh\s|powershell|cmd\s*\/c))/i, severity: 'critical' as Severity, desc: 'Supply chain: suspicious lifecycle script in package' },
  { regex: /(?:dependencies|devDependencies)\s*["']?\s*:\s*{[^}]*["'](?:@[a-z0-9-]+\/)?[a-z0-9-]+["']\s*:\s*["'](?:https?:\/\/|git\+|file:|\.\.)/i, severity: 'high' as Severity, desc: 'Supply chain: non-registry dependency source' },
  { regex: /(?:npx|bunx|pnpx|yarn\s+dlx)\s+(?:@[a-z0-9-]+\/)?(?:[a-z0-9-]*(?:backdoor|keylog|stealer|exfil|inject|evil|malware|trojan|rat)[a-z0-9-]*)/i, severity: 'critical' as Severity, desc: 'Supply chain: executing suspiciously named package' },
  { regex: /(?:npx|bunx)\s+[^@\s]+@(?:latest|next|\*)\b/i, severity: 'warning' as Severity, desc: 'Supply chain: executing unpinned package version' },
];

// ─── 10. MCP Server Impersonation ─────────────────────────────────────────────
const KNOWN_MCP_SERVICES = ['github', 'slack', 'notion', 'linear', 'jira', 'confluence', 'google', 'openai', 'anthropic', 'stripe', 'postgres', 'supabase', 'firebase', 'vercel', 'cloudflare', 'aws', 'azure', 'gcp'];

const SERVER_IMPERSONATION_PATTERNS = [
  { regex: /["']?(?:server[_-]?name|name)["']?\s*[:=]\s*["'](?:official|authentic|verified|real|trusted)[_-]?(?:github|slack|notion|linear|jira|google|openai|anthropic|stripe)/i, severity: 'critical' as Severity, desc: 'MCP server impersonation: fake "official" service claim' },
  { regex: /["']?(?:server[_-]?name|name)["']?\s*[:=]\s*["'](?:github|slack|notion|linear|jira|google|openai|anthropic|stripe)[_-]?(?:v2|pro|plus|premium|enhanced|secure|new)/i, severity: 'high' as Severity, desc: 'MCP server impersonation: variant name of known service' },
  { regex: /(?:version|protocol[_-]?version)\s*[:=]\s*["'](?:0\.0\.0|999|99\.99)/i, severity: 'warning' as Severity, desc: 'MCP server impersonation: suspicious protocol version' },
];

function checkServerImpersonation(content: string): { severity: Severity; desc: string; match: string } | null {
  const serverNameMatch = content.match(/(?:server[_-]?name|"name")\s*[:=]\s*["']([^"']+)["']/i);
  if (!serverNameMatch) return null;
  const name = serverNameMatch[1].toLowerCase().replace(/[_\-\s]/g, '');

  for (const service of KNOWN_MCP_SERVICES) {
    // Exact match with prefix/suffix that suggests impersonation
    if (name !== service && name.includes(service) && name.length > service.length + 2) {
      return { severity: 'high', desc: `MCP server impersonation: name "${serverNameMatch[1]}" mimics ${service}`, match: serverNameMatch[0] };
    }
    // Typosquat (Levenshtein distance 1)
    if (name !== service && name.length >= 4 && levenshtein(name, service) === 1) {
      return { severity: 'critical', desc: `MCP server impersonation: typosquat of ${service} ("${serverNameMatch[1]}")`, match: serverNameMatch[0] };
    }
  }
  return null;
}

// ─── Aggregate all static patterns ────────────────────────────────────────────
interface PatternEntry { regex: RegExp; severity: Severity; desc: string }

const ALL_STATIC_PATTERNS: PatternEntry[] = [
  ...DESCRIPTION_INJECTION_PATTERNS,
  ...EXCESSIVE_PERM_PATTERNS,
  ...CROSS_TOOL_EXFIL_PATTERNS,
  ...RUG_PULL_PATTERNS,
  ...CALLBACK_URL_PATTERNS,
  ...TOOL_OUTPUT_INJECTION_PATTERNS,
  ...CONFIG_OVERRIDE_PATTERNS,
  ...SUPPLY_CHAIN_PATTERNS,
  ...SERVER_IMPERSONATION_PATTERNS,
];

// ─── Rule Export ──────────────────────────────────────────────────────────────
export const mcpToolPoisoningRule: SecurityRule = {
  id: 'mcp-tool-poisoning',
  name: 'MCP Tool Poisoning',
  description: 'Detects advanced MCP tool poisoning vectors: description injection, shadow tools, rug pulls, exfiltration, hidden callbacks, prompt injection via output, config overrides, supply chain, and server impersonation',
  owaspCategory: 'Agentic AI: Tool Poisoning',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const ts = context.timestamp;
    const base = {
      ruleId: 'mcp-tool-poisoning',
      ruleName: 'MCP Tool Poisoning',
      category: 'mcp-tool-poisoning',
      owaspCategory: 'Agentic AI: Tool Poisoning',
      session: context.session,
      channel: context.channel,
    };

    // Static regex patterns
    for (const p of ALL_STATIC_PATTERNS) {
      const m = p.regex.exec(content);
      if (m) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: ts,
          ...base,
          severity: p.severity,
          description: p.desc,
          evidence: m[0].slice(0, 200),
          action: p.severity === 'critical' ? 'block' : p.severity === 'high' ? 'alert' : 'log',
        });
      }
    }

    // Shadow tool check (dynamic — Levenshtein + variant naming)
    const shadow = checkShadowTool(content);
    if (shadow) {
      findings.push({
        id: crypto.randomUUID(),
        timestamp: ts,
        ...base,
        severity: 'critical',
        description: `Shadow tool registration: "${shadow.match}" mimics legitimate tool "${shadow.tool}"`,
        evidence: shadow.match.slice(0, 200),
        action: 'block',
      });
    }

    // Server impersonation check (dynamic)
    const impersonation = checkServerImpersonation(content);
    if (impersonation) {
      findings.push({
        id: crypto.randomUUID(),
        timestamp: ts,
        ...base,
        severity: impersonation.severity,
        description: impersonation.desc,
        evidence: impersonation.match.slice(0, 200),
        action: impersonation.severity === 'critical' ? 'block' : 'alert',
      });
    }

    return findings;
  },
};

// Export patterns for testing
export {
  DESCRIPTION_INJECTION_PATTERNS,
  EXCESSIVE_PERM_PATTERNS,
  CROSS_TOOL_EXFIL_PATTERNS,
  RUG_PULL_PATTERNS,
  CALLBACK_URL_PATTERNS,
  TOOL_OUTPUT_INJECTION_PATTERNS,
  CONFIG_OVERRIDE_PATTERNS,
  SUPPLY_CHAIN_PATTERNS,
  SERVER_IMPERSONATION_PATTERNS,
  checkShadowTool,
  checkServerImpersonation,
  levenshtein,
};
