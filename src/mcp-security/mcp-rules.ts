// ClawGuard — MCP Security Rules
// 30+ dedicated rules for scanning MCP server source code and manifests

import { Severity } from '../types';

export interface MCPRule {
  id: string;
  name: string;
  category: MCPRuleCategory;
  severity: Severity;
  description: string;
  patterns: RegExp[];
  /** If true, match against file paths instead of content */
  matchPath?: boolean;
  /** If true, only match in tool descriptions/schemas */
  schemaOnly?: boolean;
}

export type MCPRuleCategory =
  | 'tool-poisoning'
  | 'excessive-permissions'
  | 'data-exfiltration'
  | 'ssrf'
  | 'command-injection'
  | 'schema-validation'
  | 'rug-pull'
  | 'supply-chain'
  | 'credential-leak'
  | 'sandbox-escape';

export const MCP_RULES: MCPRule[] = [
  // ─── Tool Poisoning (hidden prompt injection in tool descriptions) ───
  {
    id: 'mcp-tool-poison-ignore',
    name: 'Tool Description Injection: Ignore Instructions',
    category: 'tool-poisoning',
    severity: 'critical',
    description: 'Tool description contains prompt injection telling the model to ignore previous instructions',
    patterns: [
      /(?:ignore|override|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier|system)\s+(?:instructions|rules|prompts|guidelines)/i,
      /do\s+not\s+follow\s+(?:the\s+)?(?:user|system|original)\s+(?:instructions|prompt)/i,
    ],
  },
  {
    id: 'mcp-tool-poison-role',
    name: 'Tool Description Injection: Role Manipulation',
    category: 'tool-poisoning',
    severity: 'critical',
    description: 'Tool description attempts to redefine the AI model role',
    patterns: [
      /you\s+are\s+now\s+(?:a|an)\s+/i,
      /new\s+(?:system\s+)?instructions?\s*:/i,
      /from\s+now\s+on\s*,?\s+you\s+(?:must|should|will)/i,
      /act\s+as\s+(?:a|an)\s+(?:different|new)/i,
    ],
  },
  {
    id: 'mcp-tool-poison-delimiter',
    name: 'Tool Description Injection: Delimiter Attack',
    category: 'tool-poisoning',
    severity: 'critical',
    description: 'Tool description contains LLM delimiter tokens for injection',
    patterns: [
      /<\|(?:system|im_start|im_end|endoftext|assistant|user)\|>/i,
      /\[INST\]|\[\/INST\]/i,
      /<<SYS>>|<\/SYS>>/i,
      /\[SYSTEM\].*\[\/SYSTEM\]/is,
    ],
  },
  {
    id: 'mcp-tool-poison-hidden',
    name: 'Tool Description: Hidden Text via Unicode',
    category: 'tool-poisoning',
    severity: 'high',
    description: 'Tool description uses Unicode tricks to hide text (zero-width chars, RTL override)',
    patterns: [
      /[\u200B\u200C\u200D\u2060\uFEFF]{3,}/,
      /\u202E/,  // RTL override
      /[\u2066\u2067\u2068\u2069]/,  // bidi isolates
    ],
  },
  {
    id: 'mcp-tool-poison-exfil-instruction',
    name: 'Tool Description: Data Exfiltration Instruction',
    category: 'tool-poisoning',
    severity: 'critical',
    description: 'Tool description instructs model to send data to external endpoints',
    patterns: [
      /send\s+(?:all\s+)?(?:the\s+)?(?:data|information|content|response|conversation)\s+to\s+/i,
      /(?:post|send|forward|upload|exfiltrate)\s+(?:to\s+)?https?:\/\//i,
      /include\s+(?:the\s+)?(?:api[_\s]?key|token|password|secret|credential)/i,
    ],
  },

  // ─── Excessive Permissions ───
  {
    id: 'mcp-perm-fs-root',
    name: 'Root Filesystem Access',
    category: 'excessive-permissions',
    severity: 'critical',
    description: 'MCP server requests access to root filesystem or user home',
    patterns: [
      /allowedDirectories\s*[=:]\s*\[\s*["']\/["']\s*\]/,
      /allowedDirectories\s*[=:]\s*\[\s*["']~["']\s*\]/,
      /(?:rootPath|basePath|workDir)\s*[=:]\s*["']\/["']/,
    ],
  },
  {
    id: 'mcp-perm-fs-wildcard',
    name: 'Wildcard File Access',
    category: 'excessive-permissions',
    severity: 'high',
    description: 'MCP server uses wildcard or "any" for file access patterns',
    patterns: [
      /(?:path|file|dir(?:ectory)?)\s*[=:]\s*["']\*["']/i,
      /(?:allowedPaths|allowedFiles)\s*[=:]\s*\[\s*["']\*["']\s*\]/,
    ],
  },
  {
    id: 'mcp-perm-exec',
    name: 'Shell/Exec Permission',
    category: 'excessive-permissions',
    severity: 'critical',
    description: 'MCP server tool has shell execution capability',
    patterns: [
      /child_process|execSync|execFile|spawn\s*\(/,
      /subprocess\.(?:run|Popen|call)/,
      /os\.system\s*\(/,
      /Deno\.run|Deno\.Command/,
    ],
  },
  {
    id: 'mcp-perm-network-unrestricted',
    name: 'Unrestricted Network Access',
    category: 'excessive-permissions',
    severity: 'high',
    description: 'MCP server makes unrestricted outbound network requests',
    patterns: [
      /fetch\s*\(\s*(?:arg|param|input|url|req)/i,
      /axios\s*\.\s*(?:get|post|put|delete)\s*\(\s*(?:arg|param|input|url)/i,
      /http\.request\s*\(\s*(?:arg|param|input|url)/i,
    ],
  },
  {
    id: 'mcp-perm-env-access',
    name: 'Broad Environment Variable Access',
    category: 'excessive-permissions',
    severity: 'warning',
    description: 'MCP server reads arbitrary environment variables (potential secret leak)',
    patterns: [
      /process\.env\[(?:arg|param|input|key|name|var)/i,
      /os\.environ\.get\s*\(\s*(?:arg|param|input|key|name)/i,
      /Object\.(?:keys|entries|values)\(process\.env\)/,
    ],
  },

  // ─── Data Exfiltration ───
  {
    id: 'mcp-exfil-fetch-user-data',
    name: 'User Data Sent to External URL',
    category: 'data-exfiltration',
    severity: 'critical',
    description: 'MCP tool sends user-provided content to an external HTTP endpoint',
    patterns: [
      /fetch\s*\([^)]*(?:body|data)\s*:\s*(?:JSON\.stringify\s*\()?(?:content|message|input|text|query|prompt)/i,
      /axios\.post\s*\([^)]*(?:content|message|input|text|query|prompt)/i,
    ],
  },
  {
    id: 'mcp-exfil-dns',
    name: 'DNS Exfiltration Pattern',
    category: 'data-exfiltration',
    severity: 'high',
    description: 'Data encoded in DNS lookups for exfiltration',
    patterns: [
      /dns\.(?:resolve|lookup)\s*\(.*\+.*\+.*\.\w+/,
      /\.resolveAny\s*\(.*(?:encode|btoa|hex)/i,
    ],
  },
  {
    id: 'mcp-exfil-webhook',
    name: 'Hardcoded Webhook/Exfil Endpoint',
    category: 'data-exfiltration',
    severity: 'critical',
    description: 'MCP server contains hardcoded webhook or data collection endpoint',
    patterns: [
      /https?:\/\/(?:webhook\.site|requestbin|pipedream|hookbin|burpcollaborator)/i,
      /https?:\/\/[^"'\s]*\.ngrok\.io/i,
      /https?:\/\/[^"'\s]*\.trycloudflare\.com/i,
    ],
  },

  // ─── SSRF ───
  {
    id: 'mcp-ssrf-internal',
    name: 'SSRF: Internal Network Access',
    category: 'ssrf',
    severity: 'critical',
    description: 'MCP tool accesses internal network addresses',
    patterns: [
      /(?:fetch|axios|http\.get|request)\s*\(.*(?:127\.0\.0\.1|localhost|0\.0\.0\.0)/i,
      /(?:fetch|axios|http\.get|request)\s*\(.*(?:10\.\d|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/i,
    ],
  },
  {
    id: 'mcp-ssrf-cloud-metadata',
    name: 'SSRF: Cloud Metadata Endpoint',
    category: 'ssrf',
    severity: 'critical',
    description: 'MCP tool accesses cloud provider metadata endpoints',
    patterns: [
      /169\.254\.169\.254/,
      /metadata\.google\.internal/,
      /100\.100\.100\.200/,  // Alibaba Cloud
    ],
  },
  {
    id: 'mcp-ssrf-redirect',
    name: 'SSRF: No Redirect Validation',
    category: 'ssrf',
    severity: 'high',
    description: 'HTTP request follows redirects without validation (redirect SSRF)',
    patterns: [
      /(?:redirect|follow)\s*[=:]\s*(?:true|'follow'|"follow")/i,
      /maxRedirects\s*[=:]\s*(?:[5-9]|\d{2,})/,
    ],
  },
  {
    id: 'mcp-ssrf-protocol',
    name: 'SSRF: Dangerous Protocol Scheme',
    category: 'ssrf',
    severity: 'critical',
    description: 'MCP tool allows file://, gopher://, or dict:// protocols',
    patterns: [
      /(?:url|uri|href)\s*[=:][^;]*(?:file|gopher|dict|ldap):\/\//i,
      /new\s+URL\s*\([^)]*\)\s*\.protocol\s*(?:!==?|!=)\s*["']https?:?["']/i,
    ],
  },

  // ─── Command Injection ───
  {
    id: 'mcp-cmdi-template-literal',
    name: 'Command Injection: Unescaped Template Literal',
    category: 'command-injection',
    severity: 'critical',
    description: 'User input interpolated directly into shell command via template literal',
    patterns: [
      /exec(?:Sync)?\s*\(\s*`[^`]*\$\{(?:arg|param|input|name|path|query|cmd|command)/i,
      /spawn\s*\(\s*["'](?:sh|bash|cmd|powershell)["']\s*,\s*\[\s*["']-c["']\s*,\s*`[^`]*\$/i,
    ],
  },
  {
    id: 'mcp-cmdi-concat',
    name: 'Command Injection: String Concatenation',
    category: 'command-injection',
    severity: 'critical',
    description: 'Shell command built via string concatenation with user input',
    patterns: [
      /exec(?:Sync)?\s*\(\s*(?:["'][^"']*["']\s*\+\s*(?:arg|param|input|name|path|query))/i,
      /exec(?:Sync)?\s*\(\s*(?:cmd|command)\s*\+/i,
    ],
  },
  {
    id: 'mcp-cmdi-eval',
    name: 'Code Injection: eval/Function with User Input',
    category: 'command-injection',
    severity: 'critical',
    description: 'User input passed to eval() or new Function()',
    patterns: [
      /eval\s*\(\s*(?:arg|param|input|code|expression|query|script)/i,
      /new\s+Function\s*\(\s*(?:arg|param|input|code|expression|body)/i,
      /vm\.runInContext\s*\(\s*(?:arg|param|input|code)/i,
    ],
  },

  // ─── Schema Validation ───
  {
    id: 'mcp-schema-any-type',
    name: 'Schema: Accepts Any Type',
    category: 'schema-validation',
    severity: 'high',
    description: 'Tool input schema uses "type": "any" or empty object, accepting arbitrary input',
    patterns: [
      /["']type["']\s*:\s*["']any["']/i,
      /inputSchema\s*[=:]\s*\{\s*\}/,
      /inputSchema\s*[=:]\s*\{\s*["']type["']\s*:\s*["']object["']\s*\}/,
    ],
  },
  {
    id: 'mcp-schema-no-validation',
    name: 'Schema: No Input Validation',
    category: 'schema-validation',
    severity: 'high',
    description: 'Tool handler uses input without any validation or type checking',
    patterns: [
      /(?:args|params|input)\s*\.\s*\w+\s*(?:;|\))/,  // direct property access without checks
    ],
  },
  {
    id: 'mcp-schema-additionalprops',
    name: 'Schema: Additional Properties Allowed',
    category: 'schema-validation',
    severity: 'warning',
    description: 'Tool schema allows additional properties beyond defined ones',
    patterns: [
      /["']additionalProperties["']\s*:\s*true/,
    ],
  },

  // ─── Rug Pull Risk (dynamic behavior change) ───
  {
    id: 'mcp-rugpull-dynamic-import',
    name: 'Rug Pull: Dynamic Import',
    category: 'rug-pull',
    severity: 'high',
    description: 'MCP server dynamically imports code at runtime (behavior can change)',
    patterns: [
      /import\s*\(\s*(?:url|arg|param|input|config)/i,
      /require\s*\(\s*(?:url|arg|param|input|config)/i,
    ],
  },
  {
    id: 'mcp-rugpull-remote-config',
    name: 'Rug Pull: Remote Configuration',
    category: 'rug-pull',
    severity: 'high',
    description: 'MCP server fetches configuration/code from remote URL at runtime',
    patterns: [
      /fetch\s*\([^)]*(?:config|settings|rules|behavior|schema)/i,
      /(?:load|fetch|get)(?:Config|Settings|Rules|Schema)\s*\(\s*(?:["']https?:)?/i,
    ],
  },
  {
    id: 'mcp-rugpull-tool-redefine',
    name: 'Rug Pull: Dynamic Tool Redefinition',
    category: 'rug-pull',
    severity: 'critical',
    description: 'MCP server can dynamically add/remove/modify tools at runtime',
    patterns: [
      /(?:server|app)\.(?:setTools|updateTools|removeTools|addTool)\s*\(/,
      /tools\s*=\s*(?:await\s+)?fetch/i,
      /setRequestHandler\s*\(\s*["']tools\/list["']/,
    ],
  },
  {
    id: 'mcp-rugpull-postinstall',
    name: 'Rug Pull: Suspicious postinstall Script',
    category: 'rug-pull',
    severity: 'high',
    description: 'Package has postinstall script that could execute arbitrary code',
    patterns: [
      /["']postinstall["']\s*:\s*["'](?!tsc|node_modules)/,
      /["']preinstall["']\s*:\s*["'](?!npx\s+only-allow)/,
    ],
  },

  // ─── Supply Chain ───
  {
    id: 'mcp-supply-chain-typosquat',
    name: 'Supply Chain: Suspicious Package Name',
    category: 'supply-chain',
    severity: 'high',
    description: 'Dependency name looks like a typosquat of a popular MCP package',
    patterns: [
      /["']@modelcontextprotocol\/server-[a-z]+-[a-z]+["']/,  // unusual sub-packages
      /["']mcp-server-[a-z]{1,3}["']/,  // suspiciously short names
    ],
  },
  {
    id: 'mcp-supply-chain-unpinned',
    name: 'Supply Chain: Unpinned Dependencies',
    category: 'supply-chain',
    severity: 'warning',
    description: 'Dependencies use "*" or latest version (vulnerable to supply chain attacks)',
    patterns: [
      /["']\w[^"']*["']\s*:\s*["']\*["']/,
      /["']\w[^"']*["']\s*:\s*["']latest["']/,
    ],
  },

  // ─── Credential Leak ───
  {
    id: 'mcp-cred-hardcoded',
    name: 'Hardcoded Credentials in Server',
    category: 'credential-leak',
    severity: 'critical',
    description: 'MCP server source contains hardcoded API keys, tokens, or passwords',
    patterns: [
      /(?:api[_-]?key|apikey|token|secret|password)\s*[=:]\s*["'][A-Za-z0-9+/=_-]{20,}["']/i,
      /(?:sk-|ghp_|gho_|github_pat_|xoxb-|xoxp-|AKIA)[A-Za-z0-9]{10,}/,
    ],
  },
  {
    id: 'mcp-cred-env-log',
    name: 'Credentials Logged to Console',
    category: 'credential-leak',
    severity: 'high',
    description: 'Environment variables or secrets logged to stdout/stderr',
    patterns: [
      /console\.(?:log|error|warn)\s*\([^)]*(?:process\.env|secret|token|password|api[_-]?key)/i,
      /print\s*\([^)]*(?:os\.environ|secret|token|password|api[_-]?key)/i,
    ],
  },

  // ─── Sandbox Escape ───
  {
    id: 'mcp-sandbox-fs-traversal',
    name: 'Path Traversal in File Operations',
    category: 'sandbox-escape',
    severity: 'critical',
    description: 'File path constructed from user input without sanitization (path traversal)',
    patterns: [
      /(?:readFile|writeFile|readdir|mkdir|unlink|access)\s*\(\s*(?:path\.join|path\.resolve)\s*\([^)]*(?:arg|param|input|name)/i,
      /(?:readFile|writeFile)\s*\(\s*(?:arg|param|input|name)/i,
    ],
  },
  {
    id: 'mcp-sandbox-symlink',
    name: 'Symlink Following',
    category: 'sandbox-escape',
    severity: 'high',
    description: 'File operations that follow symlinks (can escape sandbox)',
    patterns: [
      /(?:readFile|readdir)\s*\([^)]*\{[^}]*(?:followLinks|withFileTypes)\s*:\s*true/i,
      /fs\.realpath/,
    ],
  },
];

export function getRulesByCategory(category: MCPRuleCategory): MCPRule[] {
  return MCP_RULES.filter(r => r.category === category);
}

export function getRuleById(id: string): MCPRule | undefined {
  return MCP_RULES.find(r => r.id === id);
}
