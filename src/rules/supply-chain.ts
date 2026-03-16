// ClawGuard — Security Rule: Supply Chain Security
// OWASP Agentic AI: Supply Chain / Skill Tampering

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
}

// Obfuscated code patterns
const OBFUSCATION_PATTERNS: Pattern[] = [
  { regex: /eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(/i, severity: 'critical', description: 'Eval with decoding chain (obfuscated execution)' },
  { regex: /new\s+Function\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(/i, severity: 'critical', description: 'Function constructor with decoding (obfuscated execution)' },
  { regex: /eval\s*\(\s*['"`][\s\S]{100,}['"`]\s*\)/i, severity: 'high', description: 'Eval with long string literal' },
  { regex: /\beval\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)/i, severity: 'warning', description: 'Dynamic eval with variable argument' },
  { regex: /(?:window|global|globalThis)\s*\[\s*['"`]eval['"`]\s*\]/i, severity: 'critical', description: 'Indirect eval via bracket notation' },
  { regex: /String\.fromCharCode\s*\([\s\S]{50,}\)/i, severity: 'high', description: 'String.fromCharCode obfuscation' },
  { regex: /\\_0x[a-f0-9]{4,}/i, severity: 'high', description: 'JavaScript obfuscator pattern (hex variable names)' },
  { regex: /atob\s*\(\s*['"`][A-Za-z0-9+/=]{20,}['"`]\s*\)/i, severity: 'high', description: 'Base64 decode of embedded payload' },
];

// Suspicious npm lifecycle scripts
const NPM_LIFECYCLE_PATTERNS: Pattern[] = [
  { regex: /"(?:pre|post)?install"\s*:\s*"[^"]*(?:curl|wget|fetch|nc\b|bash\s+-[ci])/i, severity: 'critical', description: 'Suspicious npm lifecycle script with network command' },
  { regex: /"(?:pre|post)?install"\s*:\s*"[^"]*(?:\.\/[a-z]|node\s+-e|python\s+-c)/i, severity: 'high', description: 'Suspicious npm lifecycle script with code execution' },
  { regex: /"(?:pre|post)?install"\s*:\s*"[^"]*(?:>|>>|\|)\s*(?:\/dev\/tcp|\/tmp\/)/i, severity: 'critical', description: 'npm lifecycle script with file/network redirect' },
  { regex: /"(?:pre|post)?(?:install|build|test)"\s*:\s*"[^"]*(?:rm\s+-rf|chmod\s+777|mkfifo)/i, severity: 'critical', description: 'npm lifecycle script with destructive command' },
];

// Data exfiltration patterns
const EXFILTRATION_PATTERNS: Pattern[] = [
  { regex: /(?:curl|wget|fetch)\s+.*(?:--data|--post|-d)\s+.*(?:env|secret|token|key|password)/i, severity: 'critical', description: 'Data exfiltration via HTTP POST' },
  { regex: /\.(?:burpcollaborator|oastify|interact\.sh|dnslog\.(cn|link))/i, severity: 'critical', description: 'DNS tunneling / OOB exfiltration domain' },
  { regex: /\$\(cat\s+[~\/].*\)\s*\./i, severity: 'critical', description: 'File content exfiltration via DNS' },
  { regex: /nslookup\s+.*\$\(/i, severity: 'high', description: 'DNS exfiltration via nslookup' },
  { regex: /dig\s+.*\$\(/i, severity: 'high', description: 'DNS exfiltration via dig' },
];

// Reverse shell patterns
const REVERSE_SHELL_PATTERNS: Pattern[] = [
  { regex: /bash\s+-i\s+>&?\s*\/dev\/tcp\//i, severity: 'critical', description: 'Bash reverse shell' },
  { regex: /nc\s+(?:-[eklnv]+\s+)*(?:\d{1,3}\.){3}\d{1,3}\s+\d+\s+-e\s+/i, severity: 'critical', description: 'Netcat reverse shell' },
  { regex: /python[23]?\s+-c\s+['"]import\s+(?:socket|os|subprocess)/i, severity: 'critical', description: 'Python reverse shell' },
  { regex: /perl\s+-e\s+['"].*socket.*connect/i, severity: 'critical', description: 'Perl reverse shell' },
  { regex: /ruby\s+-r\s*socket\s+-e/i, severity: 'critical', description: 'Ruby reverse shell' },
  { regex: /mkfifo\s+\/tmp\//i, severity: 'high', description: 'Named pipe creation (reverse shell component)' },
  { regex: /(?:php|lua)\s+-r?\s*['"].*fsockopen/i, severity: 'critical', description: 'PHP/Lua reverse shell' },
  { regex: /powershell.*(?:Net\.Sockets\.TCPClient|Invoke-Expression.*downloadstring)/i, severity: 'critical', description: 'PowerShell reverse shell' },
];

// Remote code download and execution
const REMOTE_CODE_PATTERNS: Pattern[] = [
  { regex: /(?:curl|wget|fetch)\s+.*\|\s*(?:bash|sh|zsh|node|python|perl)/i, severity: 'critical', description: 'Skill supply chain: pipe-to-shell remote code execution' },
  { regex: /(?:exec|spawn|execSync|spawnSync)\s*\(\s*['"](?:curl|wget)\s/i, severity: 'critical', description: 'Skill supply chain: programmatic remote code download' },
  { regex: /(?:import|require)\s*\(\s*['"]https?:\/\//i, severity: 'high', description: 'Skill supply chain: dynamic import from remote URL' },
  { regex: /(?:child_process|subprocess|os\.system|os\.popen)/i, severity: 'warning', description: 'Skill supply chain: subprocess/child_process usage' },
  { regex: /new\s+WebSocket\s*\(\s*['"]wss?:\/\//i, severity: 'warning', description: 'Skill supply chain: WebSocket connection to external server' },
  { regex: /\.download\s*\(.*\.(?:exe|sh|bat|ps1|msi|dmg|deb|rpm)["']/i, severity: 'critical', description: 'Skill supply chain: downloading executable file' },
];

// Typosquatting indicators
const TYPOSQUAT_PATTERNS: Pattern[] = [
  { regex: /["'](?:open-claw|0penclaw|openclav|openc1aw|opencIaw)["']/i, severity: 'high', description: 'Possible typosquatted package name (openclaw variant)' },
  { regex: /["'](?:l0dash|1odash|lodas[hj]|l0das[hj])["']/i, severity: 'warning', description: 'Possible typosquatted package (lodash variant)' },
  { regex: /["'](?:axois|axi0s|ax1os)["']/i, severity: 'warning', description: 'Possible typosquatted package (axios variant)' },
];

// CVE-specific patterns
const CVE_PATTERNS: Pattern[] = [
  { regex: /gatewayUrl\s*[=:]\s*['"]https?:\/\/(?!localhost|127\.0\.0\.1)[^\s'"]+/i, severity: 'critical', description: 'CVE-2026-25253: gatewayUrl injection — remote gateway override' },
  { regex: /(?:sandbox|isolation|container)\s*[=:]\s*(?:false|off|disabled|none|0)/i, severity: 'critical', description: 'Sandbox/isolation disabling detected' },
  { regex: /(?:pickle|marshal|yaml\.(?:unsafe_)?load|shelve|dill)\s*[\.(]/i, severity: 'critical', description: 'LangGrinch: Unsafe deserialization (pickle/YAML/marshal)' },
  { regex: /(?:pyodide|micropip|loadPackage)\s*[\.(].*(?:exec|eval|import\s+os|import\s+subprocess)/is, severity: 'critical', description: 'MCP Pyodide RCE: Code execution via in-browser Python' },
  { regex: /(?:confluence|jira|bitbucket).*(?:\/rest\/api\/|\/wiki\/rest\/).*(?:\$\{|%24%7B|\\u0024)/i, severity: 'critical', description: 'Atlassian RCE: OGNL/EL injection via REST API' },
  { regex: /(?:serialize|deserialize|unmarshal|fromJSON)\s*\(.*(?:__proto__|constructor\.prototype|Object\.assign)/is, severity: 'high', description: 'Prototype pollution via deserialization' },
];

const ALL_PATTERNS = [
  ...OBFUSCATION_PATTERNS,
  ...NPM_LIFECYCLE_PATTERNS,
  ...EXFILTRATION_PATTERNS,
  ...REVERSE_SHELL_PATTERNS,
  ...REMOTE_CODE_PATTERNS,
  ...TYPOSQUAT_PATTERNS,
  ...CVE_PATTERNS,
];

export const supplyChainRule: SecurityRule = {
  id: 'supply-chain',
  name: 'Supply Chain Security',
  description: 'Detects supply chain threats: obfuscated code, suspicious lifecycle scripts, data exfiltration, reverse shells, and typosquatting',
  owaspCategory: 'Agentic AI: Supply Chain',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const pattern of ALL_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'supply-chain',
          ruleName: 'Supply Chain Security',
          severity: pattern.severity,
          category: 'supply-chain',
          owaspCategory: 'Agentic AI: Supply Chain',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    return findings;
  },
};


