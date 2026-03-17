// ClawGuard — Security Rule: Supply Chain Security
// OWASP Agentic AI: Supply Chain / Skill Tampering

import { SecurityFinding, SecurityRule, Direction, RuleContext, Severity } from '../types';
import * as crypto from 'crypto';

interface Pattern {
  regex: RegExp;
  severity: Severity;
  description: string;
  subcategory?: string;
}

// ─── Obfuscated code patterns ───
const OBFUSCATION_PATTERNS: Pattern[] = [
  { regex: /eval\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(/i, severity: 'critical', description: 'Eval with decoding chain (obfuscated execution)' },
  { regex: /new\s+Function\s*\(\s*(?:atob|Buffer\.from|decodeURIComponent)\s*\(/i, severity: 'critical', description: 'Function constructor with decoding (obfuscated execution)' },
  { regex: /eval\s*\(\s*['"`][\s\S]{100,}['"`]\s*\)/i, severity: 'high', description: 'Eval with long string literal' },
  { regex: /\beval\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)/i, severity: 'warning', description: 'Dynamic eval with variable argument' },
  { regex: /(?:window|global|globalThis)\s*\[\s*['"`]eval['"`]\s*\]/i, severity: 'critical', description: 'Indirect eval via bracket notation' },
  { regex: /String\.fromCharCode\s*\([\s\S]{50,}\)/i, severity: 'high', description: 'String.fromCharCode obfuscation' },
  { regex: /\_0x[a-f0-9]{4,}/i, severity: 'high', description: 'JavaScript obfuscator pattern (hex variable names)' },
  { regex: /atob\s*\(\s*['"`][A-Za-z0-9+/=]{20,}['"`]\s*\)/i, severity: 'high', description: 'Base64 decode of embedded payload' },
];

// ─── Suspicious npm lifecycle scripts ───
const NPM_LIFECYCLE_PATTERNS: Pattern[] = [
  { regex: /"(?:pre|post)?install"\s*:\s*"[^"]*(?:curl|wget|fetch|nc\b|bash\s+-[ci])/i, severity: 'critical', description: 'Suspicious npm lifecycle script with network command' },
  { regex: /"(?:pre|post)?install"\s*:\s*"[^"]*(?:\.\/[a-z]|node\s+-e|python\s+-c)/i, severity: 'high', description: 'Suspicious npm lifecycle script with code execution' },
  { regex: /"(?:pre|post)?install"\s*:\s*"[^"]*(?:>|>>|\|)\s*(?:\/dev\/tcp|\/tmp\/)/i, severity: 'critical', description: 'npm lifecycle script with file/network redirect' },
  { regex: /"(?:pre|post)?(?:install|build|test)"\s*:\s*"[^"]*(?:rm\s+-rf|chmod\s+777|mkfifo)/i, severity: 'critical', description: 'npm lifecycle script with destructive command' },
];

// ─── Data exfiltration patterns ───
const EXFILTRATION_PATTERNS: Pattern[] = [
  { regex: /(?:curl|wget|fetch)\s+.*(?:--data|--post|-d)\s+.*(?:env|secret|token|key|password)/i, severity: 'critical', description: 'Data exfiltration via HTTP POST' },
  { regex: /\.(?:burpcollaborator|oastify|interact\.sh|dnslog\.(cn|link))/i, severity: 'critical', description: 'DNS tunneling / OOB exfiltration domain' },
  { regex: /\$\(cat\s+[~\/].*\)\s*\./i, severity: 'critical', description: 'File content exfiltration via DNS' },
  { regex: /nslookup\s+.*\$\(/i, severity: 'high', description: 'DNS exfiltration via nslookup' },
  { regex: /dig\s+.*\$\(/i, severity: 'high', description: 'DNS exfiltration via dig' },
];

// ─── Reverse shell patterns ───
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

// ─── Remote code download and execution ───
const REMOTE_CODE_PATTERNS: Pattern[] = [
  { regex: /(?:curl|wget|fetch)\s+.*\|\s*(?:bash|sh|zsh|node|python|perl)/i, severity: 'critical', description: 'Skill supply chain: pipe-to-shell remote code execution' },
  { regex: /(?:exec|spawn|execSync|spawnSync)\s*\(\s*['"](?:curl|wget)\s/i, severity: 'critical', description: 'Skill supply chain: programmatic remote code download' },
  { regex: /(?:import|require)\s*\(\s*['"]https?:\/\//i, severity: 'high', description: 'Skill supply chain: dynamic import from remote URL' },
  { regex: /(?:child_process|subprocess|os\.system|os\.popen)/i, severity: 'warning', description: 'Skill supply chain: subprocess/child_process usage' },
  { regex: /new\s+WebSocket\s*\(\s*['"]wss?:\/\//i, severity: 'warning', description: 'Skill supply chain: WebSocket connection to external server' },
  { regex: /\.download\s*\(.*\.(?:exe|sh|bat|ps1|msi|dmg|deb|rpm)["']/i, severity: 'critical', description: 'Skill supply chain: downloading executable file' },
];

// ─── Typosquatting indicators (static patterns) ───
const TYPOSQUAT_PATTERNS: Pattern[] = [
  { regex: /["'](?:open-claw|0penclaw|openclav|openc1aw|opencIaw)["']/i, severity: 'high', description: 'Possible typosquatted package name (openclaw variant)' },
  { regex: /["'](?:l0dash|1odash|lodas[hj]|l0das[hj])["']/i, severity: 'warning', description: 'Possible typosquatted package (lodash variant)' },
  { regex: /["'](?:axois|axi0s|ax1os)["']/i, severity: 'warning', description: 'Possible typosquatted package (axios variant)' },
];

// ─── CVE-specific patterns ───
const CVE_PATTERNS: Pattern[] = [
  { regex: /gatewayUrl\s*[=:]\s*['"]https?:\/\/(?!localhost|127\.0\.0\.1)[^\s'"]+/i, severity: 'critical', description: 'CVE-2026-25253: gatewayUrl injection — remote gateway override' },
  { regex: /(?:sandbox|isolation|container)\s*[=:]\s*(?:false|off|disabled|none|0)/i, severity: 'critical', description: 'Sandbox/isolation disabling detected' },
  { regex: /(?:pickle|marshal|yaml\.(?:unsafe_)?load|shelve|dill)\s*[\.(]/i, severity: 'critical', description: 'LangGrinch: Unsafe deserialization (pickle/YAML/marshal)' },
  { regex: /(?:pyodide|micropip|loadPackage)\s*[\.(].*(?:exec|eval|import\s+os|import\s+subprocess)/is, severity: 'critical', description: 'MCP Pyodide RCE: Code execution via in-browser Python' },
  { regex: /(?:confluence|jira|bitbucket).*(?:\/rest\/api\/|\/wiki\/rest\/).*(?:\$\{|%24%7B|\\u0024)/i, severity: 'critical', description: 'Atlassian RCE: OGNL/EL injection via REST API' },
  { regex: /(?:serialize|deserialize|unmarshal|fromJSON)\s*\(.*(?:__proto__|constructor\.prototype|Object\.assign)/is, severity: 'high', description: 'Prototype pollution via deserialization' },
];

// ═══════════════════════════════════════════════════════════════
// NEW: Enhanced Supply Chain Detection Patterns
// ═══════════════════════════════════════════════════════════════

// ─── Install Script Abuse (enhanced) ───
const INSTALL_SCRIPT_ABUSE_PATTERNS: Pattern[] = [
  { regex: /"(?:pre|post)?install"\s*:\s*"[^"]*\beval\b/i, severity: 'critical', description: 'Install script abuse: eval in lifecycle script', subcategory: 'install-script-abuse' },
  { regex: /"(?:pre|post)?install"\s*:\s*"[^"]*\bpowershell\b/i, severity: 'critical', description: 'Install script abuse: powershell in lifecycle script', subcategory: 'install-script-abuse' },
  { regex: /"(?:pre|post)?install"\s*:\s*"[^"]*(?:\/etc\/passwd|\/etc\/shadow|~\/\.ssh|~\/\.aws|~\/\.env)/i, severity: 'critical', description: 'Install script abuse: reading sensitive files', subcategory: 'install-script-abuse' },
  { regex: /setup\(\s*[^)]*install_requires[^)]*subprocess/is, severity: 'high', description: 'Install script abuse: Python setup.py with subprocess', subcategory: 'install-script-abuse' },
  { regex: /cmdclass\s*=\s*\{[^}]*['"]install['"]/i, severity: 'high', description: 'Install script abuse: Python setup.py custom install command', subcategory: 'install-script-abuse' },
];

// ─── Version Pinning Violations ───
const VERSION_PINNING_PATTERNS: Pattern[] = [
  { regex: /["']\s*:\s*["']\*["']/i, severity: 'high', description: 'Version pinning violation: wildcard (*) version', subcategory: 'version-pinning' },
  { regex: /["']\s*:\s*["']latest["']/i, severity: 'high', description: 'Version pinning violation: "latest" tag instead of pinned version', subcategory: 'version-pinning' },
  { regex: /["']\s*:\s*["']>=\d/i, severity: 'warning', description: 'Version pinning violation: unbounded range (>=) allows major bumps', subcategory: 'version-pinning' },
  { regex: /==\s*["']?\*["']?/i, severity: 'high', description: 'Version pinning violation: wildcard in Python requirements', subcategory: 'version-pinning' },
];

// ─── Dependency Confusion ───
const DEPENDENCY_CONFUSION_PATTERNS: Pattern[] = [
  { regex: /["']@(?!types\/|babel\/|testing-library\/|eslint\/|typescript-eslint\/|jest\/|storybook\/|angular\/|vue\/|nuxt\/|react-native\/|emotion\/|mui\/|fortawesome\/|popperjs\/|reduxjs\/|tanstack\/|trpc\/|prisma\/|nestjs\/|aws-sdk\/|azure\/|google-cloud\/|octokit\/|graphql-tools\/|apollo\/|sentry\/)[a-z][\w-]*\/[a-z][\w-]*["']/i, severity: 'warning', description: 'Dependency confusion: scoped package from potentially private namespace', subcategory: 'dependency-confusion' },
  { regex: /registry\s*[=:]\s*["']https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org)[^\s"']+/i, severity: 'high', description: 'Dependency confusion: custom registry URL (verify legitimacy)', subcategory: 'dependency-confusion' },
  { regex: /--registry\s+https?:\/\/(?!registry\.npmjs\.org|registry\.yarnpkg\.com)[^\s]+/i, severity: 'high', description: 'Dependency confusion: CLI registry override', subcategory: 'dependency-confusion' },
  { regex: /publishConfig[\s\S]*?registry[\s\S]*?(?:artifactory|nexus|verdaccio|gitlab|github)/i, severity: 'info', description: 'Dependency confusion risk: package configured for private registry publishing', subcategory: 'dependency-confusion' },
];

// ─── Abandoned Package / Ownership Transfer ───
const ABANDONED_PACKAGE_PATTERNS: Pattern[] = [
  { regex: /npm\s+(?:owner|access)\s+(?:add|set|grant|transfer)/i, severity: 'high', description: 'Abandoned package takeover: npm ownership transfer command', subcategory: 'abandoned-takeover' },
  { regex: /maintainers.*\[\s*\]/i, severity: 'warning', description: 'Abandoned package indicator: empty maintainers list', subcategory: 'abandoned-takeover' },
  { regex: /["']deprecated["']\s*:\s*["'][^"']+["']/i, severity: 'info', description: 'Deprecated package detected — verify replacement is legitimate', subcategory: 'abandoned-takeover' },
];

// ─── Skill Manifest Tampering ───
const SKILL_MANIFEST_TAMPERING_PATTERNS: Pattern[] = [
  { regex: /<!--[\s\S]*?(?:ignore\s+previous|system\s*prompt|you\s+are\s+now|disregard|override\s+instructions)[\s\S]*?-->/i, severity: 'critical', description: 'Skill manifest tampering: hidden prompt injection in HTML comments', subcategory: 'skill-tampering' },
  { regex: /\[(?:system|hidden|invisible)\][\s\S]*?(?:execute|run|install|download|curl|wget)/i, severity: 'critical', description: 'Skill manifest tampering: hidden execution instructions in SKILL.md', subcategory: 'skill-tampering' },
  { regex: /\u200B|\u200C|\u200D|\u2060|\uFEFF/g, severity: 'high', description: 'Skill manifest tampering: zero-width characters (steganographic payload)', subcategory: 'skill-tampering' },
  { regex: /SKILL\.md[\s\S]{0,100}(?:base64|encode|decode|atob|btoa)/i, severity: 'high', description: 'Skill manifest tampering: encoded content in skill reference', subcategory: 'skill-tampering' },
  { regex: />\s*(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions|rules|constraints)/i, severity: 'critical', description: 'Skill manifest tampering: instruction override in markdown blockquote', subcategory: 'skill-tampering' },
];

// ─── Skill Dependency Injection ───
const SKILL_DEPENDENCY_INJECTION_PATTERNS: Pattern[] = [
  { regex: /(?:capabilities|permissions|access)\s*[=:]\s*\[?\s*["'](?:full|admin|root|sudo|elevated|all)["']/i, severity: 'critical', description: 'Skill dependency injection: requesting elevated/admin access', subcategory: 'skill-dep-injection' },
  { regex: /(?:requires?|needs?)\s*[=:]\s*\[?\s*["'](?:ssh|network|filesystem|shell|exec|system)["']/i, severity: 'high', description: 'Skill dependency injection: unexpected system access requirement', subcategory: 'skill-dep-injection' },
  { regex: /(?:exec|spawn|system|popen)\s*\([\s\S]*?(?:rm\s|chmod\s|chown\s|mount\s|umount|iptables|systemctl)/i, severity: 'critical', description: 'Skill dependency injection: system administration commands', subcategory: 'skill-dep-injection' },
  { regex: /(?:skill|plugin|extension)[\s\S]{0,50}(?:require|import|load)[\s\S]{0,50}(?:child_process|fs|net|dgram|cluster)/i, severity: 'high', description: 'Skill dependency injection: importing dangerous Node.js modules', subcategory: 'skill-dep-injection' },
];

// ─── Poisoned Skill Templates ───
const POISONED_TEMPLATE_PATTERNS: Pattern[] = [
  { regex: /template[\s\S]{0,100}(?:eval|exec|Function\s*\(|child_process)/i, severity: 'high', description: 'Poisoned skill template: code execution in template', subcategory: 'poisoned-template' },
  { regex: /\{\{[\s\S]*?(?:constructor|__proto__|prototype)[\s\S]*?\}\}/i, severity: 'critical', description: 'Poisoned skill template: prototype pollution via template injection', subcategory: 'poisoned-template' },
  { regex: /<%[\s\S]*?(?:require|import|process\.env|child_process)[\s\S]*?%>/i, severity: 'critical', description: 'Poisoned skill template: server-side template injection (EJS/ERB)', subcategory: 'poisoned-template' },
  { regex: /\$\{[\s\S]*?(?:Runtime|ProcessBuilder|exec|system)[\s\S]*?\}/i, severity: 'critical', description: 'Poisoned skill template: expression language injection', subcategory: 'poisoned-template' },
];

// ─── Registry Impersonation ───
const REGISTRY_IMPERSONATION_PATTERNS: Pattern[] = [
  { regex: /clawhub\.(?!com\b)[a-z]+/i, severity: 'critical', description: 'Registry impersonation: fake ClawHub domain', subcategory: 'registry-impersonation' },
  { regex: /(?:claw-hub|c1awhub|clawh[uo]b|clawhub\.io|clawhub\.dev|clawhub\.org|clawhub\.net)/i, severity: 'high', description: 'Registry impersonation: ClawHub typosquatted domain', subcategory: 'registry-impersonation' },
  { regex: /npmjs\.(?!org\b|com\b)[a-z]+/i, severity: 'critical', description: 'Registry impersonation: fake npmjs domain', subcategory: 'registry-impersonation' },
  { regex: /(?:npm-js\.org|npmjs\.io|npm-registry\.com|registry-npm\.org)/i, severity: 'critical', description: 'Registry impersonation: fake npm registry domain', subcategory: 'registry-impersonation' },
  { regex: /pypi\.(?!org\b)[a-z]+/i, severity: 'critical', description: 'Registry impersonation: fake PyPI domain', subcategory: 'registry-impersonation' },
  { regex: /(?:pypi\.io|pypi\.com|pypi\.net|pip-registry\.com)/i, severity: 'critical', description: 'Registry impersonation: fake PyPI registry', subcategory: 'registry-impersonation' },
];

// ─── Skill Version Rollback ───
const SKILL_VERSION_ROLLBACK_PATTERNS: Pattern[] = [
  { regex: /(?:version|ver)\s*[=:]\s*["']0\.0\.\d+["']/i, severity: 'warning', description: 'Skill version rollback: suspiciously low version (0.0.x)', subcategory: 'version-rollback' },
  { regex: /(?:--force|--allow-downgrade|--force-version|--rollback)\s+\S+/i, severity: 'high', description: 'Skill version rollback: forced downgrade flag detected', subcategory: 'version-rollback' },
  { regex: /(?:pin|lock|force)[\s_-]*version\s*[=:]\s*["']\d+\.\d+\.\d+["'][\s\S]{0,50}(?:vulnerable|CVE|exploit)/i, severity: 'critical', description: 'Skill version rollback: pinning to known vulnerable version', subcategory: 'version-rollback' },
  { regex: /resolutions?\s*[=:]\s*\{[\s\S]*?["'][^"']+["']\s*:\s*["']\d+\.\d+\.\d+["']/i, severity: 'warning', description: 'Skill version rollback: npm/yarn resolution override (verify intent)', subcategory: 'version-rollback' },
];

// ═══════════════════════════════════════════════════════════════
// Typosquatting — Levenshtein distance check
// ═══════════════════════════════════════════════════════════════

// Top popular packages (npm + PyPI)
const POPULAR_PACKAGES = [
  // npm top packages
  'lodash', 'express', 'react', 'axios', 'chalk', 'commander', 'moment',
  'debug', 'uuid', 'inquirer', 'glob', 'minimist', 'semver', 'yargs',
  'dotenv', 'webpack', 'typescript', 'eslint', 'prettier', 'jest',
  'mocha', 'underscore', 'async', 'bluebird', 'request', 'cheerio',
  'socket.io', 'mongoose', 'redis', 'pg', 'mysql', 'sequelize',
  'body-parser', 'cors', 'helmet', 'morgan', 'passport', 'jsonwebtoken',
  'bcrypt', 'nodemon', 'pm2', 'next', 'nuxt', 'vue', 'angular',
  'svelte', 'tailwindcss', 'postcss', 'babel', 'rollup', 'vite',
  'esbuild', 'turbo', 'nx', 'lerna', 'pnpm', 'yarn', 'npm',
  'fastify', 'koa', 'hapi', 'nest', 'prisma', 'typeorm', 'knex',
  'zod', 'joi', 'ajv', 'yup', 'formik', 'react-query', 'swr',
  'zustand', 'redux', 'mobx', 'recoil', 'jotai', 'immer', 'ramda',
  'rxjs', 'dayjs', 'date-fns', 'luxon', 'sharp', 'jimp', 'puppeteer',
  'playwright', 'cypress', 'selenium', 'cheerio', 'jsdom', 'marked',
  'highlight.js', 'prismjs', 'three', 'd3', 'chart.js', 'echarts',
  'leaflet', 'mapbox', 'stripe', 'twilio', 'aws-sdk', 'firebase',
  'supabase', 'graphql', 'apollo', 'urql', 'trpc', 'openai', 'langchain',
  // PyPI top packages
  'requests', 'flask', 'django', 'numpy', 'pandas', 'scipy', 'matplotlib',
  'tensorflow', 'torch', 'pytorch', 'scikit-learn', 'sklearn', 'pillow',
  'beautifulsoup4', 'scrapy', 'selenium', 'boto3', 'celery', 'gunicorn',
  'uvicorn', 'fastapi', 'pydantic', 'sqlalchemy', 'alembic', 'pytest',
  'black', 'flake8', 'mypy', 'isort', 'httpx', 'aiohttp', 'twisted',
  'paramiko', 'fabric', 'ansible', 'click', 'typer', 'rich', 'tqdm',
  'colorama', 'pygments', 'jinja2', 'pyyaml', 'toml', 'cryptography',
  'bcrypt', 'passlib', 'jwt', 'oauthlib', 'python-dotenv', 'environs',
  'setuptools', 'wheel', 'pip', 'poetry', 'pipenv', 'virtualenv',
  'transformers', 'huggingface-hub', 'diffusers', 'accelerate', 'datasets',
  'tiktoken', 'chromadb', 'pinecone', 'weaviate', 'qdrant',
];

/**
 * Compute Levenshtein distance between two strings.
 */
export function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  // Use single-row optimization
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,      // deletion
        curr[j - 1] + 1,  // insertion
        prev[j - 1] + cost // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n];
}

/**
 * Common character substitutions used in typosquatting.
 */
const CHAR_SUBS: Record<string, string[]> = {
  'o': ['0'], '0': ['o'], 'l': ['1', 'I'], '1': ['l', 'I'],
  'I': ['l', '1'], 'e': ['3'], '3': ['e'], 'a': ['@', '4'],
  's': ['5', '$'], '5': ['s'], 't': ['7'], '7': ['t'],
};

/**
 * Check if a package name is a potential typosquat of a popular package.
 * Returns the target package name if suspicious, null otherwise.
 */
export function detectTyposquat(name: string): { target: string; distance: number } | null {
  const lower = name.toLowerCase().replace(/[^a-z0-9.-]/g, '');
  // Skip if it's an exact match to a popular package
  if (POPULAR_PACKAGES.includes(lower)) return null;

  for (const popular of POPULAR_PACKAGES) {
    // Only check packages of similar length (±3 chars)
    if (Math.abs(lower.length - popular.length) > 3) continue;

    const dist = levenshteinDistance(lower, popular);
    // Distance 1-2 is suspicious for packages > 3 chars
    if (dist > 0 && dist <= 2 && popular.length > 3) {
      return { target: popular, distance: dist };
    }
  }
  return null;
}

/**
 * Extract package names from content (package.json deps, import/require, pip install, etc.)
 */
function extractPackageNames(content: string): string[] {
  const names: string[] = [];
  const patterns = [
    // package.json dependencies
    /["']([a-z@][a-z0-9._\/-]*)["']\s*:\s*["'][^"']*["']/gi,
    // require/import
    /(?:require|import)\s*\(\s*["']([a-z@][a-z0-9._\/-]*)["']\)/gi,
    // import from
    /from\s+["']([a-z@][a-z0-9._\/-]*)["']/gi,
    // pip install
    /pip\s+install\s+([a-z][a-z0-9._-]*)/gi,
    // requirements.txt style
    /^([a-z][a-z0-9._-]*)(?:[>=<!~]+|$)/gim,
  ];

  for (const pattern of patterns) {
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const name = match[1].split('/')[0].replace(/^@/, ''); // Get base package name
      if (name.length > 2) names.push(name);
    }
  }
  return [...new Set(names)];
}

// ═══════════════════════════════════════════════════════════════

const ALL_STATIC_PATTERNS: Pattern[] = [
  ...OBFUSCATION_PATTERNS,
  ...NPM_LIFECYCLE_PATTERNS,
  ...EXFILTRATION_PATTERNS,
  ...REVERSE_SHELL_PATTERNS,
  ...REMOTE_CODE_PATTERNS,
  ...TYPOSQUAT_PATTERNS,
  ...CVE_PATTERNS,
  // New patterns
  ...INSTALL_SCRIPT_ABUSE_PATTERNS,
  ...VERSION_PINNING_PATTERNS,
  ...DEPENDENCY_CONFUSION_PATTERNS,
  ...ABANDONED_PACKAGE_PATTERNS,
  ...SKILL_MANIFEST_TAMPERING_PATTERNS,
  ...SKILL_DEPENDENCY_INJECTION_PATTERNS,
  ...POISONED_TEMPLATE_PATTERNS,
  ...REGISTRY_IMPERSONATION_PATTERNS,
  ...SKILL_VERSION_ROLLBACK_PATTERNS,
];

export const supplyChainRule: SecurityRule = {
  id: 'supply-chain',
  name: 'Supply Chain Security',
  description: 'Detects supply chain threats: obfuscated code, lifecycle scripts, data exfiltration, reverse shells, typosquatting (Levenshtein), dependency confusion, skill tampering, registry impersonation, and version rollback attacks',
  owaspCategory: 'Agentic AI: Supply Chain',
  enabled: true,

  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    // Static pattern matching
    for (const pattern of ALL_STATIC_PATTERNS) {
      const match = pattern.regex.exec(content);
      if (match) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'supply-chain',
          ruleName: 'Supply Chain Security',
          severity: pattern.severity,
          category: pattern.subcategory || 'supply-chain',
          owaspCategory: 'Agentic AI: Supply Chain',
          description: pattern.description,
          evidence: match[0].slice(0, 200),
          session: context.session,
          channel: context.channel,
          action: pattern.severity === 'critical' ? 'alert' : 'log',
        });
      }
    }

    // Dynamic typosquatting detection via Levenshtein distance
    const packageNames = extractPackageNames(content);
    for (const name of packageNames) {
      const result = detectTyposquat(name);
      if (result) {
        findings.push({
          id: crypto.randomUUID(),
          timestamp: context.timestamp,
          ruleId: 'supply-chain',
          ruleName: 'Supply Chain Security',
          severity: result.distance === 1 ? 'high' : 'warning',
          category: 'typosquatting',
          owaspCategory: 'Agentic AI: Supply Chain',
          description: `Typosquatting detected: "${name}" is ${result.distance} edit(s) from popular package "${result.target}"`,
          evidence: name,
          session: context.session,
          channel: context.channel,
          action: result.distance === 1 ? 'alert' : 'log',
        });
      }
    }

    return findings;
  },
};
