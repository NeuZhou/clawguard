// ClawGuard — Plugin Loader
// Discovers and loads plugins from: npm packages, local directories, single files

import * as fs from 'fs';
import * as path from 'path';
import { ClawGuardPlugin, ResolvedPlugin, PluginLoadError, ClawGuardConfig } from './plugin-types';
import { builtinRules } from '../rules';

const PLUGIN_PREFIX = 'clawguard-rules-';

/** The built-in plugin wrapping all default rules */
export function getBuiltinPlugin(disableIds?: string[]): ResolvedPlugin {
  const rules = disableIds?.length
    ? builtinRules.filter(r => !disableIds.includes(r.id))
    : [...builtinRules];
  return {
    plugin: {
      name: '@clawguard/builtin',
      version: '1.0.0',
      rules,
      meta: { description: 'Built-in ClawGuard security rules' },
    },
    source: 'builtin',
  };
}

/** Load a plugin from an npm package name */
function loadFromNpm(name: string): ResolvedPlugin {
  // Try with and without prefix
  const candidates = [name, `${PLUGIN_PREFIX}${name}`, `@clawguard/${name}`];
  for (const candidate of candidates) {
    try {
      const resolved = require.resolve(candidate, { paths: [process.cwd()] });
      const mod = require(resolved);
      const plugin = extractPlugin(mod, candidate);
      return { plugin, source: 'npm', path: resolved };
    } catch {
      continue;
    }
  }
  throw new Error(`Plugin "${name}" not found. Tried: ${candidates.join(', ')}`);
}

/** Load a plugin from a local directory (must have index.js/ts or package.json main) */
function loadFromDirectory(dirPath: string): ResolvedPlugin {
  const abs = path.resolve(dirPath);
  if (!fs.existsSync(abs)) throw new Error(`Plugin directory not found: ${abs}`);
  const pkgPath = path.join(abs, 'package.json');
  let entry = abs;
  if (fs.existsSync(pkgPath)) {
    const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
    if (pkg.main) entry = path.join(abs, pkg.main);
  }
  const mod = require(entry);
  const plugin = extractPlugin(mod, abs);
  return { plugin, source: 'local-dir', path: abs };
}

/** Load a plugin from a single .js file */
function loadFromFile(filePath: string): ResolvedPlugin {
  const abs = path.resolve(filePath);
  if (!fs.existsSync(abs)) throw new Error(`Plugin file not found: ${abs}`);
  const mod = require(abs);
  const plugin = extractPlugin(mod, filePath);
  return { plugin, source: 'local-file', path: abs };
}

/** Extract ClawGuardPlugin from a module (supports default export and named export) */
function extractPlugin(mod: any, name: string): ClawGuardPlugin {
  const candidate = mod.default || mod.plugin || mod;
  if (!candidate || !Array.isArray(candidate.rules)) {
    throw new Error(`"${name}" does not export a valid ClawGuardPlugin (missing rules array)`);
  }
  return {
    name: candidate.name || name,
    version: candidate.version || '0.0.0',
    rules: candidate.rules,
    meta: candidate.meta,
  };
}

/** Smart load: detect whether name is npm package, directory, or file */
export function loadPlugin(nameOrPath: string): ResolvedPlugin {
  // Absolute or relative path
  if (nameOrPath.startsWith('.') || nameOrPath.startsWith('/') || nameOrPath.includes('\\') || path.isAbsolute(nameOrPath)) {
    const abs = path.resolve(nameOrPath);
    if (fs.existsSync(abs)) {
      const stat = fs.statSync(abs);
      return stat.isDirectory() ? loadFromDirectory(abs) : loadFromFile(abs);
    }
  }
  // Try npm
  return loadFromNpm(nameOrPath);
}

/** Load multiple plugins, collecting errors */
export function loadPlugins(names: string[]): { plugins: ResolvedPlugin[]; errors: PluginLoadError[] } {
  const plugins: ResolvedPlugin[] = [];
  const errors: PluginLoadError[] = [];
  for (const name of names) {
    try {
      plugins.push(loadPlugin(name));
    } catch (err: any) {
      errors.push({ name, error: err.message });
    }
  }
  return { plugins, errors };
}

/** Auto-discover clawguard-rules-* packages in node_modules */
export function discoverPlugins(searchDir?: string): string[] {
  const dir = searchDir || path.join(process.cwd(), 'node_modules');
  const found: string[] = [];
  if (!fs.existsSync(dir)) return found;

  try {
    for (const entry of fs.readdirSync(dir)) {
      if (entry.startsWith(PLUGIN_PREFIX)) {
        found.push(entry);
      }
      // Scoped packages
      if (entry.startsWith('@')) {
        const scopeDir = path.join(dir, entry);
        try {
          for (const scoped of fs.readdirSync(scopeDir)) {
            if (scoped.startsWith('clawguard-') || scoped.startsWith('rules-')) {
              found.push(`${entry}/${scoped}`);
            }
          }
        } catch { /* skip unreadable scope dirs */ }
      }
    }
  } catch { /* skip */ }
  return found;
}

/** Load config from .clawguardrc.json or clawguard.config.js */
export function loadConfig(cwd?: string): ClawGuardConfig | null {
  const dir = cwd || process.cwd();
  const rcPath = path.join(dir, '.clawguardrc.json');
  const jsPath = path.join(dir, 'clawguard.config.js');

  if (fs.existsSync(rcPath)) {
    try {
      return JSON.parse(fs.readFileSync(rcPath, 'utf-8'));
    } catch { return null; }
  }
  if (fs.existsSync(jsPath)) {
    try {
      const mod = require(jsPath);
      return mod.default || mod;
    } catch { return null; }
  }
  return null;
}

/** Generate a plugin template directory */
export function generatePluginTemplate(targetDir: string, pluginName?: string): void {
  const name = pluginName || 'clawguard-rules-example';
  fs.mkdirSync(targetDir, { recursive: true });
  fs.mkdirSync(path.join(targetDir, 'rules'), { recursive: true });

  // package.json
  fs.writeFileSync(path.join(targetDir, 'package.json'), JSON.stringify({
    name,
    version: '0.1.0',
    description: `ClawGuard security rules plugin`,
    main: 'index.js',
    types: 'index.d.ts',
    keywords: ['clawguard', 'clawguard-plugin', 'security-rules'],
    peerDependencies: { '@neuzhou/clawguard': '>=1.0.0' },
    license: 'MIT',
  }, null, 2) + '\n');

  // index.ts
  fs.writeFileSync(path.join(targetDir, 'index.ts'), `// ${name} — ClawGuard Plugin
import { ClawGuardPlugin, SecurityRule } from '@neuzhou/clawguard';
import { exampleRule } from './rules/example-rule';

const plugin: ClawGuardPlugin = {
  name: '${name}',
  version: '0.1.0',
  rules: [exampleRule],
  meta: {
    author: 'Your Name',
    description: 'Example ClawGuard rules plugin',
    homepage: 'https://github.com/yourname/${name}',
  },
};

export default plugin;
`);

  // Example rule
  fs.writeFileSync(path.join(targetDir, 'rules', 'example-rule.ts'), `import { SecurityRule, SecurityFinding, Direction, RuleContext } from '@neuzhou/clawguard';
import * as crypto from 'crypto';

export const exampleRule: SecurityRule = {
  id: 'example/custom-check',
  name: 'Example Custom Check',
  description: 'Detects a custom pattern in messages',
  owaspCategory: 'Custom',
  enabled: true,
  check(content: string, direction: Direction, context: RuleContext): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    // Add your detection logic here
    if (content.includes('DANGEROUS_PATTERN')) {
      findings.push({
        id: crypto.randomUUID(),
        timestamp: context.timestamp,
        ruleId: 'example/custom-check',
        ruleName: 'Example Custom Check',
        severity: 'warning',
        category: 'custom',
        owaspCategory: 'Custom',
        description: 'Detected dangerous pattern in message',
        evidence: content.slice(0, 200),
        session: context.session,
        channel: context.channel,
        action: 'alert',
      });
    }
    return findings;
  },
};
`);

  // README
  fs.writeFileSync(path.join(targetDir, 'README.md'), `# ${name}

A ClawGuard security rules plugin.

## Installation

\`\`\`bash
npm install ${name}
\`\`\`

## Usage

Add to \`.clawguardrc.json\`:

\`\`\`json
{
  "plugins": ["${name}"]
}
\`\`\`

Or via CLI:

\`\`\`bash
clawguard scan ./my-project --plugins ${name}
\`\`\`

## Creating Rules

Each rule implements the \`SecurityRule\` interface from \`@neuzhou/clawguard\`:

\`\`\`ts
const myRule: SecurityRule = {
  id: 'my-plugin/rule-name',
  name: 'My Rule',
  description: 'What it detects',
  owaspCategory: 'LLM01',
  enabled: true,
  check(content, direction, context) {
    // Return SecurityFinding[] 
    return [];
  },
};
\`\`\`

## License

MIT
`);
}
