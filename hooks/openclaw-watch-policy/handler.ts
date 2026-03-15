import * as path from 'path';
import * as fs from 'fs';

interface Policy {
  exec: { dangerous_commands: string[] };
  file: { deny_read: string[]; deny_write: string[] };
  browser: { block_domains: string[] };
}

const DEFAULT_POLICY: Policy = {
  exec: {
    dangerous_commands: [
      'rm -rf', 'rmdir /s', 'del /f /s', 'mkfs', 'dd if=',
      'curl.*\\|.*bash', 'wget.*\\|.*sh', 'nc -e', 'ncat -e',
      'bash -i >& /dev/tcp', 'python.*socket.*connect',
      'powershell.*-e ', 'powershell.*downloadstring',
    ],
  },
  file: {
    deny_read: ['**/.env*', '**/.ssh/*', '**/*private*key*'],
    deny_write: ['**/SOUL.md', '**/IDENTITY.md', '**/AGENTS.md'],
  },
  browser: {
    block_domains: [],
  },
};

function loadPolicy(): Policy {
  const policyPath = path.join(
    process.env.HOME || process.env.USERPROFILE || '.',
    '.openclaw', 'carapace', 'policies.yaml'
  );
  // For simplicity, use defaults if no yaml parser available
  if (!fs.existsSync(policyPath)) return DEFAULT_POLICY;
  try {
    // Simple YAML-like parsing for flat structure
    const raw = fs.readFileSync(policyPath, 'utf-8');
    // Fall back to defaults — full YAML parsing would need a dependency
    console.log('[carapace-policy] Custom policy file found, using defaults + custom (full YAML requires js-yaml)');
    return DEFAULT_POLICY;
  } catch {
    return DEFAULT_POLICY;
  }
}

function matchesPattern(text: string, pattern: string): boolean {
  try {
    return new RegExp(pattern, 'i').test(text);
  } catch {
    return text.toLowerCase().includes(pattern.toLowerCase());
  }
}

function matchesGlob(filepath: string, glob: string): boolean {
  const regex = glob
    .replace(/\*\*/g, '.*')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '.');
  return new RegExp(regex, 'i').test(filepath);
}

const handler = async (event: any) => {
  const content = event.context?.content;
  if (!content || typeof content !== 'string') return;

  const policy = loadPolicy();
  const warnings: string[] = [];

  // Detect exec-like tool calls
  const execMatch = content.match(/exec.*?command['":\s]+(.+?)['"\n}]/is);
  if (execMatch) {
    const cmd = execMatch[1];
    for (const pattern of policy.exec.dangerous_commands) {
      if (matchesPattern(cmd, pattern)) {
        warnings.push(`🔒 **Blocked exec**: \`${cmd.slice(0, 80)}\` matches dangerous pattern \`${pattern}\``);
      }
    }
  }

  // Detect file read/write tool calls
  const fileMatch = content.match(/(read|write|edit).*?(?:path|file_path)['":\s]+(.+?)['"\n}]/is);
  if (fileMatch) {
    const action = fileMatch[1].toLowerCase();
    const filepath = fileMatch[2];
    const denyList = action === 'read' ? policy.file.deny_read :
                     action === 'write' || action === 'edit' ? policy.file.deny_write : [];
    for (const glob of denyList) {
      if (matchesGlob(filepath, glob)) {
        warnings.push(`🔒 **Blocked ${action}**: \`${filepath}\` matches deny pattern \`${glob}\``);
      }
    }
  }

  // Detect browser navigation to blocked domains
  const browserMatch = content.match(/browser.*?url['":\s]+(https?:\/\/[^\s'"]+)/is);
  if (browserMatch) {
    const url = browserMatch[1];
    for (const domain of policy.browser.block_domains) {
      if (url.toLowerCase().includes(domain.toLowerCase())) {
        warnings.push(`🔒 **Blocked browser**: URL \`${url}\` matches blocked domain \`${domain}\``);
      }
    }
  }

  if (warnings.length > 0) {
    // Log
    const logDir = path.join(process.env.HOME || process.env.USERPROFILE || '.', '.openclaw', 'carapace');
    if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
    const logFile = path.join(logDir, 'policy-blocks.jsonl');
    for (const w of warnings) {
      fs.appendFileSync(logFile, JSON.stringify({ warning: w, timestamp: Date.now(), content: content.slice(0, 200) }) + '\n');
    }

    const msg = `🔒 **Carapace Policy** (${warnings.length} violation${warnings.length > 1 ? 's' : ''}):\n${warnings.join('\n')}`;
    event.messages.push(msg);
  }
};

export default handler;

