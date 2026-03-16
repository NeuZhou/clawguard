// ClawGuard - Threat Intelligence
// Known bad patterns database for URLs, commands, and injection payloads

export interface ThreatResult {
  isThreat: boolean;
  severity: 'none' | 'low' | 'medium' | 'high' | 'critical';
  category: string;
  matched?: string;
  description?: string;
}

export interface ThreatStats {
  urlPatterns: number;
  commandPatterns: number;
  payloadPatterns: number;
  lastUpdated: number;
  version: string;
}

interface ThreatPattern {
  pattern: string;
  regex?: RegExp;
  severity: 'low' | 'medium' | 'high' | 'critical';
  category: string;
  description: string;
}

// ─── Built-in Threat Feeds ───

const URL_THREATS: ThreatPattern[] = [
  // Known malicious domains
  { pattern: 'pastebin.com/raw', severity: 'high', category: 'data-exfil', description: 'Raw pastebin used for C2/exfil' },
  { pattern: 'transfer.sh', severity: 'medium', category: 'data-exfil', description: 'File transfer service often used for exfil' },
  { pattern: 'ngrok.io', severity: 'medium', category: 'tunnel', description: 'Tunneling service — potential C2' },
  { pattern: 'requestbin.com', severity: 'medium', category: 'data-exfil', description: 'Request capture service' },
  { pattern: 'webhook.site', severity: 'medium', category: 'data-exfil', description: 'Webhook capture service' },
  { pattern: 'pipedream.net', severity: 'medium', category: 'data-exfil', description: 'Webhook/pipeline service' },
  { pattern: 'interactsh.com', severity: 'high', category: 'recon', description: 'OOB interaction testing (often malicious)' },
  { pattern: 'burpcollaborator.net', severity: 'high', category: 'recon', description: 'Burp Collaborator OOB testing' },
  { pattern: 'canarytokens.com', severity: 'medium', category: 'recon', description: 'Canary token tracking' },
  { pattern: 'raw.githubusercontent.com', severity: 'low', category: 'supply-chain', description: 'Direct GitHub raw — verify source' },
  // Suspicious TLDs
  { pattern: '.onion', severity: 'high', category: 'tor', description: 'Tor hidden service' },
  { pattern: '.bit', severity: 'medium', category: 'alt-dns', description: 'Alternative DNS (Namecoin)' },
  // IP-based URLs
  { pattern: '', regex: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, severity: 'medium', category: 'suspicious-url', description: 'Direct IP URL — potential C2' },
  // Data URI exfil
  { pattern: '', regex: /data:[^;]+;base64,.{100,}/, severity: 'high', category: 'data-exfil', description: 'Large base64 data URI — potential exfil' },
];

const COMMAND_THREATS: ThreatPattern[] = [
  // Reverse shells
  { pattern: '', regex: /bash\s+-i\s+>&?\s*\/dev\/tcp\//, severity: 'critical', category: 'reverse-shell', description: 'Bash reverse shell via /dev/tcp' },
  { pattern: '', regex: /python[3]?\s+-c\s+['"]import\s+socket/, severity: 'critical', category: 'reverse-shell', description: 'Python reverse shell' },
  { pattern: '', regex: /nc\s+(-[elknv]+\s+)+/, severity: 'high', category: 'reverse-shell', description: 'Netcat with execution flags' },
  { pattern: '', regex: /socat\s+.*exec:/, severity: 'critical', category: 'reverse-shell', description: 'Socat reverse shell' },
  { pattern: '', regex: /php\s+-r\s+.*fsockopen/, severity: 'critical', category: 'reverse-shell', description: 'PHP reverse shell' },
  { pattern: '', regex: /ruby\s+-rsocket/, severity: 'critical', category: 'reverse-shell', description: 'Ruby reverse shell' },
  { pattern: '', regex: /perl\s+-e\s+.*socket/, severity: 'critical', category: 'reverse-shell', description: 'Perl reverse shell' },
  // Credential theft
  { pattern: '', regex: /cat\s+.*\/(\.ssh\/|\.aws\/|\.env|\.netrc|shadow|passwd)/, severity: 'high', category: 'credential-theft', description: 'Reading credential files' },
  { pattern: '', regex: /curl\s+.*-d\s+.*password/, severity: 'high', category: 'credential-theft', description: 'Sending passwords via curl' },
  // Persistence
  { pattern: '', regex: /crontab\s+-[el]/, severity: 'medium', category: 'persistence', description: 'Crontab modification' },
  { pattern: '', regex: /echo\s+.*>>\s*.*\/(\.bashrc|\.profile|\.zshrc|crontab)/, severity: 'high', category: 'persistence', description: 'Modifying startup files' },
  { pattern: '', regex: /systemctl\s+(enable|start)\s+/, severity: 'medium', category: 'persistence', description: 'Enabling system services' },
  // Privilege escalation
  { pattern: '', regex: /sudo\s+chmod\s+[47]755?\s+\//, severity: 'high', category: 'privesc', description: 'Changing root permissions with sudo' },
  { pattern: '', regex: /chmod\s+u\+s\s+/, severity: 'critical', category: 'privesc', description: 'Setting SUID bit' },
  // Data destruction
  { pattern: '', regex: /rm\s+-rf\s+\/(?!\w)/, severity: 'critical', category: 'destruction', description: 'Recursive delete from root' },
  { pattern: '', regex: /mkfs\.\w+\s+\/dev\//, severity: 'critical', category: 'destruction', description: 'Formatting disk device' },
  // Crypto mining
  { pattern: '', regex: /xmrig|minerd|cgminer|cpuminer|stratum\+tcp/, severity: 'high', category: 'cryptomining', description: 'Cryptocurrency mining tools' },
  // Encoded/obfuscated commands
  { pattern: '', regex: /echo\s+[A-Za-z0-9+\/=]{20,}\s*\|\s*base64\s+-d\s*\|\s*(bash|sh)/, severity: 'critical', category: 'obfuscation', description: 'Base64-encoded command execution' },
  { pattern: '', regex: /\$\(\s*echo\s+.*\|\s*base64\s+-d\s*\)/, severity: 'high', category: 'obfuscation', description: 'Inline base64 decode execution' },
];

const PAYLOAD_THREATS: ThreatPattern[] = [
  // Prompt injection
  { pattern: '', regex: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)/i, severity: 'high', category: 'prompt-injection', description: 'Classic prompt injection' },
  { pattern: '', regex: /you\s+are\s+now\s+(DAN|jailbroken|unrestricted)/i, severity: 'high', category: 'prompt-injection', description: 'Jailbreak attempt (DAN)' },
  { pattern: '', regex: /system\s*:\s*(you|your|the)\s+(new|updated|real)\s+(instructions|role)/i, severity: 'high', category: 'prompt-injection', description: 'Fake system prompt injection' },
  { pattern: '', regex: /\[SYSTEM\]|\[INST\]|<\|system\|>|<\|im_start\|>system/i, severity: 'critical', category: 'prompt-injection', description: 'Token-level prompt injection' },
  // Data exfiltration
  { pattern: '', regex: /curl\s+.*(-X\s+POST|-d\s+@|--data-binary\s+@).*\.(env|pem|key|json|db|sqlite)/i, severity: 'critical', category: 'data-exfil', description: 'Exfiltrating sensitive files via curl' },
  { pattern: '', regex: /fetch\(['"]https?:\/\/[^'"]+['"],\s*\{[^}]*method:\s*['"]POST['"]/i, severity: 'high', category: 'data-exfil', description: 'JavaScript fetch POST exfil' },
  // SQL injection
  { pattern: '', regex: /(['";]\s*(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+|UNION\s+SELECT|DROP\s+TABLE|;\s*DELETE\s+FROM)/i, severity: 'high', category: 'sql-injection', description: 'SQL injection pattern' },
  // XSS
  { pattern: '', regex: /<script[^>]*>.*<\/script>|javascript:\s*\w+|on(error|load|click)\s*=/i, severity: 'medium', category: 'xss', description: 'Cross-site scripting pattern' },
  // SSRF
  { pattern: '', regex: /http:\/\/(169\.254\.169\.254|metadata\.google|100\.100\.100\.200)/i, severity: 'critical', category: 'ssrf', description: 'SSRF targeting cloud metadata' },
  { pattern: '', regex: /http:\/\/localhost|http:\/\/127\.0\.0\.1|http:\/\/0\.0\.0\.0/i, severity: 'medium', category: 'ssrf', description: 'SSRF targeting localhost' },
  // Path traversal
  { pattern: '', regex: /\.\.\/(\.\.\/){2,}|\.\.\\(\.\.\\){2,}/i, severity: 'high', category: 'path-traversal', description: 'Deep path traversal' },
];

export class ThreatIntel {
  private urlPatterns: ThreatPattern[];
  private commandPatterns: ThreatPattern[];
  private payloadPatterns: ThreatPattern[];
  private customUrlBlocklist: Set<string> = new Set();
  private lastUpdated: number;
  private version: string;

  constructor() {
    this.urlPatterns = [...URL_THREATS];
    this.commandPatterns = [...COMMAND_THREATS];
    this.payloadPatterns = [...PAYLOAD_THREATS];
    this.lastUpdated = Date.now();
    this.version = '1.0.0';
  }

  /** Check a URL against threat intelligence */
  checkUrl(url: string): ThreatResult {
    if (!url) return noThreat();

    // Custom blocklist
    for (const blocked of this.customUrlBlocklist) {
      if (url.toLowerCase().includes(blocked.toLowerCase())) {
        return {
          isThreat: true,
          severity: 'high',
          category: 'custom-blocklist',
          matched: blocked,
          description: 'URL matches custom blocklist',
        };
      }
    }

    return this.matchPatterns(url, this.urlPatterns);
  }

  /** Check a command against known dangerous patterns */
  checkCommand(cmd: string): ThreatResult {
    if (!cmd) return noThreat();
    return this.matchPatterns(cmd, this.commandPatterns);
  }

  /** Check a payload for injection patterns */
  checkPayload(payload: string): ThreatResult {
    if (!payload) return noThreat();
    return this.matchPatterns(payload, this.payloadPatterns);
  }

  /** Add URLs to custom blocklist */
  addToBlocklist(urls: string[]): void {
    for (const u of urls) this.customUrlBlocklist.add(u);
  }

  /** Simulate updating threat feeds */
  async update(): Promise<void> {
    // In production, this would fetch from a remote threat feed
    this.lastUpdated = Date.now();
    this.version = '1.0.1';
  }

  /** Get statistics about loaded patterns */
  getStats(): ThreatStats {
    return {
      urlPatterns: this.urlPatterns.length + this.customUrlBlocklist.size,
      commandPatterns: this.commandPatterns.length,
      payloadPatterns: this.payloadPatterns.length,
      lastUpdated: this.lastUpdated,
      version: this.version,
    };
  }

  private matchPatterns(input: string, patterns: ThreatPattern[]): ThreatResult {
    for (const p of patterns) {
      if (p.regex && p.regex.test(input)) {
        return {
          isThreat: true,
          severity: p.severity,
          category: p.category,
          matched: p.regex.source,
          description: p.description,
        };
      }
      if (p.pattern && input.toLowerCase().includes(p.pattern.toLowerCase())) {
        return {
          isThreat: true,
          severity: p.severity,
          category: p.category,
          matched: p.pattern,
          description: p.description,
        };
      }
    }
    return noThreat();
  }
}

function noThreat(): ThreatResult {
  return { isThreat: false, severity: 'none', category: 'clean', description: 'No threat detected' };
}
