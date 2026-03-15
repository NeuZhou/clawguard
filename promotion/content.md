# OpenClaw Watch — Promotion Materials

## 🇺🇸 English — Hacker News / Reddit / Twitter

### HN Title (Show HN)
**Show HN: OpenClaw Watch – An immune system for AI agents (285+ threat patterns, 100% local)**

### HN Post Body
Hi HN,

I built OpenClaw Watch — a security scanner and runtime protection layer for AI agents. Think of it as an immune system: it scans for prompt injection, data leakage, supply chain attacks, and 285+ threat patterns, all running 100% locally with zero cloud dependencies.

Key features:
- **PII Sanitizer**: strips emails, API keys, JWTs, connection strings before sending to LLMs — entirely local, nothing leaves your machine
- **Intent-Action Mismatch Detection**: catches when an agent says "I'll read the weather" but actually runs `rm -rf /`
- **OWASP Agentic AI Top 10 (2026)**: full coverage of all 10 categories
- **229 tests passing**, SARIF output, CLI scanner
- **Agent-first design**: agents install it, use it, and report back automatically

Why I built this: Commercial alternatives like MoltGuard charge $19-199/month and send your data to their cloud for analysis. I wanted something that runs entirely on your machine with zero cost.

```bash
npx openclaw-watch scan ./my-project/
npx openclaw-watch sanitize "my API key is sk-proj-abc123..."
npx openclaw-watch intent-check --intent "read the config" --action "rm -rf /"
```

GitHub: https://github.com/NeuZhou/openclaw-watch
License: MIT

I'd love feedback on the detection patterns and false positive rates. What threats are you most worried about with AI agents?

### Twitter/X Thread
🧵 I built an immune system for AI agents. Here's why:

1/ AI agents can read your files, run commands, send emails. But who watches the watchers? 🛡️

2/ OpenClaw Watch scans for 285+ threat patterns: prompt injection, data leakage, supply chain attacks, identity tampering. All running 100% locally.

3/ NEW: PII Sanitizer — strips your emails, API keys, and secrets BEFORE sending to LLMs. Unlike cloud alternatives, nothing leaves your machine. Ever.

4/ NEW: Intent-Action Mismatch — catches agents that say "I'll check the weather" but actually run `rm -rf /`. Trust but verify.

5/ OWASP Agentic AI Top 10 (2026) — full coverage. 229 tests. MIT licensed. Zero dependencies.

6/ Try it: `npx openclaw-watch scan ./your-project/`

GitHub: https://github.com/NeuZhou/openclaw-watch

#AIAgents #Security #OpenSource #OWASP

---

## 🇨🇳 中文 — 知乎 / 掘金

### 知乎标题
**我给 AI Agent 做了一个"免疫系统"：285+ 威胁检测、PII 脱敏、意图-行为不匹配检测，100% 本地运行**

### 知乎正文

大家好，我是周康，微软 Principal 工程师。

最近 AI Agent 越来越火，但一个问题被严重忽视了：**谁来保护 Agent 不被攻击？谁来保护用户不被 Agent 伤害？**

Agent 可以读你的文件、执行命令、发送邮件、访问你的各种账号。如果 Agent 被 prompt injection 劫持了怎么办？如果安装的第三方插件里藏了恶意代码呢？

所以我做了 **OpenClaw Watch** — AI Agent 的免疫系统。

### 核心能力

**1. 安全扫描 (285+ 检测模式)**
覆盖 OWASP Agentic AI Top 10 (2026) 全部 10 个类别：
- 提示词注入检测（直接/间接）
- 数据泄露防护（PII、密钥、内部信息）
- 供应链攻击（恶意依赖、typosquat）
- MCP 工具安全（SSRF、权限越界）
- 身份保护（Agent 身份篡改）
- 异常行为检测（Token 爆炸、循环调用）

**2. PII 脱敏器（100% 本地）**
发送给 LLM 之前自动清洗敏感信息：
```
输入: "我的邮箱是 kangzhou@example.com，密钥是 sk-proj-abc123..."
输出: "我的邮箱是 <EMAIL_1>，密钥是 <API_KEY_2>"
```
**关键差异**：商业方案（如 MoltGuard，$19-199/月）需要把你的数据发到他们的云端清洗。我们完全在本地完成，**一个字节都不出你的机器**。

**3. 意图-行为不匹配检测**
Agent 说"我帮你查天气"，实际执行 `rm -rf /`？我们能抓住它：
```bash
$ openclaw-watch intent-check --intent "查看天气" --action "rm -rf /home"
🔴 MISMATCH (critical, confidence: 95%)
  Reason: Stated read intent but performing deletion
```

### 为什么做这个？

市面上的 AI Agent 安全方案要么是商业 SaaS（贵、数据上云），要么是学术论文（没法直接用）。我想做一个：
- **免费开源**（MIT）
- **100% 本地**（零云依赖）
- **Agent 自己会用**（不需要人工配置）
- **生产级质量**（229 个测试全绿）

### 使用

```bash
npx openclaw-watch scan ./your-project/
npx openclaw-watch sanitize "含敏感信息的文本"
npx openclaw-watch check "可疑的消息内容"
```

GitHub: https://github.com/NeuZhou/openclaw-watch

欢迎 Star ⭐、提 Issue、贡献代码。特别欢迎反馈误报率和漏检场景。

---

## 🇨🇳 掘金标题
**开源 | AI Agent 免疫系统：285+ 威胁检测 + PII 本地脱敏 + 意图行为检测，OWASP 2026 全覆盖**

(正文同知乎，加技术细节)

---

## Reddit — r/MachineLearning / r/artificial / r/cybersecurity

### Title
**[P] OpenClaw Watch: Open-source security scanner for AI agents — 285+ patterns, PII sanitizer, intent-action mismatch detection**

### Body
(Similar to HN post, adapted for Reddit audience)

---

## Key Talking Points (for all platforms)
1. **Privacy**: 100% local, zero cloud — your data never leaves your machine
2. **Cost**: Free vs $19-199/month commercial alternatives  
3. **Agent-first**: designed for agents to use autonomously, not just humans
4. **Quality**: 229 tests, OWASP 2026 full coverage, SARIF output
5. **Real problem**: AI agents have filesystem/network/email access but zero security oversight
