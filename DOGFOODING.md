# OpenClaw Watch — Dogfooding Iteration Log

## Round 1 (v5.0.0 → v5.0.2): False Positive Reduction
- compliance "rm" regex → 要求命令上下文
- "openclaw" typosquat 自触发 → 移除正名
- 40 → 15 findings (-62.5%)

## Round 2 (v5.0.2 → v5.1.0): Agent-First Paradigm
- check 命令: 一句话检测消息威胁
- Risk Score 展示
- identity-protection "rm" 子串误报修复
- SKILL.md 重写: agent-first 免疫系统

## Round 3 (v5.1.0 → v5.1.1): Static Scan Optimization
- staticScan 标志: 跳过 tool-call tracking（文件扫描不需要）
- write regex 收紧: 要求实际文件路径
- 14 → 8 findings
- SKILL.md 加 CONTRIBUTE BACK 章节

## Round 4: 竞品实战分析 (当前)

### 竞品扫描结果
- openguardrails (MoltGuard v6.8.20): 0 findings — 干净但 SaaS 付费模式
- security-skill-scanner v2.0.0: 3 findings — 故意包含恶意示例
- openclaw-security-guard v1.0.0: 24 findings (15 critical!) — 文档中攻击示例触发

### 竞品差距分析
我们领先:
- ✅ 离线零隐私 vs MoltGuard 发数据到云端
- ✅ Agent-first + 贡献机制 vs 全部面向人类
- ✅ 自扫描干净 vs openclaw-security-guard 15 critical
- ✅ 最精简 SKILL.md (2.6KB) vs security-skill-scanner (9.5KB)

我们落后:
- ❌ 没有 Intent-Action Mismatch Detection (MoltGuard 有)
- ❌ 没有插件模式自动拦截 (MoltGuard 有 openclaw plugin)
- ❌ 没有 npm publish (npx 还是旧版)
- ❌ 没有 dashboard UI
- ❌ risk score 100 是因为 critical 过多导致溢出，不够精细

### P0 行动项
1. npm publish (需要老板帮忙 npm login)
2. mcp-security 规则对 `path:/` 和 `file:/` 在文档上下文中太敏感 — 考虑降级或加上下文检测
3. Risk Score 溢出问题: 多个 critical 直接到 100，应该有更好的分级

### P1 行动项
4. 增量扫描 baseline（heartbeat 场景）
5. Intent-Action Mismatch 概念验证
6. 自动发现并安装机制（让 agent 知道 openclaw-watch 存在）
