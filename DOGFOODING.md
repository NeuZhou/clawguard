# OpenClaw Watch — Dogfooding Iteration Log

## Round 1 (v5.0.0 → v5.0.2)
- ❌ compliance "rm" regex 太宽泛 → ✅ 已修复, 误报 -62.5%
- ❌ "openclaw" typosquat 自触发 → ✅ 已修复
- ❌ SKILL.md 触发 VirusTotal → ✅ 已精简

## Round 2 — Agent-First 体验 (当前)

### 问题 1: MEMORY.md 提及 vs 修改 分不清
- self-improving-agent 文档中**描述了** MEMORY.md 文件结构就被标记 critical
- 应该区分：`write MEMORY.md` / `echo > MEMORY.md` (真正修改) vs 文档中提到文件名
- **解决方案**: identity-protection 规则需要检测**操作动词** + 文件名组合，而非单独文件名出现

### 问题 2: Agent 用 programmatic API 不够方便
- 当前只有 CLI 和 require() 两种方式
- Agent 理想的使用方式是直接在 SKILL.md 里写好一段 node -e 单行命令
- 但 node -e 里 escape 引号很痛苦
- **解决方案**: 增加一个专门给 agent 用的 mini CLI 模式
  - `npx openclaw-watch check-message "text here"` → 直接输出 severity
  - `npx openclaw-watch check-skill ./path/` → 等同 scan 但输出更简洁

### 问题 3: 扫描结果缺少 Risk Score
- CLI scan 输出没有展示总体 risk score 和 verdict
- **解决方案**: 在 scan 输出末尾加上 Risk Score 和 Verdict

### 问题 4: 没有增量扫描能力
- 每次全量扫描，无法知道"哪些是新增的"
- heartbeat 场景需要对比上次结果
- **解决方案**: `--baseline <file>` 参数或 `.openclaw-watch-baseline.json`

### 问题 5: npm 上还是旧版 0.3.5
- SKILL.md 里写的 `npx openclaw-watch` 跑的是旧版
- **必须 npm publish v5.0.2**

## Priority
1. 🔥 P0: 修 identity-protection 误报（提及 vs 修改）
2. 🔥 P0: 增加 `check-message` CLI 子命令（agent-first）
3. 🔥 P0: scan 输出加 Risk Score
4. P1: npm publish
5. P1: 增量扫描 baseline
6. P2: ClawHub v5.0.3 发布
