# OpenClaw Watch — Dogfooding 改进清单

## 2026-03-15 首次实战扫描

### 环境
- 扫描目标: `~/.openclaw/workspace/skills/` (85 files, 16 skills)
- 结果: 40 findings (2 critical, 5 high, 3 warning, 30 info)

### 🔴 P0 — 误报率过高
1. **compliance "rm" 匹配太宽泛** — 30 个 info 级 findings 大部分是文档中 `rm`、`del`、`Remove` 作为普通英文单词出现。需要改为只匹配命令上下文（如 `rm -rf`、`rm file`）而非独立出现的单词。
2. **typosquat "openclaw" 自触发** — 我们自己的 SKILL.md 里 `"openclaw"` 被标记。需要加白名单或改为只检测 `require/import` 上下文。

### 🟠 P1 — SKILL.md 触发问题
3. **旧版 SKILL.md 触发 critical** — 已在 v5.0.1 修复，等 ClawHub 安全审核通过后更新。

### 🟡 P2 — 功能增强
4. **增加排除规则** — 用户应该能配置 `exclude` 路径/文件。
5. **增加 `--min-severity` 参数** — 让用户过滤只看 high/critical。
6. **Risk Score 没在 CLI 输出中展示** — 扫描结果应该展示总风险分。

### 合理的发现（不需要修）
- web-pilot `os.remove()` — 合理 warning
- web-pilot `PATH = "/"` — 合理 high
- docker-essentials `path:/` — 合理 high
- hugo-blog-agent `sudo` — 合理 warning
