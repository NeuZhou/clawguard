# 快速开始

## 安装

```bash
openclaw hooks install openclaw-watch
openclaw gateway restart
```

仪表盘地址：**http://localhost:19790**

## 环境要求

- Node.js ≥ 18
- OpenClaw Gateway 运行中

## 配置

首次运行自动创建配置文件 `~/.openclaw/openclaw-watch/config.json`。

### 预算限制

```json
{
  "budget": {
    "dailyUsd": 50,
    "weeklyUsd": 200,
    "monthlyUsd": 500
  }
}
```

### 安全规则

所有规则默认启用，可按需禁用：

```json
{
  "security": {
    "enabledRules": ["prompt-injection", "data-leakage", "anomaly-detection"]
  }
}
```

### 自定义规则

将 YAML 文件放入 `~/.openclaw/openclaw-watch/rules.d/` 即可自动加载。

## 验证安装

```bash
curl http://localhost:19790/api/overview
curl http://localhost:19790/api/security/score
```

## 下一步

- [安全规则参考](security-rules.md)
- [自定义规则指南](custom-rules.md)
- [仪表盘使用指南](dashboard.md)
