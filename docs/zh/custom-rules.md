# 自定义规则编写指南

## 概述

自定义规则是 YAML 文件，放置在 `~/.openclaw/openclaw-watch/rules.d/`，网关启动时自动加载。

## Schema

```yaml
name: "规则包名称"
version: "1.0"
rules:
  - id: unique-rule-id
    description: "规则描述"
    event: message:received    # 或 message:sent
    severity: critical         # critical | high | warning | info
    patterns:
      - regex: "正则表达式"     # 不区分大小写
      - keyword: "关键词"       # 简单子串匹配
    action: alert              # alert | log | block
```

## 示例

### 检测内部项目代号泄露

```yaml
name: "内部项目保护"
version: "1.0"
rules:
  - id: project-codename
    description: "检测内部项目代号"
    event: message:sent
    severity: high
    patterns:
      - keyword: "凤凰计划"
      - keyword: "PROJECT PHOENIX"
    action: alert
```

## 社区规则

查看 [`community-rules/`](../../community-rules/) 获取行业规则包（HIPAA、PCI-DSS、DLP）。
