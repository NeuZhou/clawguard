# 架构设计

## Hook 管道

```
Gateway 事件
    ├─► Collector Hook ──► 存储（JSONL）
    ├─► Security Hook ──► 安全引擎 ──► 规则管道
    ├─► Guardian Hook ──► 告警引擎
    └─► Dashboard Hook ──► HTTP 服务 (:19790)
```

## 存储

所有数据以 JSONL 格式存储在 `~/.openclaw/openclaw-watch/`：

| 文件 | 内容 |
|------|------|
| `messages.jsonl` | 所有拦截的消息 |
| `security.jsonl` | 安全发现 |
| `audit.jsonl` | 哈希链审计事件 |
| `sessions.json` | 会话状态 |
| `config.json` | 用户配置 |

超过大小限制（默认 50MB）自动轮转并 gzip 压缩。

## 设计原则

- **零原生依赖** — 纯 Node.js，跨平台运行
- **非阻塞** — 安全扫描在微秒级完成
- **自包含** — 无需外部数据库或服务
- **隐私优先** — 所有数据本地存储
