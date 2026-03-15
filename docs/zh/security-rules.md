# 安全规则参考

## 内置规则

### 1. 提示词注入检测 (`prompt-injection`)

**OWASP:** LLM01 — Prompt Injection

扫描**入站**消息，检测注入攻击。

| 类别 | 检测内容 | 严重级别 |
|------|---------|---------|
| 直接注入 | "忽略之前的指令"、角色篡改、越狱 | critical |
| 分隔符注入 | 聊天模板分隔符 (`<\|system\|>`, `[INST]`) | critical/high |
| 编码注入 | Base64 载荷、零宽字符、同形字 | high |
| 间接注入 | 隐藏指令、HTML 注释 | high/warning |
| 多轮注入 | 虚假上下文引用、记忆植入 | warning |

### 2. 数据泄露检测 (`data-leakage`)

**OWASP:** LLM06 — 敏感信息泄露

扫描**出站**消息，检测密钥和敏感数据。

| 类型 | 示例 | 严重级别 |
|------|------|---------|
| API 密钥 | OpenAI、Anthropic、GitHub、AWS、Stripe | critical |
| 凭证 | Bearer token、私钥、JWT、URL中的密码 | critical/high |
| PII | SSN、信用卡号（Luhn 校验） | critical |

检测到密钥时会提供**轮换 URL**（OpenAI、GitHub、AWS 等）。

### 3. 异常检测 (`anomaly-detection`)

| 异常类型 | 阈值 | 严重级别 |
|---------|------|---------|
| 消息轰炸 | >10条/60秒 | warning |
| Token 炸弹 | >50K token/条 | high |
| 循环检测 | >5次重复/2分钟 | high |
| 无限重试 | 同错误>3次/2分钟 | high |
| 递归子代理 | 深度>3 | critical |
| 磁盘空间炸弹 | >100MB/5分钟 | high |
| 网络洪泛 | >50请求/1分钟 | high |

### 4. 合规审计 (`compliance`)

跟踪文件系统修改、权限提升、外部访问和工具调用。

### 5. 文件删除保护 (`file-protection`)

**OWASP:** LLM02 — 不安全的输出处理

检测破坏性文件系统操作，目标为关键路径时升级为 critical。
