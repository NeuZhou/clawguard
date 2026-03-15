# クイックスタート

## インストール

```bash
openclaw hooks install clawguard
openclaw gateway restart
```

ダッシュボード：**http://localhost:19790**

## 必要条件

- Node.js ≥ 18
- OpenClaw Gateway 実行中

## 設定

初回起動時に `~/.openclaw/clawguard/config.json` が自動作成されます。

### 予算制限

```json
{
  "budget": {
    "dailyUsd": 50,
    "weeklyUsd": 200,
    "monthlyUsd": 500
  }
}
```

### セキュリティルール

全ルールがデフォルトで有効です。無効化するには：

```json
{
  "security": {
    "enabledRules": ["prompt-injection", "data-leakage"]
  }
}
```

### カスタムルール

YAMLファイルを `~/.openclaw/clawguard/rules.d/` に配置するだけで自動読み込みされます。

## 次のステップ

- [セキュリティルールリファレンス](security-rules.md)
- [English docs](../en/getting-started.md)
