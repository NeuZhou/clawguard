# CI/CD Integration Guide

ClawGuard integrates into any CI/CD pipeline. This guide covers all major platforms.

## GitHub Actions

### Option 1: Reusable Action (Recommended)

```yaml
- uses: neuzhou/clawguard@v1
  with:
    path: '.'
    format: 'sarif'
    severity-threshold: 'high'
```

This automatically:
- Installs ClawGuard
- Runs the scan
- Uploads SARIF to GitHub Security tab
- Fails the step if findings exceed the threshold
- Writes a summary to the job

### Option 2: npx (Quick Setup)

```yaml
- run: npx @neuzhou/clawguard scan . --format sarif --output results.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

### SARIF + GitHub Security Tab

When using `format: sarif`, findings appear in the **Security** tab under **Code scanning alerts**. This gives you:
- Persistent tracking of findings across commits
- Automatic PR annotations
- Dismissal workflow for false positives

> **Required permission:** `security-events: write`

### Example Workflows

See [`examples/github-actions/`](../examples/github-actions/) for copy-paste workflows:
- **basic-scan.yml** — Scan on push/PR with SARIF upload
- **pr-comment.yml** — Post findings as a PR comment
- **block-critical.yml** — Fail builds on critical/high findings

---

## GitLab CI

```yaml
clawguard-scan:
  image: node:20-slim
  stage: test
  script:
    - npm install -g @neuzhou/clawguard
    - clawguard scan . --format json --output gl-clawguard.json
    - |
      CRITICAL=$(node -e "const r=require('./gl-clawguard.json');console.log(r.summary?.critical||0)")
      HIGH=$(node -e "const r=require('./gl-clawguard.json');console.log(r.summary?.high||0)")
      if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
        echo "❌ Found $CRITICAL critical and $HIGH high severity findings"
        exit 1
      fi
  artifacts:
    paths:
      - gl-clawguard.json
    when: always

# GitLab SAST integration (converts to GitLab Security format)
clawguard-sast:
  image: node:20-slim
  stage: test
  script:
    - npm install -g @neuzhou/clawguard
    - clawguard scan . --format sarif --output gl-sast-report.sarif
  artifacts:
    reports:
      sast: gl-sast-report.sarif
    when: always
```

---

## Azure DevOps Pipelines

```yaml
trigger:
  branches:
    include: [main]

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: NodeTool@0
    inputs:
      versionSpec: '20.x'

  - script: npm install -g @neuzhou/clawguard
    displayName: 'Install ClawGuard'

  - script: |
      clawguard scan . --format sarif --output $(Build.ArtifactStagingDirectory)/clawguard.sarif
    displayName: 'Run ClawGuard Scan'
    continueOnError: true

  - script: |
      RESULT=$(clawguard scan . --format json)
      CRITICAL=$(echo "$RESULT" | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log(d.summary?.critical||0)")
      HIGH=$(echo "$RESULT" | node -e "const d=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log(d.summary?.high||0)")
      if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
        echo "##vso[task.logissue type=error]ClawGuard found $CRITICAL critical and $HIGH high findings"
        echo "##vso[task.complete result=Failed;]"
      fi
    displayName: 'Check Severity Threshold'

  - publish: $(Build.ArtifactStagingDirectory)/clawguard.sarif
    artifact: security-scan
    condition: always()
```

---

## Pre-commit Hook

### Option 1: npm script

Add to `package.json`:

```json
{
  "scripts": {
    "security": "clawguard scan . --severity-threshold high"
  }
}
```

### Option 2: Husky

```bash
npm install -D husky @neuzhou/clawguard
npx husky init
echo 'npx clawguard scan . --severity-threshold high' > .husky/pre-commit
```

### Option 3: pre-commit framework

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: clawguard
        name: ClawGuard Security Scan
        entry: npx @neuzhou/clawguard scan
        language: system
        pass_filenames: false
        stages: [pre-commit]
```

---

## Docker

```bash
# One-shot scan of current directory
docker run --rm -v $(pwd):/app neuzhou/clawguard scan /app

# With custom rules
docker run --rm -v $(pwd):/app neuzhou/clawguard scan /app --rules /app/.clawguard-rules.yml

# Output SARIF
docker run --rm -v $(pwd):/app neuzhou/clawguard scan /app --format sarif > results.sarif
```

Use in any CI system:

```yaml
# Generic CI (e.g., CircleCI, Jenkins)
steps:
  - run: docker run --rm -v $PWD:/app neuzhou/clawguard scan /app --format sarif --output /app/results.sarif
```

---

## Configuration

All CI methods support the same flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `text` | Output format: `text`, `json`, `sarif` |
| `--output` | stdout | Write output to file |
| `--severity-threshold` | `high` | Fail on findings at or above this level |
| `--rules` | built-in | Path to custom rules file |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings above threshold |
| 1 | Findings found above threshold |
| 2 | Scan error (invalid path, bad config) |
