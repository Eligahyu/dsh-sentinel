# 集成:DSH `dsh plugin add` 前置审计

## 现状结论(先搜索,后设计)

**当前未确认到 DSH 官方存在正式 pre-install hook / security provider API。**
(检索了 deepseek-harness 官方仓库与 npm 生态,未见官方 hook;生态中存在
第三方安全门项目,但均非官方接口。)

因此本仓库**不伪造任何官方 API**,提供:

1. 可复用审计 API:`auditPackageBeforeInstall(spec, opts)`
2. CLI wrapper:`dsh-sentinel audit-install <pkg>` / `dsh-sentinel npm:<pkg>`
3. 本文档描述的集成设计(供 DSH 官方未来提供 hook 时对接)

## 理想流程(§27)

```text
dsh plugin add foo
  ↓
Sentinel audit-install foo
  ↓
ALLOW / REVIEW / BLOCK-RECOMMENDED
  ↓
用户确认(REVIEW 时交互式 y/N)
  ↓
真正安装
```

## API

```js
import { auditPackageBeforeInstall } from 'deepseek-harness-sentinel'

const { report, audit } = await auditPackageBeforeInstall('some-plugin', {
  maxFiles: 3000,
  advisories: false, // OSV 查询默认关闭
})

// audit.verdict: 'ALLOW' | 'REVIEW' | 'BLOCK-RECOMMENDED'
// audit.integrityOk / tarballSha256 / dependencyCount / installScripts
// report: 完整 schema v2 报告
```

决策语义(绝不叫 "MALICIOUS",只给建议):

| decision | 含义 |
| --- | --- |
| `ALLOW` | score ≤ 19,当前规则未发现问题 |
| `REVIEW` | 20–49,存在需人工复核项 |
| `BLOCK-RECOMMENDED` | ≥ 50 或 tarball 被安全层阻止(traversal/symlink/bomb)、integrity 不匹配 |

## 安全保证(§22)

- 只做:`npm metadata → tarball → quarantine temp → safe extraction → 静态扫描 → 删除`
- 绝不:`npm install / npm ci / npm exec / postinstall / prepare / preinstall / install`
- 安全解包:拒绝 `../`、绝对路径、盘符、symlink/hardlink 条目;
  tar bomb 限制(条目数 20000 / 解压总量 300MB / 单文件 50MB / 路径 1024 / 深度 32)
- integrity(sha512)不匹配 → SEN-SUPPLY-004 + 至少 REVIEW
- 解包被阻止 → SEN-SUPPLY-005 + BLOCK-RECOMMENDED + scanComplete=false
- 任何 success/failure/exception 都 finally cleanup quarantine

## 用户体验示例(REVIEW 时)

```text
⚠ dsh-sentinel detected security-sensitive behavior.

2 high findings:
- model-controlled network target
- install lifecycle script

Continue installation? [y/N]
```

## 集成示例(DSH 官方提供 hook 后的对接位)

```js
// 假设未来 DSH 提供 DSH_PRE_INSTALL_HOOK / installer hook
// 本仓库提供的适配函数(不伪造官方 API,仅作为示例):
export async function decideInstall(spec, { force = false } = {}) {
  const { audit } = await auditPackageBeforeInstall(spec)
  if (audit.verdict === 'ALLOW') return { decision: 'ALLOW', proceed: true }
  if (audit.verdict === 'BLOCK-RECOMMENDED' && !force) {
    return { decision: 'BLOCK-RECOMMENDED', proceed: false, reason: [`critical finding in ${spec}`] }
  }
  return { decision: 'REVIEW', proceed: false, reason: ['user confirmation required'] }
}
```

## 原则

- Sentinel 不应强制篡改用户安装流程;BLOCK 是"建议 + 默认拒绝继续",
  用户可显式确认/`--force`
- 等 DSH 官方提供正式 security hook 后再对接;在此之前只提供可复用 API 与文档
