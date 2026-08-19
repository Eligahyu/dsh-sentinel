# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.2.x | ✅ |
| 0.1.x | ⚠️ 仅安全修复 |

## Reporting a Vulnerability

dsh-sentinel 是一个安全扫描工具,自身的安全同样重要。请通过以下渠道报告:

- **GitHub Private Vulnerability Reporting**:在本仓库的 **Security → Report a vulnerability** 提交
- 或邮件至仓库维护者(见 GitHub 主页)

**请勿**在公开 Issue / 讨论 / 社交媒体中披露未修复的漏洞细节(包括 0-day)。

## Response Timeline

- 48 小时内确认收到报告
- 7 天内给出修复计划
- 修复后发布安全版本,并在 CHANGELOG 中记录(CVE 编号如有)

## What We Care About

- 扫描器自身被恶意构造的插件/路径攻破(如路径逃逸、zip-slip、拒绝服务)
- 报告二次泄露:secret 脱敏绕过、绝对路径泄露
- 误执行被扫描代码(红线:任何情况下都不执行)
- 默认行为意外联网(所有联网能力默认关闭)

## Security-relevant design guarantees

- 扫描器只读:绝不 `require/import/eval/spawn` 被扫描代码
- 所有 manifest 派生路径经过 containment(`engine/path-safety.js`),逃逸即报 `SEN-MAN-009`
- 报告中的 secret 一律脱敏(`engine/redact.js`),只保留指纹
- 默认不上传任何源码;未来的联网能力(CVE/OSV)只会上传包名/版本/hash
