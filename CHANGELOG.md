# Changelog

## 0.2.0 (2026-08-19) — 专业版 Phase-1

按[专业版升级任务书](docs/upgrade-spec.md)Phase-1 十项全部完成:

### 扫描完整性(安全工具红线)
- **修复**:maxFindings 曾导致命中数达上限后停止扫描后续文件——现在只限制报告保存条数(`findingsReturned`),实际分析永不提前停止,`findingsTotal` 全量计数
- 报告新增 `scanComplete` / `filesDiscovered` / `filesAnalyzed` / `findingsTruncated` / `incompleteScan`;不完整扫描强制裁决不低于 review 并输出 `INCOMPLETE SCAN` 标记

### 扫描模式
- 新增 `source`(默认,跳过 dist/build)/ `package`(必扫构建产物)/ `profile` 三种模式;`sentinel_scan` 工具与 CLI 均支持 `--mode`
- profile 审计默认 package mode,并自动排除扫描器自身;`scratch` 等本地缓存目录不再入扫

### 大文件策略
- >512KB 不再简单跳过:512KB–20MB 走 large-file-lite 分析(规则子集 + sha256 + `analysisMode: 'large-file-lite'` 标记)

### 安全加固
- **路径 containment**(`engine/path-safety.js`):patch/main/exports/入口名等所有 manifest 派生路径防逃逸,逃逸即 `SEN-MAN-009`(critical)
- **入口契约严格化**:`name` 与 `apply` 必须同时存在(ESM 命名导出 / export default 对象 / CJS 双键)
- **secret 脱敏**(`engine/redact.js`):snippet 只保留 `****` 与 sha256 指纹,报告零完整 secret
- 压缩产物(bundle)命中降一级计分并打标,转译器噪声不再撑爆裁决

### 语义引擎(骨架)
- `engine/semantic`:识别 `defineTool` 的 `execute(args)` 主体,污点传播 `args.* → exec/spawn/readFile/writeFile/fetch`
- 新规则 `SEN-AGENT-001/002/003/004`(shell/文件读/文件写/网络),识别 child_process 别名(`const { exec: run } = require(...)`)与多步变量传播;confidence: medium(待 AST 版升级)

### 其他
- `engine/version.js` 版本单一来源;报告 schemaVersion 2;`SECURITY.md`;41 项测试(positive/negative/evasion)

## 0.1.0 (2026-08-18)

- 首个 npm 发布:零依赖静态启发式扫描(执行/凭据/外传/混淆/安装脚本/文件系统/网络/manifest/hygiene)
- 双形态:DSH 工具插件(`sentinel_scan` / `sentinel_scan_profile`)+ 独立 CLI;测试上下文降权;43 仓库生态体检
