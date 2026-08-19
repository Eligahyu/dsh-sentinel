# Changelog

## 0.3.1 (2026-08) — 第二轮一次性修复(v2)

按 `dsh-sentinel-professional-v2-full-fix.md` 完成 22 项必改,把底层正确性债务一次性清掉,
并把 SARIF / GitHub Action / 安装前审计集成准备到位。优先级:正确性 > 完整性 > 防绕过 >
输出一致性 > CI 集成 > 生态功能。

### P0 正确性

- **评分与展示彻底解耦(P0-1)**:新增 `scoreBasedOnAllFindings`;扫描器维护全量
  `allStats`(bySeverity/byCategory/byContext/rawScore),评分基于全部有效命中;
  报告展示使用**优先级有界缓冲**(critical > high > medium > low > info),
  critical/high 即使出现在 maxFindings 之后也永不丢失——攻击者无法用淹没式低危命中稀释风险分
- **profile 大文件假分析修复(P0-2)**:删除 `scanTreeSync()`,profile 统一 `await scanTree`,
  大文件真正走 large-file-lite(此前只统计语言不扫描,却报告 filesAnalyzed)
- **findingsTotal 虚高修复(P0-3)**:`applyRule` 顺序改为去重 → excludes → comment → 计数,
  注释行与 known-safe idiom 不再计入 findingsTotal
- **minified/bundle 全局降级取消(P0-4)**:压缩产物只作为 evidence(`bundleFile` 标记),
  绝不自动降 severity;置信度由检测方式决定(regex → medium,AST/taint → high)
- **path containment 强化(P0-5)**:词法 containment + realpath containment +
  symlink/junction 防护 + 平台感知大小写(仅 Windows 不敏感)

### 完整性(防 silent skip)

- **hardMax 文件(P0-6)**:超过硬上限的文件记录 metadata(path/size/sha256/extension/
  文本-二进制分类/URL/exec 关键字/熵估计),并强制 `scanComplete=false`
- **maxPlugins 截断(P0-7)**:pluginsSkipped 结构化为 `{name, reason}`
  (trusted-scope/self/maxPlugins-limit/not-installed/not-a-dsh-plugin),
  limit 类截断 → `scanComplete=false`;报告新增 policySkips / coverageSkips 分类
- **二进制最低限度审计**:新增 `engine/binary/{inspect,strings,entropy}.js`,
  `.wasm/.exe/.dll/.so/.node` 等做 magic/size/sha256/entropy/printable strings 审计,
  规则 SEN-BIN-001/002/003、SEN-WASM-001

### 扫描目标模型

- **profile 插件发现重构**:direct deps → dsh.profile manifest → cordis patch →
  bundle 声明(回退);依赖图划分 direct-plugin / direct-dependency / transitive-dependency,
  传递依赖只做 metadata 审计(install/supplychain 规则),不再产生 SEN-MAN-002 误报
- **custom trustedScopes 生效**:`@my-company/foo` 等自定义 scope 正确跳过(trusted-scope)
- **test 文件降权升级**:被 main/exports/bin/patch 运行入口可达的 test 文件不再降权
  (reachability 预留);`computeRuntimeEntries()` 计算运行期入口集合

### 配置与输出一致性

- **sentinel.config.json 全部生效**:maxBytesPerFile / maxFindings / maxPlugins /
  ignore(glob,进入 report.ignored)/ includeBuildArtifacts / redactPaths / failOn(CLI 优先)/
  advisories;redactSecrets 永远开启(config false 被忽略并警告)
- **规则文档权重动态化**:generate-rules-doc.mjs 不再硬编码 critical(45),全部取自
  `SEVERITY_WEIGHT`(唯一来源)
- **audit JSON 输出修复**:CLI `--json` 输出 `{...report, audit}`(与 Harness Tool 一致),
  audit 元数据(verdict/sha256/integrity/dependencyCount/installScripts)不再丢失
- **report schema v2 补全**:scoreBasedOnAllFindings / ignored / hardSkipped /
  policySkips / coverageSkips / attackChains / supplyChain
- **CLI**:新增 `--fail-on-incomplete`(exit 3)、`--strict-exit-codes`、
  `--redact-paths`、`--max-bytes`;config 优先从目标目录检测

### 语义引擎审计

- taint source 名传播(flow 可解释:`args.command → exec`、`Buffer.from → eval`)
- 解码判定精确化:`Buffer.from` 仅 base64/hex 编码参数视为解码
- computed env(`process.env['OPEN'+'AI_API_KEY']`)、optional chaining(`cp?.exec?.`)
- SSRF 细化:云元数据端点 169.254.169.254 → critical
- prompt 投毒 confidence 分级(low 文档 / medium description / high description+隐藏副作用)
- capability mismatch 输出 evidence(declaredCapabilities / observedCapabilities)
- 新增 `net.connect` / `dgram.createSocket` 网络 sink

### 供应链安全

- **自包含安全 tar 解析**(engine/package/tar.js):拒绝 `../`、绝对路径、盘符、
  symlink/hardlink 条目;限制条目数 20000 / 解压 300MB / 单文件 50MB / 路径 1024 / 深度 32
- **integrity 不匹配** → SEN-SUPPLY-004 + 至少 REVIEW;解包被阻止 → SEN-SUPPLY-005 +
  BLOCK-RECOMMENDED + scanComplete=false;quarantine 任何路径 finally cleanup
- **lockfile 识别与统计**(package-lock/shrinkwrap/pnpm/yarn/bun)→ supplyChain 字段
- secret 形态扩展:github_pat_ / npm_ / AIza / Anthropic sk-ant- / PEM 私钥块脱敏
- 敏感文件扩展:.pypirc / .yarnrc / .env.local / .env.production / gcloud / Azure / kubeconfig
- persistence 最低限度:SEN-PERSIST-001(持久化机制)/ SEN-PERSIST-002(写 shell profile,high)

### CI 与生态

- **GitHub Action**:`.github/actions/dsh-sentinel/` 自包含 composite action
  (path/mode/fail-on/fail-on-incomplete/max-files/sarif-file 输入,exit-code/sarif-path 输出),
  acorn 已 vendored;示例 workflow `.github/workflows/sentinel.yml`(SARIF → Code Scanning)
- **SARIF 审计**:相对路径(不写盘符绝对路径)、稳定指纹、severity 映射、GitHub 兼容
- **benchmark 升级**:rule / finding(±2 行)/ flow(source→sink)三级指标
- **DSH pre-install 集成**:确认无官方 hook(不伪造),提供 `auditPackageBeforeInstall` API
  + CLI wrapper + 集成设计文档

### 测试与文档

- 测试 63 → 94 项(新增供应链安全 12 项 + v2 正确性 19 项)
- 新增 fixtures:bench 扩至 16 项(跨函数/SSRF/optional-chain/computed-env 等)
- 文档:新增 architecture.md / integration-github-action.md / integration-dsh-preinstall.md;
  更新 README / SECURITY / roadmap / rules.md / example-report.json

### Benchmark(16 项带标注语料)

```text
rule-level   precision 0.962 · recall 1.000 · F1 0.981
finding-level precision 0.941 · recall 1.000 · F1 0.970
flow-level   precision 1.000 · recall 1.000 · F1 1.000
```

## 0.2.0 (2026-08-19) — 专业版 Phase-1

- 扫描完整性:maxFindings 只限报告条数;scanComplete/filesDiscovered/filesAnalyzed 如实上报
- 三种扫描模式 source/package/profile;大文件 large-file-lite;路径 containment;入口契约严格化
- secret 脱敏;VERSION 单一来源;41 项测试

## 0.1.0 (2026-08-18)

- 首个 npm 发布:零依赖静态启发式扫描(执行/凭据/外传/混淆/安装脚本/文件系统/网络/manifest/hygiene)
- 双形态:DSH 工具插件 + 独立 CLI;测试上下文降权;43 仓库生态体检
