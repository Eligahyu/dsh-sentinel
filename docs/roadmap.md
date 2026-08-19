# Roadmap / 发布清单

## 🚀 发布 Checklist(拿到第一批 star 的路径)

### 1. 创建 GitHub 仓库 ✅
- [x] 仓库 `dsh-sentinel` 已建并推送:github.com/Eligahyu/dsh-sentinel
- [x] Topics:`dsh-plugin`、`deepseek-harness`、`security`、`scanner`、`supply-chain-security`、`static-analysis`
- [x] 中文简介已设置
- [ ] SECURITY.md(补上)

### 2. 上架插件目录
- [x] **自动入队**:`dsh-plugin` Topic + 简介已满足,awesome-dsh-plugin 每日工作流会自动抓进待审核队列
- [x] 自荐提交包已备好:`docs/submission-awesome.md`(SHOWCASE 行、PR 标题/描述、步骤)
- [ ] **自荐展示位:等 star > 10** 后按提交包执行(CI 自动核验 star 数)
- [x] dsh-market:目录即 awesome-dsh-plugin 注册表,自动跟随,无需单独提交

### 3. npm 发布 ✅(2026-08-18)
- [x] 包名定为 **`deepseek-harness-sentinel`**(`dsh-sentinel` 在 npm 已被占用),patch/README 已同步
- [x] `npm pack --dry-run` 验证通过:11 文件 / 28.4 kB,内容正确
- [x] **v0.1.0 已发布**:`npm view deepseek-harness-sentinel` 线上可见;全局安装 + CLI 冒烟测试通过
- [x] 发布方式:浏览器交互 2FA 挑战(npm 2026-07-31 新政禁掉 bypass-2FA 令牌,发布必须走 EOTP 浏览器认证)
- [ ] 配置 Trusted Publishing(OIDC):包设置页 → Trusted Publisher → `Eligahyu/dsh-sentinel` / `publish.yml` → 之后打 tag 自动发布
- [ ] 撤销对话中暴露的 5 个令牌

### 4. 中文社区传播
- [x] 生态体检素材已生成:`docs/ecosystem-scan.md`(11 个 Top 插件扫描快照)
- [ ] 掘金/知乎/公众号文章 + 演示动图(待发布后写)

### 5. 持续运营
- [ ] 每周合并误报修复 PR(安全工具的口碑 = 误报率)
- [ ] 推出 GitHub Action(`dsh-sentinel-action`),让"PR 自动审计插件改动"成为生态默认姿势
- [ ] 调研 awesome-dsh-plugin 的 `data/repositories.json`,批量扫描 Top 200 生成公开排行榜(天然传播素材 + 数据新闻点)

## 🧭 版本规划

### v0.2 ✅(2026-08-19,按专业版升级任务书 Phase-1 完成)
- [x] 扫描完整性:maxFindings 不再提前停扫,findingsTotal/findingsReturned/scanComplete 如实上报;不完整扫描强制 review + INCOMPLETE 标记
- [x] 三种扫描模式 source/package/profile;package/profile 模式必扫 dist/build/lib/out;profile 扫描自动排除扫描器自身
- [x] 大文件策略:512KB–20MB 走 large-file-lite 分析(复用规则子集 + hash + analysisMode 标记),不再简单跳过
- [x] 路径 containment:`engine/path-safety.js`,manifest 全部路径(patch/main/exports/入口名)防逃逸,SEN-MAN-009
- [x] 入口契约严格化:name 与 apply 必须同时存在(ESM/default 对象/CJS 三形态)
- [x] secret 脱敏:`engine/redact.js`,报告只保留指纹,CLI/JSON 均无完整 secret
- [x] VERSION 单一来源 `engine/version.js`;schemaVersion 2
- [x] 语义引擎骨架 `engine/semantic`:defineTool execute(args) 污点分析(SEN-AGENT-001/002/003/004),含别名与多步传播(confidence: medium,待 AST 升级)
- [x] 压缩产物降权:minified bundle 命中打标并降一级计分(转译器噪声)
- [x] SECURITY.md、41 项测试(positive/negative/evasion)

### v0.3 ✅(2026-08-19,Phase 2–8 全部完成)
- [x] **Phase 2 扫描目标模型**:sentinel.config.json;profile 依赖图(direct/transitive);内置包信任策略 + `--include-builtins`
- [x] **Phase 3 安装前扫描**:npm tarball 隔离获取/完整性校验/不执行脚本;`audit-install` / `npm:<pkg>` / `sentinel_audit_package`;ALLOW/REVIEW/BLOCK-RECOMMENDED
- [x] **Phase 4 AST**:acorn 解析;调用识别/计算属性(`cp['ex'+'ec']`)/别名;confidence high
- [x] **Phase 5 Taint**:SEN-TAINT-001(secret→network)/002(workspace→network)/003(decode→exec);跨函数传播;受信端点豁免
- [x] **Phase 6 Harness 专属**:SEN-AGENT-005(prompt 投毒)/006(能力不匹配);SSRF 目标细化;containment 提示;记忆/对话外传
- [x] **Phase 7 CI**:稳定 fingerprint;SARIF 2.1.0;baseline 对比;`--fail-on` 阈值退出码
- [x] **Phase 8 生态**:OSV(`--advisories`,默认关,仅上传包名+版本);provenance(`--provenance`);源码↔发布包 diff(`dsh-sentinel diff`,`SEN-SUPPLY-003`);HTML 报告;benchmark(precision/recall)
- [x] Benchmark 结果:**precision 1.000 · recall 1.000 · F1 1.000**(11 项带标注语料)
- [ ] 已知恶意模式指纹库(需要外部威胁情报源,未实现——作为后续项)

### v1.0
- 规则插件化(第三方规则包)
- GitHub Action(`dsh-sentinel-action`)+ 徽章服务
- 多生态支持(pi / Claude Code 插件扫描)

## 🎯 定位红线(决定不做的事)

- ❌ 不做"自动判定恶意"的一票否决——只做证据与建议,决策权留给用户
- ❌ 不联网收集被扫描代码(隐私),离线纯本地
- ❌ 不执行被扫描代码(动态沙箱是另一个项目的事)
