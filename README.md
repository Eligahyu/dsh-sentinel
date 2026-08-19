<div align="center">

# 🛡️ dsh-sentinel

**给 DeepSeek Harness 插件拍 X 光 · Plugin security & health scanner for DSH**

一个只读的 DSH 插件供应链 + Agent Tool 静态安全审计器:静态启发式扫描代码执行、凭据窃取、数据外传、混淆、安装脚本、原生二进制、供应链风险与 bundle 清单合规,输出 **0–100 风险分 + 裁决**,并给出每一条命中的修复建议。

既可以装进 DeepSeek Harness 当 **Agent 工具**(`sentinel_scan` / `sentinel_scan_profile` / `sentinel_audit_package`),也可以作为 **独立 CLI**(`npx dsh-sentinel`)在 CI 里使用,并输出 **SARIF 2.1.0** 对接 GitHub Code Scanning。

```
Node ≥ 18.17 · 只读静态分析 · 绝不执行被扫描代码 · 安装前隔离审计 · MIT
```

</div>

---

## 为什么做这个

DeepSeek Harness 插件生态在爆发:截至 2026-08,仅 [awesome-dsh-plugin](https://github.com/bruc3van/awesome-dsh-plugin) 就收录了 **4798** 个经核实的插件仓库——其中 **253** 个被维护者拉黑或剔除。而插件本质上等于"**让你的 AI 在完整权限下执行任意代码**"(安装脚本甚至绕过沙箱直接运行),供应链风险是生态最大的隐忧。

但环顾生态:**4798 个插件,几乎没有头部做"插件的安全体检"**。本项目的目标就是填补这个空白:

- **对用户**:装任何第三方插件前,先给它拍一张 X 光;
- **对作者**:发布插件前自检一遍,让"通过了 dsh-sentinel"成为质量与可信的标签。

> ⚠️ 免责声明:启发式静态扫描 ≠ 安全保证。命中只表示"需要人工复核",未命中不代表绝对安全。**绝不要因为一份"safe"报告就盲目信任插件。**

---

## 必须明确的四件事

1. **SARIF 是报告交换格式,不是检测引擎**——真正检测能力来自 engine;
2. **GitHub Action 是自动化执行层,不是新算法**——它只是运行 CLI 并上传结果;
3. **audit-install 不执行 npm install**——只下载 tarball、隔离解包、静态扫描、删除;
4. **scan verdict 不是恶意判定**——只有 `safe/review/risky/dangerous` 与
   `ALLOW/REVIEW/BLOCK-RECOMMENDED` 建议,决策权永远留给用户。

## 功能

| 能力 | 说明 |
| --- | --- |
| 🔍 规则引擎 | 51 条启发式规则,14 大类别(含 agent/taint/supplychain/binary/persistence,见 [规则目录](docs/rules.md)) |
| 🧠 语义引擎 | defineTool `execute(args)` 污点分析:`args.* → shell/文件/网络`(SEN-AGENT 系列),别名/跨变量/跨函数传播/计算属性/optional chaining;env 凭据 → 网络、文件 → 网络、解码 → 执行(SEN-TAINT 系列,confidence high) |
| 🎯 双重形态 | DSH 工具插件(`sentinel_scan` / `sentinel_scan_profile` / `sentinel_audit_package`)+ 独立 CLI |
| 📦 清单体检 | `dsh.bundle` / `cordis.patch.yml` / 入口契约(name+apply 必须同时存在)/ **路径 containment**(词法 + realpath + symlink 防护,逃逸即 SEN-MAN-009) |
| 🧹 全量审计 | `sentinel_scan_profile` 以 **package mode** 扫描 profile 第三方插件;插件发现基于 direct deps / dsh.profile manifest / cordis patch / bundle 声明,传递依赖只做 metadata 审计(不产生 SEN-MAN-002 误报) |
| 📊 量化裁决 | 0–100 风险分 + 四级裁决;**评分基于全部有效命中**(scoreBasedOnAllFindings),critical/high 即使出现在 maxFindings 截断之后也不丢失;**扫描完整性如实上报**(scanComplete / hardSkippedFiles / filesSkipped),不完整扫描绝不显示 clean |
| 📐 三种扫描模式 | `source`(默认,跳过构建产物)/ `package`(必扫 dist/build)/ `profile` |
| 📦 安装前审计 | `audit-install <pkg>`:tarball → quarantine → **安全解包**(防 traversal/symlink/tar bomb)→ 静态扫描 → 删除;sha512 integrity 校验;ALLOW/REVIEW/BLOCK-RECOMMENDED |
| 🧬 原生二进制 | .wasm/.exe/.dll/.so/.node 等 metadata 审计:magic / size / sha256 / entropy / printable strings(SEN-BIN-001/002/003、SEN-WASM-001) |
| 🔒 只读安全 | 不执行被扫描代码、不跟随符号链接、manifest 路径防逃逸、大文件走 lite 分析不跳过、超过 20MB 记录 metadata 并标记不完整 |
| 🕶️ 隐私保护 | 报告中的 **secret 一律脱敏**(永远开启,只保留指纹);`--redact-paths` 匿名化绝对路径;所有 ignore/skip 全部进入报告,绝不静默 |
| 🧪 自带验证 | 94 项自动化测试(positive/negative/evasion)+ 三级 benchmark(rule / finding±2 行 / flow source→sink) |
| 🚀 CI 集成 | `--format sarif`(2.1.0,相对路径 + 稳定指纹)、`--fail-on`、`--fail-on-incomplete`(exit 3)、`--strict-exit-codes`、自包含 [GitHub Action](.github/actions/dsh-sentinel/) |

## 快速开始

### 方式一:装进 DSH(推荐)

```sh
# 本地目录安装
dsh plugin --profile web add ./dsh-sentinel

# 或从 GitHub 安装
dsh plugin --profile web add github:Eligahyu/dsh-sentinel-scanner

# npm 发布后(推荐;npm 包名 deepseek-harness-sentinel,
# 因为 "dsh-sentinel" 在 npm 上已被占用):
dsh plugin --profile web add deepseek-harness-sentinel

dsh --profile web
```

然后在对话里直接说:

> "用 sentinel_scan 检查一下 `~/Downloads/some-plugin` 这个目录"
> "用 sentinel_scan_profile 审计一下我 web profile 里装的所有插件"
> "用 sentinel_audit_package 在安装前审计 `some-plugin@1.2.3`"

### 方式二:独立 CLI(不装 DSH 也能用)

```sh
# 不安装、直接跑
node bin/sentinel.mjs <插件目录>            # 或 npx dsh-sentinel <目录>

# 安装前审计(隔离、不执行任何脚本)
node bin/sentinel.mjs audit-install some-plugin@1.2.3

# CI 集成:exit 0 = safe/review,exit 1 = risky/dangerous / fail-on 超阈值
node bin/sentinel.mjs ./some-plugin --json --out report.json
node bin/sentinel.mjs ./repo --mode package --format sarif --out sentinel.sarif
node bin/sentinel.mjs ./repo --fail-on high --fail-on-incomplete
node bin/sentinel.mjs --profile web            # 审计整个 profile 的第三方插件
node bin/sentinel.mjs --rules                  # 打印规则目录
```

### GitHub Action

```yaml
- uses: Eligahyu/dsh-sentinel-scanner@v1
  with:
    path: .
    mode: source
    fail-on: high
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel.sarif
```

详见 [docs/integration-github-action.md](docs/integration-github-action.md)。

### 示例输出

```
✅ SAFE — risk score 0/100
─────────────────────────────────────────────
target        packages/bundle/web-app
manifest      @deepseek-ai/dsh-web-app@0.1.0-rc.5 · isBundle=true · patch=./cordis.patch.yml
files         28/28 analyzed (0 build · 0 large-lite · 0 binary · 0 hard-skipped)
findings      0 total(返回 0) · CRITICAL 0 · HIGH 0 · MEDIUM 0 · low 0 · info 0
context       source 0 · test 0 (test 文件命中降一级计分,除非被运行入口可达)
scoring       score 基于全部 0 条有效命中(scoreBasedOnAllFindings)
scan time     18 ms

当前启用规则未发现问题;这不等价于插件已被证明安全。
No findings detected by enabled rules; this does not prove the plugin is safe.
```

对恶意 fixture 的完整报告见 [docs/example-report.json](docs/example-report.json)。

## 评分与裁决

| 严重度 | 权重 | 示例 |
| --- | --- | --- |
| 🔴 critical | 50 | 远程代码下载执行、读取 SSH 私钥、外传端点、`rm -rf $HOME`、安装脚本含网络下载、tar 路径逃逸 |
| 🟠 high | 20 | `eval`、硬编码密钥、env 凭据读取、入口契约缺失、二进制内可疑字符串 |
| 🟡 medium | 8 | shell 执行、网络调用、安装生命周期脚本(需人工确认)、高熵二进制、持久化机制 |
| 🟢 low | 3 | 编码载荷混用、硬编码公网 IP、缺 license/description |
| ⚪ info | 0 | 原生二进制存在、WASM 模块 |

总分封顶 100:**0–19 ✅ safe · 20–49 👀 review · 50–79 ⚠️ risky · 80–100 🚨 dangerous**——单条 critical(50 分)即达 risky,两条即 dangerous。

> **评分与展示分离**:分数基于**全部有效命中**(即使报告只展示 maxFindings 条),
> critical/high 命中即使出现在截断之后也不会丢失计分——攻击者无法靠"淹没式低危命中"稀释风险分。
>
> **minified/bundle 不自动降级**:压缩产物只作为 evidence(`bundleFile` 标记),
> 绝不改变 severity;置信度由检测方式决定(regex-only → medium,AST/taint → high)。
>
> 测试上下文:位于 `test/`、`tests/`、`__tests__/` 等目录的命中打 `(test)` 标记并**降一级计分**;
> 但被 `main/exports/bin/patch` 运行入口可达的 test 文件**不降权**(防止攻击者把恶意代码藏在"测试文件"里)。
>
> 降噪设计:纯注释行不触发执行类规则;同一规则在同一文件最多记 10 条(计数不丢);`chmod 0o600/0o700` 等严格权限不告警;`prepare: npm run build` 按 medium 复核项处理。

完整规则目录(51 条,含检测模式说明)见 [docs/rules.md](docs/rules.md)。

## 工作方式

```
插件仓库/目录 ──► collectFiles(模式感知跳过 / ignore glob / 大文件 / 二进制 / hardMax 分类)
              ──► 逐文件:51 条启发式规则(行级 + 全文级正则)+ AST 污点深扫
              ──► 可执行二进制 metadata 审计(magic/entropy/strings)
              ──► inspectBundle:package.json + cordis.patch.yml 清单合规
              ──► 全量统计 → 加权计分(基于全部命中)→ 裁决 → 结构化 JSON / SARIF / HTML
```

- 扫描器**只读**:不执行被扫描代码,因此可以放心扫描任何"可疑"插件;
- 报告是**结构化 JSON**,模型可以直接消费,也可以落盘进 CI;
- 规则全部集中在 [engine/rules.js](engine/rules.js),加规则只需加一个对象。

架构与不变式详见 [docs/architecture.md](docs/architecture.md)。

## 安装前审计(不执行任何脚本)

```sh
node bin/sentinel.mjs audit-install some-plugin@1.2.3
# 或
node bin/sentinel.mjs npm:some-plugin@1.2.3
```

流程:`npm metadata → tarball → quarantine 临时目录 → 安全解包(防 ../、绝对路径、
盘符、symlink/hardlink、tar bomb)→ 静态扫描 → 删除 quarantine`。
**绝不执行** `npm install / preinstall / install / postinstall / prepare`。
输出 `ALLOW / REVIEW / BLOCK-RECOMMENDED` 建议与 sha256/integrity/依赖数/安装脚本清单。

与 DSH `dsh plugin add` 的前置审计集成设计见 [docs/integration-dsh-preinstall.md](docs/integration-dsh-preinstall.md)。

## 狗粮:扫描器扫描自己

```sh
node bin/sentinel.mjs engine
```

会命中 `SEN-FS-001`/`SEN-EXEC-003` 等——因为规则库文件本身含有 `rm -rf`、`eval(` 这些**规则字面量**。这是模式扫描的固有行为(自指误报),也是项目诚实性的体现:规则作者同样需要人工复核。

## 基准(三级 benchmark)

```sh
npm run benchmark
```

rule-level(期望规则 ID 集合)+ finding-level(期望 `{id, line}`,±2 行容忍)
+ flow-level(期望 `{id, source, sink}` 链),当前 16 项带标注语料:

```text
rule-level   precision 0.962 · recall 1.000 · F1 0.981
finding-level precision 0.941 · recall 1.000 · F1 0.970
flow-level   precision 1.000 · recall 1.000 · F1 1.000
```

目标门槛:precision ≥ 0.90、recall ≥ 0.85;Harness critical 规则 recall ≥ 0.95。

## Roadmap

- [x] v0.2:扫描完整性 / 三种模式 / 路径 containment / secret 脱敏
- [x] v0.3:AST/taint、Harness 专属规则、SARIF/fingerprint/baseline、安装前审计、benchmark
- [x] v0.3.1(第二轮):评分-展示解耦、bundle 不降级、binary 审计、safe tar、GitHub Action、DSH 前置审计接口
- [x] v0.4.0(本轮):发布加固——完整度失败显式化、资源上限、IPv6/DNS SSRF、凭据专属豁免、bare sink 绑定、multiple taints、semantic evidence、fingerprint 闭环、Node ≥22.18 基线
- [ ] v0.5:lockfile 依赖图深化、跨文件 taint、reachability 图
- [ ] v0.5:GitHub Action 独立仓库发布、DSH 官方 hook 对接(如官方提供)
- [ ] v1.0:稳定语义引擎、公开基准、文档化限制

详见 [docs/roadmap.md](docs/roadmap.md)。

## 开发

```sh
npm test            # 94 项测试(引擎 + CLI + 插件加载 + 供应链 + v2 正确性)
npm run benchmark   # 三级 benchmark(rule/finding/flow)
npm run docs:rules  # 从规则目录重新生成 docs/rules.md(权重动态取自 SEVERITY_WEIGHT)
npm run demo        # 生成 docs/example-report.json
npm run scan:self   # 扫描器扫自己(狗粮)
```

## 收录与传播

如果这个项目对你有用,欢迎:

1. ⭐ Star —— 生态需要更多人去关心插件安全;
2. 提 [Issue]/[PR] 补规则、修误报;
3. 帮我把它收录进 [awesome-dsh-plugin](https://github.com/bruc3van/awesome-dsh-plugin)(提交 CONTRIBUTING 作者自荐)、[dsh-market](https://github.com/dsh-market/dsh-market) 等市场。

## License

[MIT](LICENSE) © dsh-sentinel contributors

---

## English Summary

**dsh-sentinel** is a read-only security & supply-chain scanner for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH) plugins — heuristic static audit plus an AST taint engine for Harness Agent Tools, pre-install tarball quarantine audit (never executes `npm install` or lifecycle scripts), binary metadata audit, SARIF 2.1.0 output and a self-contained GitHub Action.

- **Two forms**: a DSH tool plugin (`sentinel_scan`, `sentinel_scan_profile`, `sentinel_audit_package`) and a standalone CLI with CI-friendly exit codes (0/1/2/3).
- **Heuristic engine**: 51 rules across execution, credentials, exfiltration, obfuscation, install scripts, filesystem, network, manifest, agent, taint, supply-chain, binary and persistence → weighted 0–100 risk score with `safe / review / risky / dangerous` verdict.
- **Scoring is decoupled from display**: score is computed from ALL findings (`scoreBasedOnAllFindings`); the report shows at most `maxFindings` entries, but critical/high findings are never dropped by the cap (priority-bounded buffer).
- **Minified/bundle content is evidence, not a severity downgrade**: `bundleFile` tags only; confidence comes from the detection method (regex → medium, AST/taint → high).
- **Pre-install audit**: tarball → quarantine → safe extraction (blocks `../`, absolute paths, drive letters, symlink/hardlink entries and tar bombs) → static scan → cleanup; sha512 integrity verification; `ALLOW / REVIEW / BLOCK-RECOMMENDED`.
- **Profile audit**: discovers real DSH plugins via direct deps / profile manifest / cordis patch / bundle declarations; transitive dependencies get metadata-only audit (no `SEN-MAN-002` false positives).
- **Safe by design**: never executes scanned code, skips symlinks, path containment (lexical + realpath + symlink), secrets always redacted, all skips visible in the report.

```sh
# standalone
npx dsh-sentinel <plugin-dir> [--json] [--out report.json] [--format sarif]
# pre-install audit
npx dsh-sentinel audit-install <pkg>[@ver]
# as a DSH plugin
dsh plugin --profile web add ./dsh-sentinel
```

> Disclaimer: heuristic static analysis is not a security guarantee. Findings mean "review this", not "this is malicious". SARIF/GitHub Action/HTML are result standardization and automation layers — the detection capability lives in the engine.

[Rule catalog](docs/rules.md) · [Architecture](docs/architecture.md) · [GitHub Action](docs/integration-github-action.md) · [Example report](docs/example-report.json) · MIT License
