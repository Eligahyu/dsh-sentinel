<div align="center">

# 🛡️ dsh-sentinel

**给 DeepSeek Harness 插件拍 X 光 · Plugin security & health scanner for DSH**

一个零依赖、只读的 DSH 插件安全体检中心:静态启发式扫描代码执行、凭据窃取、数据外传、混淆、安装脚本与 bundle 清单合规,输出 **0–100 风险分 + 裁决**,并给出每一条命中的修复建议。

既可以装进 DeepSeek Harness 当 **Agent 工具**(`sentinel_scan` / `sentinel_scan_profile`),也可以作为 **独立 CLI**(`npx dsh-sentinel`)在 CI 里使用。

```
Node ≥ 18.17 · 零运行时依赖 · 不执行被扫描代码 · MIT
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

## 功能

| 能力 | 说明 |
| --- | --- |
| 🔍 规则引擎 | 30+ 条启发式规则,12 大类别(含 agent/taint/supplychain,见 [规则目录](docs/rules.md)) |
| 🧠 语义引擎 | defineTool `execute(args)` 污点分析:`args.* → shell/文件/网络`(SEN-AGENT 系列),识别别名与跨变量传播 |
| 🎯 双重形态 | DSH 工具插件(`sentinel_scan` / `sentinel_scan_profile`)+ 独立 CLI |
| 📦 清单体检 | `dsh.bundle` / `cordis.patch.yml` / 入口契约(name+apply 必须同时存在)/ **路径 containment**(逃逸即 SEN-MAN-009) |
| 🧹 全量审计 | `sentinel_scan_profile` 以 **package mode** 扫描 profile 第三方插件(含 dist/build/lib 构建产物,内置包与扫描器自身自动排除) |
| 📊 量化裁决 | 0–100 风险分 + 四级裁决;**扫描完整性如实上报**(scanComplete / filesAnalyzed / findingsTruncated),不完整扫描绝不显示 clean |
| 📐 三种扫描模式 | `source`(默认,跳过构建产物)/ `package`(必扫 dist/build)/ `profile` |
| 🔒 只读安全 | 不执行被扫描代码、不跟随符号链接、manifest 路径防逃逸、大文件走 lite 分析不跳过 |
| 🕶️ 隐私保护 | 报告中的 **secret 一律脱敏**(只保留指纹,绝不二次泄露) |
| 🧪 自带验证 | 41 项自动化测试(positive/negative/evasion)+ 多套 fixture |

## 快速开始

### 方式一:装进 DSH(推荐)

```sh
# 本地目录安装
dsh plugin --profile web add ./dsh-sentinel

# 或从 GitHub 安装
dsh plugin --profile web add github:Eligahyu/dsh-sentinel

# npm 发布后(推荐,无需构建授权;npm 包名 deepseek-harness-sentinel,
# 因为 "dsh-sentinel" 在 npm 上已被占用):
dsh plugin --profile web add deepseek-harness-sentinel

dsh --profile web
```

然后在对话里直接说:

> "用 sentinel_scan 检查一下 `~/Downloads/some-plugin` 这个目录"
> "用 sentinel_scan_profile 审计一下我 web profile 里装的所有插件"

模型会调用工具并返回:

```
🚨 DANGEROUS (risk score 100/100)
scanned 3 files · 20 findings: critical 5 · high 9 · medium 4 · low 2 · info 0
manifest: evil-plugin@0.1.0 · isBundle=true · patch=./cordis.patch.yml
Top findings:
  [critical] SEN-EXFIL-001 plugin/index.js:22 — 可疑数据外传端点(webhook / pastebin / 隧道 / 监听服务)
  [critical] SEN-CRED-001 plugin/index.js:15 — 读取凭据文件(SSH 私钥 / AWS / npmrc / kubeconfig 等)
  ...
```

### 方式二:独立 CLI(不装 DSH 也能用)

```sh
# 不安装、直接跑(零依赖)
npx dsh-sentinel <插件目录>            # 或 node bin/sentinel.mjs <目录>

# CI 集成:exit 0 = safe/review,exit 1 = risky/dangerous
dsh-sentinel ./some-plugin --json --out report.json
dsh-sentinel --profile web            # 审计整个 profile 的第三方插件(package mode)
dsh-sentinel ./repo --mode package    # 扫描模式:source(默认)/package/profile
dsh-sentinel --rules                  # 打印规则目录
```

### 示例输出

```
✅ SAFE — risk score 0/100
─────────────────────────────────────────────
target        packages/bundle/web-app
manifest      @deepseek-ai/dsh-web-app@0.1.0-rc.5 · isBundle=true · patch=./cordis.patch.yml
files         28 scanned (0 binary skipped)
findings      0 total · CRITICAL 0 · HIGH 0 · MEDIUM 0 · low 0 · info 0
scan time     18 ms
```

上面的示例是对 **DeepSeek Harness 官方 `dsh-web-app` bundle 的真实扫描结果**;对恶意 fixture 的完整报告见 [docs/example-report.json](docs/example-report.json)。

## 评分与裁决

| 严重度 | 权重 | 示例 |
| --- | --- | --- |
| 🔴 critical | 50 | 远程代码下载执行、读取 SSH 私钥、外传端点、`rm -rf $HOME`、安装脚本含网络下载 |
| 🟠 high | 20 | `eval`、硬编码密钥、env 凭据读取、入口契约缺失 |
| 🟡 medium | 8 | shell 执行、网络调用、写入工作区外、安装生命周期脚本(需人工确认)、patch 解析问题 |
| 🟢 low | 3 | 编码载荷混用、硬编码公网 IP、缺 license/description |
| ⚪ info | 0 | 统计信息 |

总分封顶 100:**0–19 ✅ safe · 20–49 👀 review · 50–79 ⚠️ risky · 80–100 🚨 dangerous**——单条 critical(50 分)即达 risky,两条即 dangerous。

> 测试上下文:位于 `test/`、`tests/`、`__tests__/` 等目录或 `*.spec.*`、`*.test.*`、`*.e2e.*` 文件中的命中会打上 `(test)` 标记并**降一级计分**(测试 fixture 通常是故意构造的恶意字符串/二进制数据),但仍完整列出、不隐藏。
>
> 降噪设计:纯注释行不触发执行类规则(避免 JSDoc 里提到 `spawn()` 被误报);同一规则在同一文件的命中最多记 10 条(能力证明即可,避免刷屏);`chmod 0o600/0o700` 等严格权限是良好实践,只对宽松权限(777/666)告警;`prepare: npm run build` 这类 DSH 官方推荐的构建脚本按 medium 复核项处理。

完整规则目录(30+ 条,含检测模式说明)见 [docs/rules.md](docs/rules.md)。

## 工作方式

```
插件仓库/目录 ──► collectFiles(跳过 .git/node_modules/二进制/符号链接)
              ──► 逐文件跑 30+ 条启发式规则(行级 + 全文级正则)
              ──► inspectBundle:package.json + cordis.patch.yml 清单合规
              ──► 加权计分 → 裁决 → 结构化 JSON 报告
```

- 扫描器**只读**:不执行被扫描代码,因此可以放心扫描任何"可疑"插件;
- 报告是**结构化 JSON**,模型可以直接消费,也可以落盘进 CI;
- 规则全部集中在 [engine/rules.js](engine/rules.js),加规则只需加一个对象。

## 狗粮:扫描器扫描自己

```sh
node bin/sentinel.mjs engine
```

会命中 `SEN-FS-001`/`SEN-EXEC-003` 等——因为规则库文件本身含有 `rm -rf`、`eval(` 这些**规则字面量**。这是模式扫描的固有行为(自指误报),也是项目诚实性的体现:规则作者同样需要人工复核。

## 真实世界验证(官方语料)

用 DeepSeek Harness 官方仓库的 15 个包 + 示例组合做过一轮批量扫描,验证规则不失控:

| 语料 | 结果 |
| --- | --- |
| 官方 bundle(`base`/`headless`/`web-app`) | ✅ safe · 0 分 |
| 纯库包(`tool-todo`/`tool-bash`/`hooks` 等) | 👀 review · 仅"非 bundle"提示(正确) |
| 能力型工具包(`tool-fs-search`/`tool-web`/`llm-deepseek`) | 👀 review~risky · 命中均为正当"需复核"项(spawn ripgrep / fetch / 读 API key env) |
| 测试文件(`tests/*.e2e.ts` 等) | 全部正确打上 `(test)` 标记,不再扭曲评分 |

这轮狗粮还让扫描器自身修掉 3 个缺陷:**patch 指向包根时未解析 `main` 字段**、**入口契约不认 `export default { name, apply }` 对象**、**测试文件命中按原严重度计分导致误判**(现降一级计分)。

## Roadmap

- [ ] Web UI 报告可视化(HTML 报告 + 风险热力表)
- [ ] GitHub Action:`dsh-sentinel-action` 自动审计 PR 里的插件改动
- [ ] `dsh plugin add` 前置钩子:安装前自动扫描,`risky` 以上默认拦截
- [ ] 规则扩展:YAML/JSON 配置混淆、加密载荷检测、供应链指纹(已知恶意仓库 hash)
- [ ] 风险徽章服务:`![risk](https://api.dsh-sentinel.dev/badge/<repo>)`

详见 [docs/roadmap.md](docs/roadmap.md)。

## 开发

```sh
npm test            # 41 项测试(引擎 + CLI + 插件加载冒烟 + 专业版功能)
npm run docs:rules  # 从规则目录重新生成 docs/rules.md
npm run demo        # 生成 docs/example-report.json
npm run scan:self   # 扫描器扫自己(狗粮)
```

## 安装链路实测

`deepseek-harness-sentinel@0.1.0`(2026-08-18)在真实环境验证过完整链路:
`dsh plugin --profile <p> add deepseek-harness-sentinel`(npm 安装,1.3s)→
`--dump-config` 注入 `# == deepseek-harness-sentinel` bundle 层 →
loader 解析 `deepseek-harness-sentinel/plugin`(exports 映射)→
peer 依赖 `@deepseek-ai/dsh-tools` 经 `$DSH_HOME/profiles/node_modules` 扁平回退解析 →
`apply()` 成功注册 `sentinel_scan` / `sentinel_scan_profile`。

## 收录与传播

如果这个项目对你有用,欢迎:

1. ⭐ Star —— 生态需要更多人去关心插件安全;
2. 提 [Issue]/[PR] 补规则、修误报;
3. 帮我把它收录进 [awesome-dsh-plugin](https://github.com/bruc3van/awesome-dsh-plugin)(提交 CONTRIBUTING 作者自荐)、[dsh-market](https://github.com/dsh-market/dsh-market) 等市场。

## License

[MIT](LICENSE) © dsh-sentinel contributors

---

## English Summary

**dsh-sentinel** is a dependency-free, read-only security & health scanner for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH) plugins. The DSH ecosystem has ~4,800 plugin repos but almost no tooling to audit them — plugins run arbitrary code with your full permissions, so supply-chain hygiene matters.

- **Two forms**: a DSH tool plugin (`sentinel_scan`, `sentinel_scan_profile`) and a standalone CLI (`npx dsh-sentinel`) with CI-friendly exit codes.
- **Heuristic engine**: 30+ rules across execution, credentials, exfiltration, obfuscation, install scripts, filesystem, network, manifest compliance and hygiene → weighted 0–100 risk score with `safe / review / risky / dangerous` verdict.
- **Manifest checks**: validates `dsh.bundle`, `cordis.patch.yml` rows and the plugin entry contract (`name`/`apply` exports) against the real loader semantics.
- **Profile audit**: scans every third-party plugin installed in a profile (`$DSH_HOME/profiles/<name>/node_modules`), skipping trusted `@deepseek-ai/*` built-ins and tagging findings per package.
- **Safe by design**: never executes scanned code, skips symlinks/binaries, zero runtime dependencies, Node ≥ 18.17.

```sh
# standalone
npx dsh-sentinel <plugin-dir> [--json] [--out report.json]
# as a DSH plugin
dsh plugin --profile web add ./dsh-sentinel
```

> Disclaimer: heuristic static analysis is not a security guarantee. Findings mean "review this", not "this is malicious".

[Rule catalog](docs/rules.md) · [Example report](docs/example-report.json) · MIT License
