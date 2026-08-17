# awesome-dsh-plugin 收录提交包(待触发)

> 状态:**已自动入队**。`dsh-sentinel` 已带 `dsh-plugin` Topic + 中文简介,awesome-dsh-plugin 的每日
> `update-catalog` 工作流会自动把它抓进 `data/review/pending.md` 待审核队列(无需人工提交),
> 维护者核实后进入目录与榜单。
>
> **自荐展示位(SHOWCASE)需要 star > 10**(CI 自动核验,不达标即拒)。本文件是 star 达标后
> "即开即用"的提交包,按下面步骤执行即可。

## 前置检查(全部已满足)

- [x] 仓库公开:github.com/Eligahyu/dsh-sentinel
- [x] `dsh-plugin` Topic(已通过 gh api 设置)
- [x] GitHub 项目简介(已设置)
- [x] 真实可安装的 DSH bundle(声明了 `dsh.bundle` + `cordis.patch.yml`)
- [x] MIT 许可证
- [ ] star > 10(等待社区积累;或先发传播内容拉星)

## 步骤(star > 10 后执行)

```sh
# 1. 克隆 + 分支
gh repo clone bruc3van/awesome-dsh-plugin /tmp/awesome-dsh-plugin
cd /tmp/awesome-dsh-plugin
git checkout -b showcase-dsh-sentinel

# 2. 在 SHOWCASE.md 的「作者自荐」列表末尾追加一行(中文区):
#    [dsh-sentinel](https://github.com/Eligahyu/dsh-sentinel) — DSH 插件安全体检与健康检查:静态扫描代码执行/凭据/外传/混淆/安装脚本/bundle 清单,输出 0-100 风险分与裁决,双形态(DSH 工具 + 独立 CLI),零依赖只读。
#    在「Author showcase」列表末尾追加一行(英文区):
#    [dsh-sentinel](https://github.com/Eligahyu/dsh-sentinel) — Security & health scanner for DSH plugins: heuristic static audit (code execution, credentials, exfiltration, obfuscation, install scripts, bundle manifest) with a 0-100 risk score. DSH tool plugin + zero-dependency CLI.

# 3. 同步两个 README 首页的自荐预览区为列表末尾最近 10 条
#    (README.md 与 README_EN.md 的 showcase 预览块)

# 4. 本地自检
node scripts/validate-curated.mjs

# 5. 提交 + 开 PR
git add SHOWCASE.md README.md README_EN.md
git commit -m "showcase: add dsh-sentinel (plugin security scanner)"
git push -u origin showcase-dsh-sentinel
gh pr create --title "showcase: 推荐 dsh-sentinel 插件安全体检工具" --body "<见下>"
```

## PR 描述(自荐说明,必填)

```
自荐说明:deepseek-harness-sentinel(dsh-sentinel)解决 DSH 生态最缺的一环——
插件安全体检。生态有 4798+ 插件仓库,但几乎没有头部工具做供应链审计;插件本质是
"让 AI 以完整权限执行任意代码"。本项目以零依赖、只读的静态扫描(30+ 条启发式规则,
9 大类别)输出 0-100 风险分与 safe/review/risky/dangerous 四级裁决,可装进 Harness
当 Agent 工具(sentinel_scan / sentinel_scan_profile),也可作为独立 CLI 进 CI。
适合:任何想在安装第三方插件前先"拍一张 X 光"的 DSH 用户,以及想给插件打上
"通过体检"标签的作者。

Self-recommendation: deepseek-harness-sentinel fills the missing supply-chain
audit lane for the DSH ecosystem — a zero-dependency, read-only static scanner
(30+ heuristic rules, 9 categories) that scores plugin repos 0-100 with a
safe/review/risky/dangerous verdict. Ships as a DSH tool plugin and a standalone
CLI. For anyone who wants to X-ray a third-party plugin before installing it.
```

## 备注

- 不要提交生成文件(`CATALOG.md`/`TOP200.md`/`data/`),维护者合并时会重新生成。
- dsh-market 的收录自动跟随 awesome-dsh-plugin(市场目录即其注册表),无需单独提交。
- 若维护者先在待审核队列中收录,自荐条目被首页精选收录后会从自荐区移除,不占名额。
