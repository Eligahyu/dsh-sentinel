# 生态扫描:DSh 插件体检快照

> 由 **dsh-sentinel** 对生态 Top 插件的公开源码做只读静态扫描(不执行任何被扫描代码)。
> 数据为一次快照,不代表插件安全性结论——命中只表示"需要人工复核"。

## 方法

- 语料来源:通过 jsDelivr CDN 抓取各仓库 `main`/`master` 分支的 `package.json`、`cordis.patch.yml`、入口与 README 等关键文件(网络受限环境下 raw.githubusercontent 不可达)
- **语料不完整**:每个仓库只抓取了部分文件,缺失文件会导致 manifest 类命中(MAN-00x)失真;部分入口文件为构建产物(git 仓库没有 `lib/`),也会产生假命中
- 复现:`node scripts/fetch-corpus.mjs && node scripts/scan-corpus.mjs`

## 结果一览(按风险分排序)

| 插件 | 裁决 | 分 | 命中 | manifest |
| --- | --- | --- | --- | --- |
| dsh-market(插件市场) | 🚨 dangerous | 100/100 | 12(src 12) | bundle |
| modlens(视觉) | ⚠️ risky | 64/100 | 8(src 8) | bundle |
| dsh-TUI(终端 UI) | ⚠️ risky | 56/100 | 7(src 7) | bundle |
| whale-girl(桌宠) | 👀 review | 48/100 | 6(src 6) | bundle |
| DSH-better-sidebar(侧边栏) | 👀 review | 44/100 | 4(src 4) | bundle |
| dsh-vision-toolkit(视觉) | 👀 review | 24/100 | 3(src 3) | bundle |
| dsh-web-ui(UI 合集) | 👀 review | 20/100 | 1(src 1) | 非 bundle |
| dsh-memory-evolve(记忆) | ✅ safe | 16/100 | 2(src 2) | bundle |
| dsh-ads(整活) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dsh-agent-teams(Agent 团队) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dsh-deep-whale(皮肤) | ✅ safe | 8/100 | 1(src 1) | 非 bundle |

## 主要命中明细

### dsh-vision-toolkit(视觉)

- 裁决:👀 review · 24/100
- 命中 3 条(source 3)
- 无 critical/high 级 source 命中

### dsh-TUI(终端 UI)

- 裁决:⚠️ risky · 56/100
- 命中 7 条(source 7)
- 无 critical/high 级 source 命中

### dsh-memory-evolve(记忆)

- 裁决:✅ safe · 16/100
- 命中 2 条(source 2)
- 无 critical/high 级 source 命中

### dsh-market(插件市场)

- 裁决:🚨 dangerous · 100/100
- 命中 12 条(source 12)
- critical/high 命中:
  - `SEN-MAN-006` dshmarket:1 — 插件入口无效(缺少 name 或 apply 导出):dshmarket

### modlens(视觉)

- 裁决:⚠️ risky · 64/100
- 命中 8 条(source 8)
- 无 critical/high 级 source 命中

### dsh-ads(整活)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### dsh-agent-teams(Agent 团队)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### DSH-better-sidebar(侧边栏)

- 裁决:👀 review · 44/100
- 命中 4 条(source 4)
- critical/high 命中:
  - `SEN-MAN-006` dsh-better-sidebar:1 — 插件入口无效(缺少 name 或 apply 导出):dsh-better-sidebar

### dsh-deep-whale(皮肤)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### whale-girl(桌宠)

- 裁决:👀 review · 48/100
- 命中 6 条(source 6)
- 无 critical/high 级 source 命中

### dsh-web-ui(UI 合集)

- 裁决:👀 review · 20/100
- 命中 1 条(source 1)
- critical/high 命中:
  - `SEN-MAN-002` package.json:1 — 不是 DSH bundle(缺少 dsh.bundle 声明)

## 说明与免责

- 启发式静态扫描 ≠ 安全保证;本表不构成对任何插件的指控或背书。
- 高风险的插件市场类(如 dsh-market)命中多为"能力型"网络调用(其自身 API 端点),属预期复核项。
- 部分 MAN-00x 命中来自语料不完整(见"方法"),请在完整仓库上复核。
