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
| ax-feishu-bridge(飞书桥) | ⚠️ risky | 60/100 | 6(src 6) | bundle |
| dsh-TUI(终端 UI) | ⚠️ risky | 56/100 | 7(src 7) | bundle |
| dsh-market(插件市场) | 👀 review | 44/100 | 4(src 4) | bundle |
| DSH-better-sidebar(侧边栏) | 👀 review | 44/100 | 4(src 4) | bundle |
| dsh-interconnect(跨实例转发) | 👀 review | 40/100 | 2(src 2) | bundle |
| lhh010__dsh-minigames | 👀 review | 40/100 | 5(src 5) | bundle |
| dsh-qqbot(腾讯官方 QQ Bot) | 👀 review | 40/100 | 2(src 2) | bundle |
| whale-girl(桌宠) | 👀 review | 40/100 | 5(src 5) | bundle |
| deepseek-harness-studio(零代码桌面端) | 👀 review | 31/100 | 3(src 3) | 非 bundle |
| dsh-custom-tool(自定义工具) | 👀 review | 28/100 | 2(src 2) | bundle |
| dsh-lark(飞书通道) | 👀 review | 28/100 | 2(src 2) | bundle |
| deepseek-harness-desktop(Tauri 桌面端) | 👀 review | 23/100 | 2(src 2) | 非 bundle |
| working-activity(活动行) | 👀 review | 20/100 | 1(src 1) | 非 bundle |
| dsh-kun-like-pet(坤坤桌宠) | 👀 review | 20/100 | 1(src 1) | 非 bundle |
| DSH-Transparent-UI(玻璃质感皮肤) | 👀 review | 20/100 | 1(src 1) | 非 bundle |
| dsh-web-ui(UI 合集) | 👀 review | 20/100 | 1(src 1) | 非 bundle |
| dsh-memory-evolve(记忆) | ✅ safe | 16/100 | 2(src 2) | bundle |
| dsh-remote(SSH 反向隧道) | ✅ safe | 16/100 | 2(src 2) | bundle |
| modlens(视觉) | ✅ safe | 16/100 | 2(src 2) | bundle |
| dsh-vision-toolkit(视觉) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dsh-harness-mcp-server(MCP 服务) | ✅ safe | 8/100 | 1(src 1) | 非 bundle |
| deepseek-harness-skin(换肤系统) | ✅ safe | 8/100 | 1(src 1) | 非 bundle |
| hellodigua__dsh-emoji | ✅ safe | 8/100 | 1(src 1) | bundle |
| distill(对话蒸馏) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dsh-ads(整活) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dsh-agent-teams(Agent 团队) | ✅ safe | 8/100 | 1(src 1) | bundle |
| oil-oil/dsh-vision(视觉) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dsh-at-file(@ 文件引用) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dsh-mnemon(Mnemon 记忆) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dsh-pet(桌宠) | ✅ safe | 8/100 | 1(src 1) | 非 bundle |
| dsh-deep-whale(皮肤) | ✅ safe | 8/100 | 1(src 1) | 非 bundle |
| dsh-notifier(8 渠道通知网关) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dsh-automation(定时任务) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dshcode(Electron 桌面端) | ✅ safe | 8/100 | 1(src 1) | 非 bundle |
| dsh-noema(长期记忆) | ✅ safe | 8/100 | 1(src 1) | bundle |
| dsh-toolkit(确定性工具集) | ✅ safe | 0/100 | 0(src 0) | bundle |
| dsh-im(8 渠道 IM 桥) | ✅ safe | 0/100 | 0(src 0) | bundle |
| dsh-vision-router(视觉路由) | ✅ safe | 0/100 | 0(src 0) | bundle |
| dsh-im-gateway(IM 聚合网关) | ✅ safe | 0/100 | 0(src 0) | bundle |

## 主要命中明细

### dsh-vision-toolkit(视觉)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### ax-feishu-bridge(飞书桥)

- 裁决:⚠️ risky · 60/100
- 命中 6 条(source 6)
- critical/high 命中:
  - `SEN-MAN-006` ax-feishu-bridge\harness:1 — 插件入口无效(缺少 name 或 apply 导出):ax-feishu-bridge/harness

### dsh-TUI(终端 UI)

- 裁决:⚠️ risky · 56/100
- 命中 7 条(source 7)
- 无 critical/high 级 source 命中

### working-activity(活动行)

- 裁决:👀 review · 20/100
- 命中 1 条(source 1)
- critical/high 命中:
  - `SEN-MAN-002` package.json:1 — 不是 DSH bundle(缺少 dsh.bundle 声明)

### dsh-interconnect(跨实例转发)

- 裁决:👀 review · 40/100
- 命中 2 条(source 2)
- critical/high 命中:
  - `SEN-MAN-006` dsh-interconnect\interconnect:1 — 插件入口无效(缺少 name 或 apply 导出):dsh-interconnect/interconnect
  - `SEN-MAN-006` dsh-interconnect\tool-interconnect:1 — 插件入口无效(缺少 name 或 apply 导出):dsh-interconnect/tool-interconnect

### dsh-harness-mcp-server(MCP 服务)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### dsh-memory-evolve(记忆)

- 裁决:✅ safe · 16/100
- 命中 2 条(source 2)
- 无 critical/high 级 source 命中

### dsh-market(插件市场)

- 裁决:👀 review · 44/100
- 命中 4 条(source 4)
- critical/high 命中:
  - `SEN-MAN-006` dshmarket:1 — 插件入口无效(缺少 name 或 apply 导出):dshmarket

### dsh-remote(SSH 反向隧道)

- 裁决:✅ safe · 16/100
- 命中 2 条(source 2)
- 无 critical/high 级 source 命中

### deepseek-harness-studio(零代码桌面端)

- 裁决:👀 review · 31/100
- 命中 3 条(source 3)
- critical/high 命中:
  - `SEN-MAN-002` package.json:1 — 不是 DSH bundle(缺少 dsh.bundle 声明)

### deepseek-harness-desktop(Tauri 桌面端)

- 裁决:👀 review · 23/100
- 命中 2 条(source 2)
- critical/high 命中:
  - `SEN-MAN-002` package.json:1 — 不是 DSH bundle(缺少 dsh.bundle 声明)

### deepseek-harness-skin(换肤系统)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### hellodigua__dsh-emoji

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### lhh010__dsh-minigames

- 裁决:👀 review · 40/100
- 命中 5 条(source 5)
- 无 critical/high 级 source 命中

### modlens(视觉)

- 裁决:✅ safe · 16/100
- 命中 2 条(source 2)
- 无 critical/high 级 source 命中

### dsh-kun-like-pet(坤坤桌宠)

- 裁决:👀 review · 20/100
- 命中 1 条(source 1)
- critical/high 命中:
  - `SEN-MAN-002` package.json:1 — 不是 DSH bundle(缺少 dsh.bundle 声明)

### distill(对话蒸馏)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### dsh-ads(整活)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### dsh-agent-teams(Agent 团队)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### oil-oil/dsh-vision(视觉)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### dsh-at-file(@ 文件引用)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### DSH-better-sidebar(侧边栏)

- 裁决:👀 review · 44/100
- 命中 4 条(source 4)
- critical/high 命中:
  - `SEN-MAN-006` dsh-better-sidebar:1 — 插件入口无效(缺少 name 或 apply 导出):dsh-better-sidebar

### dsh-custom-tool(自定义工具)

- 裁决:👀 review · 28/100
- 命中 2 条(source 2)
- critical/high 命中:
  - `SEN-EXEC-003` lib__index.js:587 — 动态代码执行(eval / Function / vm / 编译钩子)

### dsh-lark(飞书通道)

- 裁决:👀 review · 28/100
- 命中 2 条(source 2)
- critical/high 命中:
  - `SEN-MAN-006` dsh-lark-channel:1 — 插件入口无效(缺少 name 或 apply 导出):dsh-lark-channel

### dsh-mnemon(Mnemon 记忆)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### dsh-toolkit(确定性工具集)

- 裁决:✅ safe · 0/100
- 命中 0 条(source 0)
- 无 critical/high 级 source 命中

### dsh-pet(桌宠)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### dsh-deep-whale(皮肤)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### dsh-qqbot(腾讯官方 QQ Bot)

- 裁决:👀 review · 40/100
- 命中 2 条(source 2)
- critical/high 命中:
  - `SEN-MAN-006` @tencent-connect\dsh-qqbot:1 — 插件入口无效(缺少 name 或 apply 导出):@tencent-connect/dsh-qqbot
  - `SEN-CRED-002` src\index.ts:44 — 读取环境变量中的凭据(API key / token / secret)

### dsh-notifier(8 渠道通知网关)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### dsh-automation(定时任务)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### whale-girl(桌宠)

- 裁决:👀 review · 40/100
- 命中 5 条(source 5)
- 无 critical/high 级 source 命中

### dshcode(Electron 桌面端)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

### DSH-Transparent-UI(玻璃质感皮肤)

- 裁决:👀 review · 20/100
- 命中 1 条(source 1)
- critical/high 命中:
  - `SEN-MAN-002` package.json:1 — 不是 DSH bundle(缺少 dsh.bundle 声明)

### dsh-im(8 渠道 IM 桥)

- 裁决:✅ safe · 0/100
- 命中 0 条(source 0)
- 无 critical/high 级 source 命中

### dsh-vision-router(视觉路由)

- 裁决:✅ safe · 0/100
- 命中 0 条(source 0)
- 无 critical/high 级 source 命中

### dsh-web-ui(UI 合集)

- 裁决:👀 review · 20/100
- 命中 1 条(source 1)
- critical/high 命中:
  - `SEN-MAN-002` package.json:1 — 不是 DSH bundle(缺少 dsh.bundle 声明)

### dsh-im-gateway(IM 聚合网关)

- 裁决:✅ safe · 0/100
- 命中 0 条(source 0)
- 无 critical/high 级 source 命中

### dsh-noema(长期记忆)

- 裁决:✅ safe · 8/100
- 命中 1 条(source 1)
- 无 critical/high 级 source 命中

## 说明与免责

- 启发式静态扫描 ≠ 安全保证;本表不构成对任何插件的指控或背书。
- 高风险的插件市场类(如 dsh-market)命中多为"能力型"网络调用(其自身 API 端点),属预期复核项。
- 部分 MAN-00x 命中来自语料不完整(见"方法"),请在完整仓库上复核。
