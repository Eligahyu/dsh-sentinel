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

### 3. npm 发布(需要你的 npm 账号)
- [x] 包名定为 **`deepseek-harness-sentinel`**(`dsh-sentinel` 在 npm 已被占用),patch/README 已同步
- [x] `npm pack --dry-run` 验证通过:11 文件 / 28.4 kB,内容正确
- [ ] **执行:`npm login && npm publish`**(交互式认证无法代做)

### 4. 中文社区传播
- [x] 生态体检素材已生成:`docs/ecosystem-scan.md`(11 个 Top 插件扫描快照)
- [ ] 掘金/知乎/公众号文章 + 演示动图(待发布后写)

### 5. 持续运营
- [ ] 每周合并误报修复 PR(安全工具的口碑 = 误报率)
- [ ] 推出 GitHub Action(`dsh-sentinel-action`),让"PR 自动审计插件改动"成为生态默认姿势
- [ ] 调研 awesome-dsh-plugin 的 `data/repositories.json`,批量扫描 Top 200 生成公开排行榜(天然传播素材 + 数据新闻点)

## 🧭 版本规划

### v0.2(近期)
- HTML 报告(单文件,内嵌样式,可直接分享)
- `--ignore <pattern>` / 项目级 `sentinel.config.json`
- 规则命中上下文(前后 N 行)而非单行 snippet
- 扫描缓存(按文件 hash,增量扫描大仓库)

### v0.3
- GitHub Action + 徽章服务
- 已知恶意模式指纹库(从公开情报同步)
- 供应链证据链:`dsh plugin add` 前自动扫描并生成"安装审计单"

### v1.0
- 规则插件化(第三方规则包)
- 语义级检测(轻量 AST,替代纯正则,显著降误报)
- 多生态支持(pi / Claude Code 插件扫描)

## 🎯 定位红线(决定不做的事)

- ❌ 不做"自动判定恶意"的一票否决——只做证据与建议,决策权留给用户
- ❌ 不联网收集被扫描代码(隐私),离线纯本地
- ❌ 不执行被扫描代码(动态沙箱是另一个项目的事)
