# Roadmap / 发布清单

## 🚀 发布 Checklist(拿到第一批 star 的路径)

### 1. 创建 GitHub 仓库
- [ ] 仓库名 `dsh-sentinel`,描述用 README 第一行
- [ ] Topics 打上:`dsh-plugin`、`deepseek-harness`、`security`、`scanner`、`supply-chain-security`、`static-analysis`(topic 是 awesome 榜单抓取和用户搜索的入口)
- [ ] 开 Discussions(生态用户习惯直接聊)
- [ ] 加 `SECURITY.md`(报告漏洞的渠道,安全工具的信任锚)

### 2. 上架插件目录(流量入口)
- [ ] [awesome-dsh-plugin](https://github.com/bruc3van/awesome-dsh-plugin):按 CONTRIBUTING.md 提交作者自荐(SHOWCASE),强调"生态第一个插件安全体检工具"的定位
- [ ] [dsh-market](https://github.com/dsh-market/dsh-market) 提交收录
- [ ] [DSH-Plugins-Marketplace](https://github.com/bradeGithub/DSH-Plugins-Marketplace) 提交收录
- [ ] [dsh-find-plugins](https://github.com/Nagi-ovo/dsh-find-plugins)(Skill)会被 Agent 搜索到,topic 打对即可

### 3. npm 发布(消除 git 安装的构建授权门槛)
- [ ] `npm publish`(仓库已配好 `files`:`engine`/`plugin`/`bin`/`cordis.patch.yml`)
- [ ] 发布后安装变成 `dsh plugin add dsh-sentinel`——一键,无 `allowBuilds` 授权

### 4. 中文社区传播(生态爆款路径)
- [ ] 掘金/知乎/公众号各一篇:《DeepSeek Harness 插件生态 4798 个插件,谁来给它们体检?》
  - 素材:生态数据 + 恶意 fixture 演示(先给一个"看起来正常"的插件,扫描出 20 条高危)
  - 钩子:供应链安全叙事 + "你的 AI 正在执行来路不明的代码"
- [ ] 小红书/即刻发 CLI 演示动图
- [ ] 找 [dsh-handbook](https://github.com/Electricitysheep/dsh-handbook) 作者互推(插件开发手册,读者即插件作者)

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
