/**
 * 生成 docs/ecosystem-scan.md:把 scratch/corpus 下抓取的第三方插件体检结果
 * 汇总成一份可发布的生态扫描报告。
 * 用法:node scripts/generate-ecosystem-doc.mjs
 */
import { readdirSync, statSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { scan } from '../engine/index.js'

const ROOT = join(process.cwd(), 'scratch', 'corpus')
const DOCS = join(process.cwd(), 'docs')
mkdirSync(DOCS, { recursive: true })

const VERDICT_EMOJI = { safe: '✅', review: '👀', risky: '⚠️', dangerous: '🚨' }
const REPO_LABELS = {
  'zhu1090093659__dsh-web-ui': 'dsh-web-ui(UI 合集)',
  'liustack__modlens': 'modlens(视觉)',
  'omdsh-dev__DSH-better-sidebar': 'DSH-better-sidebar(侧边栏)',
  'ccch1mneyyy__dsh-TUI': 'dsh-TUI(终端 UI)',
  'dsh-market__dsh-market': 'dsh-market(插件市场)',
  'Anionex__dsh-vision-toolkit': 'dsh-vision-toolkit(视觉)',
  'Nagi-ovo__dsh-ads': 'dsh-ads(整活)',
  'NanmiCoder__dsh-agent-teams': 'dsh-agent-teams(Agent 团队)',
  'vlln__whale-girl': 'whale-girl(桌宠)',
  'csyangwen__dsh-memory-evolve': 'dsh-memory-evolve(记忆)',
  'Small-tailqwq__dsh-deep-whale': 'dsh-deep-whale(皮肤)',
}

const rows = []
const details = []
for (const dirName of readdirSync(ROOT)) {
  const dir = join(ROOT, dirName)
  if (!statSync(dir).isDirectory()) continue
  if (!existsSync(join(dir, 'package.json'))) continue
  const report = await scan(dir, { maxFiles: 2000 })
  const s = report.summary
  const label = REPO_LABELS[dirName] ?? dirName
  const top = report.findings
    .filter((f) => !f.testFile && (f.severity === 'critical' || f.severity === 'high'))
    .slice(0, 6)
  rows.push({
    label,
    dir: dirName,
    verdict: s.verdict,
    score: s.score,
    findings: s.totalFindings,
    src: s.byContext?.source ?? 0,
    manifest: report.manifest.isBundle ? 'bundle' : '非 bundle',
    top: top.map((f) => ({ id: f.id, file: f.file, line: f.line, message: f.message })),
  })
  details.push({ label, ...rows[rows.length - 1] })
}

rows.sort((a, b) => b.score - a.score)

const lines = []
lines.push('# 生态扫描:DSh 插件体检快照')
lines.push('')
lines.push('> 由 **dsh-sentinel** 对生态 Top 插件的公开源码做只读静态扫描(不执行任何被扫描代码)。')
lines.push('> 数据为一次快照,不代表插件安全性结论——命中只表示"需要人工复核"。')
lines.push('')
lines.push('## 方法')
lines.push('')
lines.push('- 语料来源:通过 jsDelivr CDN 抓取各仓库 `main`/`master` 分支的 `package.json`、`cordis.patch.yml`、入口与 README 等关键文件(网络受限环境下 raw.githubusercontent 不可达)')
lines.push('- **语料不完整**:每个仓库只抓取了部分文件,缺失文件会导致 manifest 类命中(MAN-00x)失真;部分入口文件为构建产物(git 仓库没有 `lib/`),也会产生假命中')
lines.push('- 复现:`node scripts/fetch-corpus.mjs && node scripts/scan-corpus.mjs`')
lines.push('')
lines.push('## 结果一览(按风险分排序)')
lines.push('')
lines.push('| 插件 | 裁决 | 分 | 命中 | manifest |')
lines.push('| --- | --- | --- | --- | --- |')
for (const r of rows) {
  lines.push(`| ${r.label} | ${VERDICT_EMOJI[r.verdict]} ${r.verdict} | ${r.score}/100 | ${r.findings}(src ${r.src}) | ${r.manifest} |`)
}
lines.push('')
lines.push('## 主要命中明细')
lines.push('')
for (const d of details) {
  lines.push(`### ${d.label}`)
  lines.push('')
  lines.push(`- 裁决:${VERDICT_EMOJI[d.verdict]} ${d.verdict} · ${d.score}/100`)
  lines.push(`- 命中 ${d.findings} 条(source ${d.src})`)
  if (d.top.length === 0) {
    lines.push('- 无 critical/high 级 source 命中')
  } else {
    lines.push('- critical/high 命中:')
    for (const f of d.top) {
      lines.push(`  - \`${f.id}\` ${f.file}:${f.line} — ${f.message}`)
    }
  }
  lines.push('')
}
lines.push('## 说明与免责')
lines.push('')
lines.push('- 启发式静态扫描 ≠ 安全保证;本表不构成对任何插件的指控或背书。')
lines.push('- 高风险的插件市场类(如 dsh-market)命中多为"能力型"网络调用(其自身 API 端点),属预期复核项。')
lines.push('- 部分 MAN-00x 命中来自语料不完整(见"方法"),请在完整仓库上复核。')
lines.push('')

writeFileSync(join(DOCS, 'ecosystem-scan.md'), lines.join('\n'))
console.log('docs/ecosystem-scan.md written')
