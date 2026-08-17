/**
 * 扫描抓取到的第三方插件语料:重建目录结构 → dsh-sentinel 扫描 → 汇总。
 * 用法:node scripts/scan-corpus.mjs
 */
import { readdirSync, statSync, mkdirSync, renameSync, existsSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { scan } from '../engine/index.js'

const ROOT = join(process.cwd(), 'scratch', 'corpus')

/** 把 `lib__index.js` 这类扁平文件名还原为 `lib/index.js` 目录树。 */
function rebuildTree(dir) {
  for (const entry of readdirSync(dir)) {
    const abs = join(dir, entry)
    if (statSync(abs).isDirectory()) continue
    if (!entry.includes('__')) continue
    const parts = entry.split('__')
    const rel = parts.join('/')
    const dest = join(dir, rel)
    mkdirSync(dirname(dest), { recursive: true })
    renameSync(abs, dest)
  }
}

const results = []
for (const dirName of readdirSync(ROOT)) {
  const dir = join(ROOT, dirName)
  if (!statSync(dir).isDirectory()) continue
  if (!existsSync(join(dir, 'package.json'))) continue
  rebuildTree(dir)
  const report = await scan(dir, { maxFiles: 2000 })
  const s = report.summary
  const top = report.findings
    .filter((f) => !f.testFile && (f.severity === 'critical' || f.severity === 'high'))
    .slice(0, 6)
    .map((f) => `${f.id}@${f.file}:${f.line}`)
  results.push({
    dir: dirName,
    verdict: s.verdict,
    score: s.score,
    files: s.filesScanned,
    findings: s.totalFindings,
    src: s.byContext?.source ?? 0,
    test: s.byContext?.test ?? 0,
    manifest: `${report.manifest.name ?? ''}@${report.manifest.version ?? ''} isBundle=${report.manifest.isBundle}`,
    top,
  })
}

results.sort((a, b) => b.score - a.score)
for (const r of results) {
  console.log(`\n${'='.repeat(70)}`)
  console.log(`${r.dir}  →  ${r.verdict.toUpperCase()} score=${r.score}/100 (files=${r.files} findings=${r.findings} src=${r.src} test=${r.test})`)
  console.log(`  manifest: ${r.manifest}`)
  for (const t of r.top) console.log(`  ⚠ ${t}`)
}

writeFileSync(join(ROOT, '_scan-summary.json'), JSON.stringify(results, null, 2))
console.log(`\n汇总写入 scratch/corpus/_scan-summary.json`)
