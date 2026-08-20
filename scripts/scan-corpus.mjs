/**
 * 扫描抓取到的第三方插件语料:重建目录结构 → dsh-sentinel 扫描 → 汇总。
 * 用法:node scripts/scan-corpus.mjs
 */
import { readdirSync, statSync, mkdirSync, renameSync, existsSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { scan } from '../engine/index.js'
import { validateRepositoryTree } from './corpus-utils.mjs'

const FULL_ROOT = join(process.cwd(), 'scratch', 'corpus-full')
const ROOT = process.env.DSH_CORPUS_ROOT || (existsSync(FULL_ROOT) ? FULL_ROOT : join(process.cwd(), 'scratch', 'corpus'))

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
  if (ROOT !== FULL_ROOT && !process.env.DSH_CORPUS_ROOT) rebuildTree(dir)
  let validation
  try {
    validation = validateRepositoryTree(dir)
  } catch (error) {
    results.push({
      dir: dirName,
      error: `invalid-corpus: ${error?.message ?? error}`,
      verdict: 'invalid',
      score: null,
      complete: false,
    })
    continue
  }
  const report = await scan(dir, { maxFiles: 2000 })
  const s = report.summary
  const moduleGraph = report.analysisLayers.moduleGraph
  const top = report.findings
    .filter((f) => !f.testFile && !f.developmentFile && (f.severity === 'critical' || f.severity === 'high'))
    .slice(0, 6)
    .map((f) => `${f.id}@${f.file}:${f.line}`)
  results.push({
    dir: dirName,
    verdict: s.verdict,
    score: s.score,
    complete: s.scanComplete,
    incompleteReasons: s.incompleteReasons,
    files: s.filesScanned,
    sourceFiles: validation.sourceFiles,
    findings: s.totalFindings,
    src: s.byContext?.source ?? 0,
    test: s.byContext?.test ?? 0,
    development: s.byContext?.development ?? 0,
    manifest: `${report.manifest.name ?? ''}@${report.manifest.version ?? ''} isBundle=${report.manifest.isBundle}`,
    moduleFailures: moduleGraph.failures?.length ?? 0,
    moduleWarnings: moduleGraph.warnings?.length ?? 0,
    unparsed: (moduleGraph.nodes ?? []).filter((node) => node.parser === 'unparsed').length,
    top,
  })
}

results.sort((a, b) => b.score - a.score)
for (const r of results) {
  console.log(`\n${'='.repeat(70)}`)
  console.log(`${r.dir}  →  ${r.verdict.toUpperCase()} score=${r.score ?? 'n/a'}/100 complete=${r.complete} (files=${r.files ?? 0} findings=${r.findings ?? 0} src=${r.src ?? 0} test=${r.test ?? 0} dev=${r.development ?? 0})`)
  if (r.error) console.log(`  error: ${r.error}`)
  if (r.manifest) console.log(`  manifest: ${r.manifest}`)
  if (r.moduleFailures || r.moduleWarnings) console.log(`  module graph: failures=${r.moduleFailures} warnings=${r.moduleWarnings} unparsed=${r.unparsed}`)
  for (const t of r.top) console.log(`  ⚠ ${t}`)
}

writeFileSync(join(ROOT, '_scan-summary.json'), JSON.stringify(results, null, 2))
console.log(`\n汇总写入 ${join(ROOT, '_scan-summary.json')}`)
