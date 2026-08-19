/**
 * Benchmark(§22.4):基于 test/fixtures/bench 的带标注语料,
 * 计算 TP / FP / FN / precision / recall。
 * 用法:npm run benchmark
 */

import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../engine/index.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const MANIFEST = JSON.parse(readFileSync(join(ROOT, 'test', 'fixtures', 'bench', 'manifest.json'), 'utf8'))

const rows = []
let tp = 0; let fp = 0; let fn = 0
for (const entry of MANIFEST) {
  const file = join(ROOT, 'test', 'fixtures', 'bench', entry.file)
  const report = await scan(file)
  const detected = new Set(report.findings.map((f) => f.id))
  const expected = new Set(entry.expects)
  const t = [...expected].filter((id) => detected.has(id)).length
  const fpos = [...detected].filter((id) => !expected.has(id)).length
  const fneg = [...expected].filter((id) => !detected.has(id)).length
  tp += t; fp += fpos; fn += fneg
  rows.push({ file: entry.file, expected: entry.expects.length, detected: detected.size, tp: t, fp: fpos, fn: fneg, detail: [...detected].join(',') || '—' })
}

const precision = tp + fp > 0 ? (tp / (tp + fp)).toFixed(3) : 'n/a'
const recall = tp + fn > 0 ? (tp / (tp + fn)).toFixed(3) : 'n/a'
const f1 = precision !== 'n/a' && recall !== 'n/a' ? (2 * Number(precision) * Number(recall) / (Number(precision) + Number(recall) || 1)).toFixed(3) : 'n/a'

console.log('=== dsh-sentinel benchmark ===')
console.log('file'.padEnd(48), 'exp', 'det', 'TP', 'FP', 'FN', 'detected ids')
for (const r of rows) {
  console.log(r.file.padEnd(48), String(r.expected).padEnd(3), String(r.detected).padEnd(3),
    String(r.tp).padEnd(3), String(r.fp).padEnd(3), String(r.fn).padEnd(3), r.detail)
}
console.log('\nmetrics:')
console.log(`  true positives : ${tp}`)
console.log(`  false positives: ${fp}`)
console.log(`  false negatives: ${fn}`)
console.log(`  precision      : ${precision}`)
console.log(`  recall         : ${recall}`)
console.log(`  F1             : ${f1}`)
console.log(`\n(带标注语料:${MANIFEST.length} 项,恶意/安全/绕过三组)`)
