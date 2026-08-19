/**
 * Benchmark(§17):基于 test/fixtures/bench 的带标注语料,
 * 计算三级指标:
 *   1. Rule-level   — 期望规则 ID 集合 vs 检测到的规则 ID 集合(TP/FP/FN/precision/recall/F1)
 *   2. Finding-level— 期望 {id, line}(±tolerance 行)vs 实际 finding 位置
 *   3. Flow-level   — 期望 {id, source, sink} vs 实际 finding 的 source/sink 链
 * 用法:npm run benchmark
 */

import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { scan } from '../engine/index.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const MANIFEST = JSON.parse(readFileSync(join(ROOT, 'test', 'fixtures', 'bench', 'manifest.json'), 'utf8'))

const LINE_TOLERANCE = 2

const rows = []
let tp = 0; let fp = 0; let fn = 0
let ftp = 0; let ffp = 0; let ffn = 0
let ltp = 0; let lfp = 0; let lfn = 0
let findingMode = 0
let flowMode = 0

for (const entry of MANIFEST) {
  const file = join(ROOT, 'test', 'fixtures', 'bench', entry.file)
  const report = await scan(file)
  const findings = report.findings
  const detected = new Set(findings.map((f) => f.id))
  const expected = new Set(entry.expects ?? [])

  // ── Rule-level ──
  const t = [...expected].filter((id) => detected.has(id)).length
  const fpos = [...detected].filter((id) => !expected.has(id)).length
  const fneg = [...expected].filter((id) => !detected.has(id)).length
  tp += t; fp += fpos; fn += fneg

  // ── Finding-level(仅当该条目声明了 finding 级期望) ──
  let ft = 0; let ff = 0; let ffn_ = 0
  if (Array.isArray(entry.findings) && entry.findings.length > 0) {
    findingMode += 1
    const used = new Set()
    for (const ef of entry.findings) {
      const tol = ef.tolerance ?? LINE_TOLERANCE
      let hit = null
      for (let i = 0; i < findings.length; i += 1) {
        if (used.has(i)) continue
        const f = findings[i]
        if (f.id === ef.id && Math.abs((f.line ?? 1) - (ef.line ?? 1)) <= tol) {
          hit = i
          break
        }
      }
      if (hit !== null) { ft += 1; used.add(hit) } else { ffn_ += 1 }
    }
    // FP:实际命中中,既未被 finding 期望匹配、其规则也不在规则级期望中
    for (let i = 0; i < findings.length; i += 1) {
      if (used.has(i)) continue
      if (!expected.has(findings[i].id)) ff += 1
    }
    ftp += ft; ffp += ff; ffn += ffn_
  }

  // ── Flow-level(仅当该条目声明了 flow 级期望) ──
  let lt = 0; let lf = 0; let lfn_ = 0
  if (Array.isArray(entry.flows) && entry.flows.length > 0) {
    flowMode += 1
    const used = new Set()
    for (const ef of entry.flows) {
      let hit = null
      for (let i = 0; i < findings.length; i += 1) {
        if (used.has(i)) continue
        const f = findings[i]
        if (f.id !== ef.id) continue
        const src = typeof f.source?.name === 'string' ? f.source.name : ''
        const sink = typeof f.sink?.callee === 'string' ? f.sink.callee : ''
        if ((!ef.source || src.includes(ef.source)) && (!ef.sink || sink.includes(ef.sink))) {
          hit = i
          break
        }
      }
      if (hit !== null) { lt += 1; used.add(hit) } else { lfn_ += 1 }
    }
    for (let i = 0; i < findings.length; i += 1) {
      if (used.has(i)) continue
      const f = findings[i]
      if (f.source && f.sink && !expected.has(f.id)) lf += 1
    }
    ltp += lt; lfp += lf; lfn += lfn_
  }

  rows.push({
    file: entry.file,
    expected: entry.expects?.length ?? 0,
    detected: detected.size,
    tp: t, fp: fpos, fn: fneg,
    finding: Array.isArray(entry.findings) ? `${ft}/${entry.findings.length}` : '—',
    flow: Array.isArray(entry.flows) ? `${lt}/${entry.flows.length}` : '—',
    detail: [...detected].join(',') || '—',
  })
}

const metrics = (t, p, n) => {
  const precision = t + p > 0 ? (t / (t + p)).toFixed(3) : 'n/a'
  const recall = t + n > 0 ? (t / (t + n)).toFixed(3) : 'n/a'
  const f1 = precision !== 'n/a' && recall !== 'n/a'
    ? (2 * Number(precision) * Number(recall) / (Number(precision) + Number(recall) || 1)).toFixed(3)
    : 'n/a'
  return { precision, recall, f1 }
}

const rule = metrics(tp, fp, fn)
const finding = metrics(ftp, ffp, ffn)
const flow = metrics(ltp, lfp, lfn)

console.log('=== dsh-sentinel benchmark(rule / finding / flow) ===')
console.log('file'.padEnd(42), 'exp', 'det', 'TP', 'FP', 'FN', 'F@l', 'FL@l', 'detected ids')
for (const r of rows) {
  console.log(r.file.padEnd(42), String(r.expected).padEnd(3), String(r.detected).padEnd(3),
    String(r.tp).padEnd(3), String(r.fp).padEnd(3), String(r.fn).padEnd(3),
    r.finding.padEnd(4), r.flow.padEnd(4), r.detail)
}
console.log('\nrule-level metrics:')
console.log(`  true positives : ${tp}\n  false positives: ${fp}\n  false negatives: ${fn}\n  precision      : ${rule.precision}\n  recall         : ${rule.recall}\n  F1             : ${rule.f1}`)
console.log(`\nfinding-level metrics(位置 ±${LINE_TOLERANCE} 行,${findingMode} 条带标注):`)
console.log(`  precision      : ${finding.precision}\n  recall         : ${finding.recall}\n  F1             : ${finding.f1}`)
console.log(`\nflow-level metrics(source→sink,${flowMode} 条带标注):`)
console.log(`  precision      : ${flow.precision}\n  recall         : ${flow.recall}\n  F1             : ${flow.f1}`)
console.log(`\n(带标注语料:${MANIFEST.length} 项,恶意/安全/绕过三组;finding 级 ${ftp}/${ftp + ffn} 命中,flow 级 ${ltp}/${ltp + lfn} 命中)`)
