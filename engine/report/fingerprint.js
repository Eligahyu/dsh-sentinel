/**
 * Finding 稳定指纹(Phase 7):代码移动几行不应产生全新 finding。
 *
 * 指纹 = sha256(ruleId + normalizedFile + normalizedSink + normalizedSource),
 * 不依赖绝对行号。normalizedFile:统一分隔符、小写。
 */

import { createHash } from 'node:crypto'

/** 归一化文件路径:统一分隔符 + 小写(Windows/macOS/Linux 一致)。 */
export function normalizeFile(file) {
  return String(file ?? '').replace(/\\/g, '/').toLowerCase()
}

/** finding → 稳定指纹。兼容原始形态(ruleId)与报告形态(id)。 */
export function fingerprintOf(finding) {
  const sink = typeof finding.sink?.callee === 'string' ? finding.sink.callee : ''
  const source = typeof finding.source?.name === 'string' ? finding.source.name : ''
  const key = [
    finding.ruleId ?? finding.id ?? '',
    normalizeFile(finding.file),
    sink,
    source,
  ].join('|')
  return createHash('sha256').update(key).digest('hex')
}

/** 给报告内每个 finding 附加 fingerprint(幂等)。 */
export function attachFingerprints(report) {
  for (const f of report.findings ?? []) {
    if (!f.fingerprint) f.fingerprint = fingerprintOf(f)
  }
  return report
}

/**
 * Baseline 对比:按指纹区分 new / existing / resolved。
 * @param {object} report - 当前报告(已附指纹)
 * @param {object} baseline - 历史报告(已附指纹)
 * @returns {{newFindings: number, existingFindings: number, resolvedFindings: number, new: Array, resolved: Array}}
 */
export function diffBaseline(report, baseline) {
  const current = new Map((report.findings ?? []).map((f) => [f.fingerprint, f]))
  const past = new Map((baseline?.findings ?? []).map((f) => [f.fingerprint, f]))
  const newFindings = []
  const resolved = []
  for (const [fp, f] of current) {
    if (!past.has(fp)) newFindings.push(f)
  }
  for (const [fp, f] of past) {
    if (!current.has(fp)) resolved.push(f)
  }
  return {
    newFindings: newFindings.length,
    existingFindings: current.size - newFindings.length,
    resolvedFindings: resolved.length,
    new: newFindings,
    resolved,
  }
}
