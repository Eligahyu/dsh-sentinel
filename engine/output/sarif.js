/**
 * SARIF 2.1.0 输出(Phase 7):供 GitHub Code Scanning / 各 SARIF 消费者使用。
 *
 * 注意:SARIF 是"结果标准化"格式,不是检测引擎本身。
 *
 * 约定:
 *   - severity 映射:critical/high → error,medium → warning,low/info → note
 *   - 路径尽量输出仓库相对路径(basePath 提供时),不写本机绝对路径
 *   - 每个结果带稳定 partialFingerprints(rule+normalizedFile+sink+source,不依赖行号)
 */

import { VERSION } from '../version.js'
import { fingerprintOf } from '../report/fingerprint.js'
import { relative, isAbsolute, resolve } from 'node:path'

const SEVERITY_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }

/** 报告 → SARIF 2.1.0 JSON。@param {object} opts - {basePath: 仓库根(相对化路径用)} */
export function toSarif(report, opts = {}) {
  let basePath = null
  if (opts.basePath) {
    try {
      basePath = resolve(opts.basePath)
    } catch {
      basePath = null
    }
  }
  const toUri = (p) => {
    const norm = String(p ?? '').replace(/\\/g, '/')
    if (basePath && isAbsolute(p)) {
      const r = relative(basePath, p).replace(/\\/g, '/')
      if (!r.startsWith('..') && r !== '..') return r
    }
    return norm
  }

  const rules = new Map()
  for (const f of report.findings ?? []) {
    if (!rules.has(f.id)) {
      rules.set(f.id, {
        id: f.id,
        name: f.id,
        shortDescription: { text: f.message },
        defaultConfiguration: { level: SEVERITY_LEVEL[f.severity] ?? 'warning' },
        help: { text: f.recommendation ?? '', markdown: f.recommendation ?? '' },
        properties: { category: f.category, severity: f.severity, confidence: f.confidence ?? 'medium' },
      })
    }
  }
  const results = (report.findings ?? []).map((f) => ({
    ruleId: f.id,
    level: SEVERITY_LEVEL[f.severity] ?? 'warning',
    message: { text: `${f.message}${f.detail ? ` — ${f.detail}` : ''}` },
    locations: [{
      physicalLocation: {
        artifactLocation: { uri: toUri(f.file) },
        region: { startLine: f.line ?? 1 },
      },
    }],
    partialFingerprints: { primaryLocationLineHash: fingerprintOf(f).slice(0, 32) },
    properties: { severity: f.severity, confidence: f.confidence ?? 'medium' },
  }))
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'dsh-sentinel',
          version: VERSION,
          informationUri: 'https://github.com/Eligahyu/dsh-sentinel-scanner',
          rules: [...rules.values()],
        },
      },
      results,
      properties: {
        summary: report.summary,
      },
    }],
  }
}
