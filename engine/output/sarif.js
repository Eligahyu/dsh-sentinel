/**
 * SARIF 2.1.0 输出(Phase 7):供 GitHub Code Scanning / 各 SARIF 消费者使用。
 */

import { VERSION } from '../version.js'
import { fingerprintOf } from '../report/fingerprint.js'

const SEVERITY_LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' }

/** 报告 → SARIF 2.1.0 JSON。 */
export function toSarif(report) {
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
        artifactLocation: { uri: f.file.replace(/\\/g, '/') },
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
          informationUri: 'https://github.com/Eligahyu/dsh-sentinel',
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
