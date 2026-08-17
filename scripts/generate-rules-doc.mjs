/**
 * Generate docs/rules.md from the rule catalog.
 * Run: node scripts/generate-rules-doc.mjs
 */

import { writeFileSync, mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { RULES, SEVERITY_WEIGHT } from '../engine/rules.js'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

const severityLabel = {
  critical: '🔴 critical(45 分)',
  high: '🟠 high(20 分)',
  medium: '🟡 medium(8 分)',
  low: '🟢 low(3 分)',
  info: '⚪ info(0 分)',
}

const lines = []
lines.push('# 规则目录 / Rule Catalog')
lines.push('')
lines.push(`共 ${RULES.length} 条启发式规则。启发式 ≠ 判决:命中只表示"需要人工复核",不代表插件一定恶意。`)
lines.push('')
lines.push(`| ID | 严重度(权重) | 类别 | 规则 | 说明 |`)
lines.push('| --- | --- | --- | --- | --- |')
for (const rule of RULES) {
  lines.push(`| \`${rule.id}\` | ${severityLabel[rule.severity]} | ${rule.category} | **${rule.name}** | ${rule.description ?? ''} |`)
}
lines.push('')
lines.push(`权重:critical=${SEVERITY_WEIGHT.critical} · high=${SEVERITY_WEIGHT.high} · medium=${SEVERITY_WEIGHT.medium} · low=${SEVERITY_WEIGHT.low} · info=${SEVERITY_WEIGHT.info},总分封顶 100。`)
lines.push('')
lines.push('裁决:0-19 ✅ safe · 20-49 👀 review · 50-79 ⚠️ risky · 80-100 🚨 dangerous')
lines.push('')

const docsDir = join(root, 'docs')
mkdirSync(docsDir, { recursive: true })
writeFileSync(join(docsDir, 'rules.md'), lines.join('\n'))
console.log('docs/rules.md written')
