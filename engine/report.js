/**
 * Report assembly: scoring, verdict, and the canonical JSON shape.
 *
 * 完整度契约:
 *   - findings 上限只影响 findingsReturned,不影响实际分析(filesAnalyzed)
 *   - 任何截断(scanComplete=false)都会强制裁决不低于 review 并显式标记
 *   - 所有 snippet 中的 secret 一律脱敏(redactSecrets),绝不二次泄露
 *
 * The emitted object keeps every legacy key for compatibility.
 */

import { SEVERITY_ORDER, CATEGORIES, severityWeight } from './rules.js'
import { VERSION } from './version.js'
import { redactSecrets } from './redact.js'

export const VERDICTS = Object.freeze({
  safe: { min: 0, max: 19, label: 'safe', emoji: '✅' },
  review: { min: 20, max: 49, label: 'review', emoji: '👀' },
  risky: { min: 50, max: 79, label: 'risky', emoji: '⚠️' },
  dangerous: { min: 80, max: 100, label: 'dangerous', emoji: '🚨' },
})

/**
 * Test-file findings are usually deliberate fixtures (malicious strings,
 * base64 blobs, env-gated tests) rather than shipped code. They are still
 * listed with their detected severity, but SCORED one level lower so a repo
 * whose only hits live in tests doesn't get branded dangerous.
 */
export const TEST_SEVERITY_DOWNGRADE = Object.freeze({
  critical: 'high',
  high: 'medium',
  medium: 'low',
  low: 'info',
  info: 'info',
})

/**
 * 压缩/打包产物(bundleFile)同样降一级计分:压缩代码里 eval/Function/长 base64
 * 可能是转译器产物,信号强但精度低——照常列出并打标,权重让位于人工复核。
 */
export const BUNDLE_SEVERITY_DOWNGRADE = TEST_SEVERITY_DOWNGRADE

/**
 * Heuristic: is this relative path a test file or under a test directory?
 * Matches `test/`, `tests/`, `__tests__/`, `spec/`, `e2e/` segments and
 * `.spec.` / `.test.` / `.e2e.` filename markers.
 */
export function isTestPath(relPath) {
  return /(^|[\\/])(?:test|tests|__tests__|spec|e2e)([\\/]|\.)|\.(?:spec|test|e2e)\./i.test(relPath)
}

export function verdictFor(score) {
  for (const v of Object.values(VERDICTS)) {
    if (score >= v.min && score <= v.max) return v
  }
  return VERDICTS.dangerous
}

export function emptyCounts() {
  return {
    bySeverity: Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])),
    byCategory: Object.fromEntries(CATEGORIES.map((c) => [c, 0])),
  }
}

/**
 * Build the canonical report object.
 * @param {object} parts - 见调用方;新增完整度字段:
 *   findingsTotal, filesAnalyzed, filesDiscovered, scanComplete, scanCoverage
 */
export function buildReport(parts, maxFindings = 300) {
  const counts = emptyCounts()
  const contextCounts = { source: 0, test: 0 }
  let score = 0
  let total = 0
  for (const f of parts.findings) {
    total += 1
    const inTest = isTestPath(f.file)
    if (inTest) contextCounts.test += 1
    else contextCounts.source += 1
    counts.bySeverity[f.severity] = (counts.bySeverity[f.severity] ?? 0) + 1
    counts.byCategory[f.category] = (counts.byCategory[f.category] ?? 0) + 1
    let weighted = f.severity
    if (inTest) weighted = TEST_SEVERITY_DOWNGRADE[f.severity] ?? f.severity
    else if (f.bundleFile) weighted = BUNDLE_SEVERITY_DOWNGRADE[f.severity] ?? f.severity
    score += severityWeight(weighted)
  }
  score = Math.min(100, score)
  let verdict = verdictFor(score)

  const scanComplete = parts.scanComplete !== false
  const findingsTotal = parts.findingsTotal ?? total
  const findingsReturned = Math.min(total, maxFindings)
  const findingsTruncated = findingsTotal > findingsReturned

  // 不完整扫描绝不能显示 clean:强制至少 review 并显式标记。
  if (!scanComplete) {
    if (verdict.label === 'safe') {
      score = Math.max(score, 20)
      verdict = verdictFor(score)
    }
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
  const seen = new Set()
  const capped = [...parts.findings]
    .filter((f) => {
      const key = `${f.ruleId}|${f.file}|${f.line ?? 1}|${f.package ?? ''}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
    .sort((a, b) => order[a.severity] - order[b.severity] || a.file.localeCompare(b.file) || a.line - b.line)
    .slice(0, maxFindings)
    .map((f) => {
      const redacted = redactSecrets(f.snippet ?? '')
      return {
        id: f.ruleId,
        severity: f.severity,
        category: f.category,
        confidence: f.confidence ?? 'medium',
        message: f.message,
        file: f.file,
        line: f.line ?? 1,
        snippet: redacted.text,
        recommendation: f.recommendation ?? '',
        package: f.package ?? '',
        testFile: isTestPath(f.file),
        ...(redacted.redacted ? { redacted: true, secretFingerprints: redacted.fingerprints } : {}),
        ...(f.analysisMode ? { analysisMode: f.analysisMode } : {}),
        ...(f.bundleFile ? { bundleFile: true } : {}),
        ...(f.source ? { source: f.source } : {}),
        ...(f.sink ? { sink: f.sink } : {}),
        ...(f.flow ? { flow: f.flow } : {}),
      }
    })

  return {
    schemaVersion: 2,
    tool: 'dsh-sentinel',
    version: VERSION,
    scannedAt: new Date().toISOString(),
    target: {
      kind: parts.kind,
      path: parts.path,
      name: parts.name ?? '',
    },
    summary: {
      verdict: verdict.label,
      score,
      // 完整度
      scanComplete,
      incompleteScan: !scanComplete,
      filesDiscovered: parts.filesDiscovered ?? parts.filesScanned ?? 0,
      filesAnalyzed: parts.filesAnalyzed ?? parts.filesScanned ?? 0,
      findingsTotal,
      findingsReturned,
      findingsTruncated,
      // 兼容旧字段
      filesScanned: parts.filesAnalyzed ?? parts.filesScanned ?? 0,
      filesSkipped: parts.filesSkipped?.binary ?? 0,
      totalFindings: total,
      bySeverity: counts.bySeverity,
      byCategory: counts.byCategory,
      byContext: contextCounts,
      scanMs: parts.scanMs,
    },
    scanCoverage: parts.scanCoverage ?? {
      sourceFiles: 0,
      buildFiles: 0,
      binaryFiles: parts.filesSkipped?.binary ?? 0,
      largeFiles: 0,
      parseFailures: 0,
    },
    manifest: parts.manifest,
    profile: {
      name: parts.name ?? '',
      pluginsScanned: parts.pluginsScanned ?? [],
      pluginsSkipped: parts.pluginsSkipped ?? [],
      plugins: parts.plugins ?? [],
    },
    findings: capped,
    stats: {
      languages: parts.languages ?? {},
      largestFiles: (parts.largestFiles ?? []).map((f) => ({ file: f.file, bytes: f.bytes })),
    },
  }
}
