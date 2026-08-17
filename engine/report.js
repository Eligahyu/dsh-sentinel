/**
 * Report assembly: scoring, verdict, and the canonical JSON shape.
 *
 * The emitted object is the exact schema the DSH tools validate against, so
 * every key is always present (empty strings/arrays where not applicable).
 */

import { SEVERITY_ORDER, CATEGORIES, severityWeight } from './rules.js'

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
 * @param {object} parts
 * @param {string} parts.kind - 'path' | 'profile'
 * @param {string} parts.path - absolute scan root or profile node_modules root
 * @param {string} parts.name - profile name (kind === 'profile')
 * @param {Array} parts.findings - raw findings ({ruleId, severity, category, message, file, line, snippet, recommendation, package?})
 * @param {object} parts.manifest - normalized manifest object
 * @param {number} parts.filesScanned
 * @param {object} parts.filesSkipped
 * @param {object} parts.languages
 * @param {Array} parts.largestFiles
 * @param {Array} parts.pluginsScanned
 * @param {Array} parts.pluginsSkipped
 * @param {number} parts.scanMs
 * @param {number} maxFindings
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
    const weighted = inTest ? TEST_SEVERITY_DOWNGRADE[f.severity] ?? f.severity : f.severity
    score += severityWeight(weighted)
  }
  score = Math.min(100, score)
  const verdict = verdictFor(score)

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
    .map((f) => ({
      id: f.ruleId,
      severity: f.severity,
      category: f.category,
      message: f.message,
      file: f.file,
      line: f.line ?? 1,
      snippet: f.snippet ?? '',
      recommendation: f.recommendation ?? '',
      package: f.package ?? '',
      testFile: isTestPath(f.file),
    }))

  return {
    tool: 'dsh-sentinel',
    version: '0.1.0',
    scannedAt: new Date().toISOString(),
    target: {
      kind: parts.kind,
      path: parts.path,
      name: parts.name ?? '',
    },
    summary: {
      verdict: verdict.label,
      score,
      filesScanned: parts.filesScanned,
      filesSkipped: parts.filesSkipped?.binary ?? 0,
      totalFindings: total,
      bySeverity: counts.bySeverity,
      byCategory: counts.byCategory,
      byContext: contextCounts,
      scanMs: parts.scanMs,
    },
    manifest: parts.manifest,
    profile: {
      name: parts.name ?? '',
      pluginsScanned: parts.pluginsScanned ?? [],
      pluginsSkipped: parts.pluginsSkipped ?? [],
    },
    findings: capped,
    stats: {
      languages: parts.languages ?? {},
      largestFiles: (parts.largestFiles ?? []).map((f) => ({ file: f.file, bytes: f.bytes })),
    },
  }
}
