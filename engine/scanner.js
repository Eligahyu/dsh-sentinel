/**
 * File walking + rule matching.
 *
 * The scanner is intentionally dependency-free and read-only: it never
 * executes plugin code, never follows directory symlinks, and skips binary
 * payloads by extension. All paths in findings are relative to the scan root.
 */

import { readdirSync, readFileSync, lstatSync, statSync, existsSync, realpathSync } from 'node:fs'
import { join, relative, sep, dirname, basename } from 'node:path'
import { RULES, CATEGORIES } from './rules.js'

export const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.avif', '.tiff',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.pdf', '.zip', '.gz', '.tgz', '.tar', '.7z', '.rar',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.webm', '.wav', '.flac',
  '.wasm', '.exe', '.dll', '.so', '.dylib', '.class', '.pyc', '.o', '.a',
  '.db', '.sqlite', '.sqlite3', '.lockb', '.node',
])

export const SKIP_DIRECTORIES = new Set([
  '.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.nuxt',
  '.svelte-kit', '__pycache__', '.venv', 'venv', 'vendor', '.pytest_cache',
  '.turbo', '.cache', '.idea', '.vscode', 'target', 'out',
])

export const DEFAULT_LIMITS = Object.freeze({
  maxFiles: 3000,
  maxBytesPerFile: 512 * 1024,
  maxFindings: 300,
})

/** Does this relative path look like a binary we should skip? */
export function isBinaryPath(relPath) {
  const lower = relPath.toLowerCase()
  return BINARY_EXTENSIONS.has(extOf(lower))
}

function extOf(name) {
  const i = name.lastIndexOf('.')
  return i < 0 ? '' : name.slice(i)
}

/** Extract the first line number containing `index` (0-based char offset). */
function lineOf(content, index) {
  let line = 1
  for (let i = 0; i < index && i < content.length; i += 1) {
    if (content.charCodeAt(i) === 10) line += 1
  }
  return line
}

/** Trim a snippet to a readable window around the match. */
function makeSnippet(lineText, max = 240) {
  const t = lineText.replace(/\s+/g, ' ').trim()
  if (t.length <= max) return t
  return t.slice(0, max - 1) + '…'
}

function readTextFile(absPath, maxBytes) {
  const stat = statSync(absPath)
  if (!stat.isFile()) return null
  if (stat.size > maxBytes) return null
  try {
    return readFileSync(absPath, 'utf8')
  } catch {
    return null
  }
}

/** Recursively collect text files under root, applying skip rules. */
export function collectFiles(root, { maxFiles = DEFAULT_LIMITS.maxFiles, maxBytesPerFile = DEFAULT_LIMITS.maxBytesPerFile } = {}) {
  const files = []
  const skipped = { binary: 0, big: 0, dirs: 0 }
  const walk = (dir) => {
    if (files.length >= maxFiles) return
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      if (files.length >= maxFiles) return
      const abs = join(dir, entry.name)
      let stat
      try {
        stat = lstatSync(abs)
      } catch {
        continue
      }
      if (stat.isSymbolicLink()) continue // never follow symlinks
      if (stat.isDirectory()) {
        if (SKIP_DIRECTORIES.has(entry.name)) {
          skipped.dirs += 1
          continue
        }
        walk(abs)
        continue
      }
      if (!stat.isFile()) continue
      const rel = relative(root, abs)
      if (isBinaryPath(rel)) {
        skipped.binary += 1
        continue
      }
      if (stat.size > maxBytesPerFile) {
        skipped.big += 1
        continue
      }
      files.push({ abs, rel, size: stat.size })
    }
  }
  walk(root)
  return { files, skipped }
}

/** Apply one rule to one file; returns findings (deduped per rule+file+line). */
export function applyRule(rule, relPath, content) {
  if (rule.filePattern && !rule.filePattern.test(relPath)) return []

  const findings = []
  const isCommentLine = (lineText) => /^\s*(\/\/|\*|\/\*)/.test(lineText)
  const push = (line, note) => {
    if (findings.some((f) => f.line === line)) return
    const lines = content.split('\n')
    const lineText = lines[line - 1] ?? ''
    // Rule-level exclusions: known-safe idioms on the same line (e.g. the
    // `new Function("")` globalThis-detection idiom) suppress the finding.
    if (rule.excludes?.some((re) => re.test(lineText))) return
    // Comment lines carry prose/JSDoc, not executable code — exec-family rules
    // skip them to avoid "spawn()" mentioned in a comment being flagged.
    if (rule.ignoreComments && isCommentLine(lineText)) return
    findings.push({
      ruleId: rule.id,
      severity: rule.severity,
      category: rule.category,
      message: rule.message + (note ? `(${note})` : ''),
      file: relPath,
      line,
      snippet: makeSnippet(lineText),
      recommendation: rule.recommendation ?? '',
    })
  }

  for (const p of rule.linePatterns ?? []) {
    const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g')
    let m
    let guard = 0
    while ((m = re.exec(content)) !== null && guard < 50) {
      guard += 1
      push(lineOf(content, m.index), p.note)
      if (m.index === re.lastIndex) re.lastIndex += 1
      // Same-rule spam on one file adds no information; cap per file.
      if (findings.length >= 10) break
    }
  }

  for (const p of rule.contentPatterns ?? []) {
    const m = p.re.exec(content)
    if (m !== null) push(lineOf(content, m.index), p.note)
  }

  return findings
}

/**
 * Scan a directory tree with the full rule set.
 * @returns {Promise<{findings: Array, filesScanned: number, filesSkipped: {binary: number, big: number, dirs: number}, languages: Record<string, number>, largestFiles: Array}>}
 */
export async function scanTree(root, opts = {}) {
  const limits = { ...DEFAULT_LIMITS, ...opts }
  const { files, skipped } = collectFiles(root, limits)

  const findings = []
  const languages = {}
  const largest = []

  for (const file of files) {
    const content = readTextFile(file.abs, limits.maxBytesPerFile)
    if (content === null) continue
    const ext = extOf(file.rel).replace(/^\./, '') || 'text'
    languages[ext] = (languages[ext] ?? 0) + 1
    largest.push({ file: file.rel, bytes: file.size })
    if (findings.length >= limits.maxFindings) break
    for (const rule of RULES) {
      if (rule.category === 'manifest' || rule.category === 'hygiene') continue
      for (const finding of applyRule(rule, file.rel, content)) {
        findings.push(finding)
        if (findings.length >= limits.maxFindings) break
      }
      if (findings.length >= limits.maxFindings) break
    }
  }

  largest.sort((a, b) => b.bytes - a.bytes)
  return {
    findings,
    filesScanned: files.length,
    filesSkipped: skipped,
    languages,
    largestFiles: largest.slice(0, 5),
  }
}

/**
 * Resolve a patch row `name` (e.g. `dsh-sentinel/plugin`) against a package
 * root. Patch names are package-qualified: `<packageName>` or
 * `<packageName>/<subpath>`. When `packageName` is known, the package prefix
 * is stripped and the subpath resolved inside the package root; otherwise the
 * whole name is tried as a relative path. Returns the resolved absolute path
 * or null.
 */
export function resolvePatchEntry(packageRoot, name, packageName = '') {
  if (!name || name.startsWith('cordis:') || name.startsWith('@deepseek-ai/')) return null
  let rel
  if (packageName && (name === packageName || name.startsWith(packageName + '/'))) {
    rel = name === packageName ? '' : name.slice(packageName.length + 1)
  } else {
    rel = name
  }
  const candidates = []
  // Prefer the exports map (Node's modern resolution) when present.
  const pkgText = readMaybe(join(packageRoot, 'package.json'))
  if (pkgText !== null) {
    let exportsMap = null
    try {
      exportsMap = JSON.parse(pkgText).exports
    } catch {
      exportsMap = null
    }
    if (exportsMap !== null && typeof exportsMap === 'object') {
      const key = rel === '' ? '.' : `./${rel.replace(/\\/g, '/')}`
      let target = exportsMap[key]
      if (target !== null && typeof target === 'object' && !Array.isArray(target)) {
        target = target.default
      }
      if (typeof target === 'string' && target.startsWith('./')) {
        candidates.push(join(packageRoot, ...target.slice(2).split('/')))
      }
    }
    if (rel === '') {
      // Package root: honor the declared `main` first, then index conventions.
      try {
        const main = JSON.parse(pkgText).main
        if (typeof main === 'string' && main.length > 0) {
          candidates.push(join(packageRoot, ...main.replace(/\\/g, '/').split('/')))
        }
      } catch {
        // unparseable manifest — fall through to index conventions
      }
    }
  }
  if (rel === '') {
    candidates.push(join(packageRoot, 'index.js'), join(packageRoot, 'index.mjs'))
  } else {
    const parts = rel.replace(/\\/g, '/').split('/')
    const base = join(packageRoot, ...parts)
    candidates.push(base, base + '.js', base + '.mjs', join(base, 'index.js'), join(base, 'index.mjs'))
  }
  for (const c of candidates) {
    try {
      if (statSync(c).isFile()) return c
    } catch {
      // not a file — try next candidate
    }
  }
  return null
}

/** Cheap line-based extraction of rows from a patch file.
 *
 * DSH patch rows come in two flavors: `- id: X, name: Y` (insert/override a
 * plugin row) and `- id: X, config: {...}` / `- id: X, disabled: true`
 * (override an existing base row — legitimately has no `name`). Both start
 * with `- id:`; `- insert:` blocks nest rows one level deeper.
 */
export function parsePatchRows(patchText) {
  const rows = []
  let current = null
  for (const rawLine of patchText.split('\n')) {
    const line = rawLine.trim()
    const idMatch = /^-\s*id:\s*(\S+)/.exec(line)
    if (idMatch) {
      if (current) rows.push(current)
      current = { id: idMatch[1] }
      continue
    }
    if (!current) {
      // A name without any preceding id row (e.g. `- name: x`) is still a row.
      const nameOnly = /^-\s*name:\s*['"]?([^'"]+)['"]?\s*$/.exec(line)
      if (nameOnly) {
        if (current) rows.push(current)
        current = { name: nameOnly[1].trim() }
      }
      continue
    }
    const nameMatch = /^name:\s*['"]?([^'"]+)['"]?\s*$/.exec(line)
    if (nameMatch) current.name = nameMatch[1].trim()
    if (/^disabled:\s*true/i.test(line)) current.disabled = true
  }
  if (current) rows.push(current)
  return rows
}

export function readMaybe(absPath) {
  try {
    return readFileSync(absPath, 'utf8')
  } catch {
    return null
  }
}

export function hasExportContract(absPath) {
  const content = readMaybe(absPath)
  if (content === null) return false
  // Named exports: `export const name` / `export function apply` / `export default function apply`.
  if (/export\s+(?:const|function|class|default)\s+(name|apply)\b/.test(content)) return true
  // The loader's unwrapExports (`exports.default ?? exports`) also accepts a
  // default-exported object carrying the { name, inject, apply } contract.
  const defaultStart = content.search(/export\s+default\s*\{/m)
  if (defaultStart >= 0) {
    const body = content.slice(defaultStart)
    // name: '...' plus either apply: fn or the apply(ctx) method shorthand.
    return /\bname\s*:/.test(body) && /\bapply\s*[:(]/.test(body)
  }
  // CommonJS compiled bundles: `module.exports = {...}` / `exports.default = {...}`.
  if (/module\.exports\s*=|exports\.default\s*=/.test(content)) return true
  return false
}
