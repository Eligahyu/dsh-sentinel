/**
 * File walking + rule matching + semantic pass.
 *
 * The scanner is read-only: it never executes plugin code, never follows
 * directory symlinks, and treats every manifest-derived path as untrusted
 * (path containment, see engine/path-safety.js).
 *
 * Completeness contract (安全工具的红线):
 *   - findings 上限只限制"报告保存条数"(findingsReturned),绝不提前停止分析
 *   - 每个文件的每条规则命中都会被计数(findingsTotal)
 *   - 大文件不跳过:走 large-file-lite 分析并标记 analysisMode
 *   - 任何截断/跳过都会在报告中显式体现(scanComplete / filesSkipped / scanCoverage)
 */

import { readdirSync, readFileSync, lstatSync, statSync } from 'node:fs'
import { join, relative, sep, dirname } from 'node:path'
import { createHash } from 'node:crypto'
import { RULES, CODE_EXT } from './rules.js'
import { isInsideRoot, PathEscapeError } from './path-safety.js'
import { semanticScan } from './semantic/index.js'

export const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.bmp', '.avif', '.tiff',
  '.woff', '.woff2', '.ttf', '.otf', '.eot',
  '.pdf', '.zip', '.gz', '.tgz', '.tar', '.7z', '.rar',
  '.mp3', '.mp4', '.mov', '.avi', '.mkv', '.webm', '.wav', '.flac',
  '.wasm', '.exe', '.dll', '.so', '.dylib', '.class', '.pyc', '.o', '.a',
  '.db', '.sqlite', '.sqlite3', '.lockb', '.node',
])

/** source mode 跳过的目录(GitHub 源码仓库视角)。 */
export const SKIP_DIRECTORIES = new Set([
  '.git', 'node_modules', 'dist', 'build', 'coverage', '.next', '.nuxt',
  '.svelte-kit', '__pycache__', '.venv', 'venv', 'vendor', '.pytest_cache',
  '.turbo', '.cache', '.idea', '.vscode', 'target', 'out', 'scratch',
])

/** package/profile mode 仍跳过的目录:实际执行产物(dist/build/lib/out/bundle)必须扫描。 */
export const SKIP_PACKAGE_DIRECTORIES = new Set([
  '.git', 'node_modules', 'coverage', '__pycache__', '.venv', 'venv',
  '.pytest_cache', '.cache', '.idea', '.vscode', 'scratch',
])

export const DEFAULT_LIMITS = Object.freeze({
  maxFiles: 3000,
  maxBytesPerFile: 512 * 1024,
  hardMaxBytesPerFile: 20 * 1024 * 1024, // 超过此值连 lite 都不做,只记录 hash
  maxFindings: 300,
})

/** 目录路径是否属于构建产物(dist/build/out/bundle)。 */
export function isBuildPath(relPath) {
  return /(^|[\\/])(?:dist|build|out|bundle)([\\/]|$)/i.test(relPath)
}

/**
 * 压缩/打包产物启发式:存在超长单行(>3000 字符)。
 * 压缩代码是"高信号、低精度"区域(eval/Function 可能是转译器产物),
 * 命中照常列出,但计分降一级(与 test 文件同理)。
 */
export function isMinifiedContent(content) {
  let start = 0
  const max = Math.min(content.length, 2 * 1024 * 1024)
  for (let i = 0; i < max; i += 1) {
    if (content.charCodeAt(i) === 10) {
      if (i - start > 3000) return true
      start = i + 1
    }
  }
  return content.length - start > 3000
}

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

/**
 * Recursively collect text files under root, applying mode-dependent skip rules.
 * 大文件(> maxBytesPerFile,<= hardMaxBytesPerFile)单独收集,后续走 lite 分析。
 * @returns {{ files: Array, largeFiles: Array, skipped: {binary: number, big: number, dirs: number}, truncated: boolean }}
 */
export function collectFiles(root, {
  maxFiles = DEFAULT_LIMITS.maxFiles,
  maxBytesPerFile = DEFAULT_LIMITS.maxBytesPerFile,
  hardMaxBytesPerFile = DEFAULT_LIMITS.hardMaxBytesPerFile,
  mode = 'source',
} = {}) {
  const skipDirs = mode === 'source' ? SKIP_DIRECTORIES : SKIP_PACKAGE_DIRECTORIES
  const entries = []
  const skipped = { binary: 0, big: 0, dirs: 0 }
  let truncated = false
  const walk = (dir) => {
    if (entries.length >= maxFiles) {
      truncated = true
      return
    }
    let dirEntries
    try {
      dirEntries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of dirEntries) {
      if (entries.length >= maxFiles) {
        truncated = true
        return
      }
      const abs = join(dir, entry.name)
      let stat
      try {
        stat = lstatSync(abs)
      } catch {
        continue
      }
      if (stat.isSymbolicLink()) continue // never follow symlinks
      if (stat.isDirectory()) {
        if (skipDirs.has(entry.name)) {
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
      if (stat.size > hardMaxBytesPerFile) {
        skipped.big += 1
        continue
      }
      entries.push({ abs, rel, size: stat.size })
    }
  }
  walk(root)
  const files = []
  const largeFiles = []
  for (const e of entries) {
    if (e.size > maxBytesPerFile) largeFiles.push(e)
    else files.push(e)
  }
  return { files, largeFiles, skipped, truncated }
}

/**
 * Apply one rule to one file.
 * 完整度契约:total 计所有独立命中(按行去重),findings 只存前 10 条(防刷屏),
 * 绝不因单规则命中多而丢失全量计数。
 * @returns {{ findings: Array, total: number }}
 */
export function applyRule(rule, relPath, content) {
  if (rule.filePattern && !rule.filePattern.test(relPath)) return { findings: [], total: 0 }

  const findings = []
  const seenLines = new Set()
  let total = 0
  const isCommentLine = (lineText) => /^\s*(\/\/|\*|\/\*)/.test(lineText)
  const push = (line, note) => {
    if (seenLines.has(line)) return
    seenLines.add(line)
    total += 1
    const lines = content.split('\n')
    const lineText = lines[line - 1] ?? ''
    // Rule-level exclusions: known-safe idioms on the same line.
    if (rule.excludes?.some((re) => re.test(lineText))) return
    // Comment lines carry prose/JSDoc, not executable code.
    if (rule.ignoreComments && isCommentLine(lineText)) return
    if (findings.length >= 10) return // 存储上限,计数已保留
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
    if (p.needsImport) {
      const impRe = new RegExp(`(?:require|import)[^;\\n]{0,80}['"][^'"]{0,40}${p.needsImport}['"]`)
      if (!impRe.test(content)) continue
    }
    const re = new RegExp(p.re.source, p.re.flags.includes('g') ? p.re.flags : p.re.flags + 'g')
    let m
    let guard = 0
    while ((m = re.exec(content)) !== null && guard < 200) {
      guard += 1
      push(lineOf(content, m.index), p.note)
      if (m.index === re.lastIndex) re.lastIndex += 1
    }
  }

  for (const p of rule.contentPatterns ?? []) {
    const m = p.re.exec(content)
    if (m !== null) push(lineOf(content, m.index), p.note)
  }

  return { findings, total }
}

/** 大文件 lite 分析使用的规则子集(廉价行模式)。 */
const LITE_RULE_IDS = new Set(['SEN-OBF-002', 'SEN-EXEC-003', 'SEN-EXEC-002', 'SEN-NET-001', 'SEN-CRED-003', 'SEN-OBF-001'])

/**
 * 大文件(512KB–20MB)lite 分析:复用规则子集 + 文件 hash,标记 analysisMode。
 */
export function analyzeLargeFileLite(content, relPath, { hash, bytes }) {
  const findings = []
  let total = 0
  for (const rule of RULES) {
    if (!LITE_RULE_IDS.has(rule.id)) continue
    const r = applyRule(rule, relPath, content)
    total += r.total
    for (const f of r.findings) {
      f.analysisMode = 'large-file-lite'
      f.fileHash = hash
      f.fileBytes = bytes
      findings.push(f)
    }
  }
  return { findings, total }
}

/**
 * Scan a directory tree: regex fast pass + semantic deep pass.
 * @returns {Promise<object>} 完整度字段见返回对象。
 */
export async function scanTree(root, opts = {}) {
  const limits = { ...DEFAULT_LIMITS, ...opts }
  const { files, largeFiles, skipped, truncated } = collectFiles(root, limits)

  const findings = []
  let findingsTotal = 0
  const languages = {}
  const largest = []
  let sourceFiles = 0
  let buildFiles = 0

  const store = (list) => {
    for (const f of list) {
      if (findings.length < limits.maxFindings) findings.push(f)
    }
  }

  for (const file of files) {
    let content
    try {
      content = readFileSync(file.abs, 'utf8')
    } catch {
      continue
    }
    const ext = extOf(file.rel).replace(/^\./, '') || 'text'
    languages[ext] = (languages[ext] ?? 0) + 1
    largest.push({ file: file.rel, bytes: file.size })
    if (isBuildPath(file.rel)) buildFiles += 1
    else sourceFiles += 1
    const minified = isMinifiedContent(content)
    const tagMinified = (list) => {
      for (const f of list) {
        f.bundleFile = true
        f.analysisMode = 'minified'
      }
    }
    // regex fast pass
    for (const rule of RULES) {
      if (rule.category === 'manifest' || rule.category === 'hygiene') continue
      if (rule.category === 'agent' || rule.category === 'taint') continue // semantic 引擎处理
      const r = applyRule(rule, file.rel, content)
      findingsTotal += r.total
      if (minified) tagMinified(r.findings)
      store(r.findings)
    }
    // semantic deep pass(JS/TS 工具类)
    if (CODE_EXT.test(file.rel)) {
      const sem = semanticScan(content, file.rel)
      findingsTotal += sem.length
      if (minified) tagMinified(sem)
      store(sem)
    }
  }

  for (const lf of largeFiles) {
    let content
    try {
      content = readFileSync(lf.abs, 'utf8')
    } catch {
      continue
    }
    const ext = extOf(lf.rel).replace(/^\./, '') || 'text'
    languages[ext] = (languages[ext] ?? 0) + 1
    largest.push({ file: lf.rel, bytes: lf.size })
    if (isBuildPath(lf.rel)) buildFiles += 1
    else sourceFiles += 1
    const hash = createHash('sha256').update(content).digest('hex').slice(0, 16)
    const lite = analyzeLargeFileLite(content, lf.rel, { hash, bytes: lf.size })
    findingsTotal += lite.total
    if (isMinifiedContent(content)) {
      for (const f of lite.findings) {
        f.bundleFile = true
        f.analysisMode = 'minified'
      }
    }
    store(lite.findings)
  }

  largest.sort((a, b) => b.bytes - a.bytes)
  const filesAnalyzed = files.length + largeFiles.length
  return {
    findings,
    findingsTotal,
    filesAnalyzed,
    filesDiscovered: filesAnalyzed + skipped.big,
    scanComplete: !truncated,
    scanCoverage: { sourceFiles, buildFiles, binaryFiles: skipped.binary, largeFiles: largeFiles.length, parseFailures: 0 },
    filesSkipped: skipped,
    languages,
    largestFiles: largest.slice(0, 5),
  }
}

/**
 * Resolve a patch row `name` (e.g. `dsh-sentinel/plugin`) against a package
 * root, with path containment:任何解析结果必须位于包根之内,否则抛 PathEscapeError。
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
    // containment:manifest 派生的任何路径都不可信
    if (!isInsideRoot(packageRoot, c)) throw new PathEscapeError(c)
    try {
      if (statSync(c).isFile()) return c
    } catch {
      // not a file — try next candidate
    }
  }
  return null
}

/** Cheap line-based extraction of rows from a patch file. */
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

/**
 * 插件入口契约校验:Cordis/DSH 插件必须同时导出 name 与 apply。
 * 支持 ESM 命名导出、export default 对象、CJS module.exports/exports.default 对象。
 */
export function hasExportContract(absPath) {
  const content = readMaybe(absPath)
  if (content === null) return false
  const has = (re) => re.test(content)

  // ESM 命名导出:export const name / export function apply 等。
  if (has(/export\s+(?:const|let|function|class|default)\s+name\b/)
    && has(/export\s+(?:const|let|function|class|default)\s+apply\b/)) {
    return true
  }
  // export default 对象:必须同时含 name 与 apply(键或方法简写)。
  const defStart = content.search(/export\s+default\s*\{/m)
  if (defStart >= 0) {
    const body = content.slice(defStart)
    return /\bname\s*:/.test(body) && /\bapply\s*[:(]/.test(body)
  }
  // CommonJS:module.exports = {...} / exports.default = {...},必须含两个键。
  const cjsRe = /(?:module\.exports|exports\.default)\s*=\s*\{([\s\S]*?)\n?\}/m
  const cjs = cjsRe.exec(content)
  if (cjs) {
    return /\bname\s*:/.test(cjs[1]) && /\bapply\s*[:(]/.test(cjs[1])
  }
  // 仅 module.exports = require(...) 等转发形态:无法静态确认,视为不合格。
  return false
}
