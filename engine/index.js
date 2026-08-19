/**
 * dsh-sentinel public API — shared by the DSH tool plugin and the CLI.
 *
 * 扫描模式:
 *   source  — GitHub 源码仓库视角:跳过 dist/build/out(默认)
 *   package — npm tarball / 已安装插件视角:必须扫描 dist/build/lib/out(实际执行产物)
 *   profile — 已安装 profile 视角:同 package
 *
 * 完整度契约:findings 上限只限报告保存条数;filesAnalyzed / scanComplete 如实上报。
 */

import { statSync, readdirSync, readFileSync, existsSync, realpathSync } from 'node:fs'
import { join, resolve, dirname, relative } from 'node:path'
import { homedir } from 'node:os'
import { scanTree, applyRule, collectFiles, isBuildPath, isMinifiedContent } from './scanner.js'
import { inspectBundle } from './manifest.js'
import { buildReport, verdictFor } from './report.js'
import { RULES, CODE_EXT } from './rules.js'
import { semanticScan } from './semantic/index.js'

export { VERSION } from './version.js'
export { RULES } from './rules.js'
export { parsePatchRows, resolvePatchEntry } from './scanner.js'
export { inspectBundle } from './manifest.js'
export { buildReport, verdictFor } from './report.js'
export { semanticScan } from './semantic/index.js'

/** Resolve the DeepSeek Harness home: $DSH_HOME, else ~/.dsh (matches dsh). */
export function resolveDshHome(env = process.env) {
  const fromEnv = env.DSH_HOME
  const home = fromEnv !== undefined && fromEnv.trim().length > 0 ? fromEnv : join(homedir(), '.dsh')
  return resolve(home)
}

/** Nearest ancestor (≤3 levels) carrying package.json, else the target itself. */
function findBundleRoot(target) {
  let dir = target
  for (let i = 0; i < 3; i += 1) {
    if (existsSync(join(dir, 'package.json'))) return dir
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return target
}

/**
 * Scan a directory or a single file for security & health issues.
 * @param {string} target - path to a plugin repo/directory (or a file).
 * @param {object} opts - {mode, maxFiles, maxBytesPerFile, maxFindings}
 * @returns {Promise<object>} canonical report
 */
export async function scan(target, opts = {}) {
  const started = Date.now()
  const abs = resolve(target)
  let findings = []
  let findingsTotal = 0
  let filesAnalyzed = 0
  let filesDiscovered = 0
  let scanComplete = true
  let scanCoverage = { sourceFiles: 0, buildFiles: 0, binaryFiles: 0, largeFiles: 0, parseFailures: 0 }
  let filesSkipped = { binary: 0, big: 0, dirs: 0 }
  let languages = {}
  let largestFiles = []
  let manifest = { ok: false, name: '', version: '', isBundle: false, patch: '', license: '', description: '' }

  if (existsSync(abs) && statSync(abs).isFile()) {
    const content = readFileSync(abs, 'utf8')
    findings = []
    findingsTotal = 0
    const minified = isMinifiedContent(content)
    for (const rule of RULES) {
      if (rule.category === 'manifest' || rule.category === 'hygiene') continue
      if (rule.category === 'agent' || rule.category === 'taint') continue
      const r = applyRule(rule, target, content)
      findingsTotal += r.total
      if (minified) for (const f of r.findings) { f.bundleFile = true; f.analysisMode = 'minified' }
      findings.push(...r.findings)
    }
    if (CODE_EXT.test(target)) {
      const sem = semanticScan(content, target)
      findingsTotal += sem.length
      if (minified) for (const f of sem) { f.bundleFile = true; f.analysisMode = 'minified' }
      findings.push(...sem)
    }
    filesAnalyzed = 1
    filesDiscovered = 1
    largestFiles = [{ file: target, bytes: content.length }]
    const ext = target.includes('.') ? target.slice(target.lastIndexOf('.') + 1) : 'text'
    languages = { [ext]: 1 }
  } else {
    const tree = await scanTree(abs, { ...opts, mode: opts.mode ?? 'source' })
    findings = tree.findings
    findingsTotal = tree.findingsTotal
    filesAnalyzed = tree.filesAnalyzed
    filesDiscovered = tree.filesDiscovered
    scanComplete = tree.scanComplete
    scanCoverage = tree.scanCoverage
    filesSkipped = tree.filesSkipped
    languages = tree.languages
    largestFiles = tree.largestFiles
    // Manifest checks run against the nearest package root (allows scanning a
    // subdirectory of a repo); finding paths are remapped relative to target.
    const bundleRoot = findBundleRoot(abs)
    const bundle = inspectBundle(bundleRoot)
    for (const f of bundle.findings) {
      f.file = relative(abs, join(bundleRoot, f.file))
    }
    findings = [...findings, ...bundle.findings]
    findingsTotal += bundle.findings.length
    manifest = bundle.manifest
  }

  return buildReport(
    {
      kind: 'path',
      path: abs,
      name: '',
      findings,
      findingsTotal,
      filesAnalyzed,
      filesDiscovered,
      scanComplete,
      scanCoverage,
      manifest,
      filesScanned: filesAnalyzed,
      filesSkipped,
      languages,
      largestFiles,
      pluginsScanned: [],
      pluginsSkipped: [],
      scanMs: Date.now() - started,
    },
    opts.maxFindings,
  )
}

/**
 * Audit every user-installed third-party plugin in a profile.
 *
 * Scans $DSH_HOME/profiles/<name>/node_modules in package mode(dist/build/lib
 * 等实际执行产物全部纳入),跳过受信 @deepseek-ai 内置与扫描器自身。
 * @param {string} profile - profile name (defaults to 'web').
 * @param {object} opts - {maxFiles, maxPlugins, maxFindings, home}
 * @returns {Promise<object>} canonical report (kind: 'profile')
 */
export async function scanProfile(profile = 'web', opts = {}) {
  const started = Date.now()
  const home = resolveDshHome(opts.env ?? process.env)
  const profileDir = resolve(join(home, 'profiles', profile))
  const modulesDir = join(profileDir, 'node_modules')
  const maxPlugins = opts.maxPlugins ?? 12
  const perPluginMaxFiles = Math.max(200, Math.floor((opts.maxFiles ?? 3000) / Math.max(1, maxPlugins)))
  // 受信 scope:默认 @deepseek-ai;--include-builtins 时也全量扫描。
  const trustedScopes = opts.trustedScopes ?? ['@deepseek-ai']
  const includeBuiltins = opts.includeBuiltins === true
  const isTrustedScope = (name) => trustedScopes.some((s) => name === s || name.startsWith(s + '/'))

  const findings = []
  let findingsTotal = 0
  const pluginsScanned = []
  const pluginsSkipped = []
  const plugins = [] // §9.2: {name, version, direct, dependencies, findings}
  let filesAnalyzed = 0
  let filesDiscovered = 0
  let scanComplete = true
  const coverage = { sourceFiles: 0, buildFiles: 0, binaryFiles: 0, largeFiles: 0, parseFailures: 0 }
  const skipped = { binary: 0, big: 0, dirs: 0 }
  const languages = {}
  const largestFiles = []
  let manifest = { ok: false, name: `dsh-profile-${profile}`, version: '', isBundle: false, patch: '', license: '', description: '' }

  const readProfileManifest = () => {
    const pkg = readJsonSafe(join(profileDir, 'package.json'))
    if (!pkg) return null
    return pkg.dsh?.profile ?? null
  }
  const profileManifest = readProfileManifest()
  const profilePkg = readJsonSafe(join(profileDir, 'package.json'))
  const directDeps = new Set(Object.keys(profilePkg?.dependencies ?? {}))
  // 每个插件的直接依赖名(用于 transitive 判定)
  const depOf = new Map()

  const absorb = (result, prefix) => {
    scanned += 1
    pluginsScanned.push(result.name)
    findings.push(...result.findings)
    findingsTotal += result.findingsTotal
    filesAnalyzed += result.filesAnalyzed
    filesDiscovered += result.filesDiscovered
    scanComplete = scanComplete && result.scanComplete
    skipped.binary += result.skipped.binary
    skipped.big += result.skipped.big
    skipped.dirs += result.skipped.dirs
    coverage.sourceFiles += result.scanCoverage.sourceFiles
    coverage.buildFiles += result.scanCoverage.buildFiles
    coverage.binaryFiles += result.scanCoverage.binaryFiles
    coverage.largeFiles += result.scanCoverage.largeFiles
    for (const [k, v] of Object.entries(result.languages)) languages[k] = (languages[k] ?? 0) + v
    largestFiles.push(...result.largestFiles.map((f) => ({ file: `${prefix}/${f.file}`, bytes: f.bytes })))
    plugins.push({
      name: result.name,
      version: result.version,
      direct: directDeps.has(result.name),
      dependencies: result.dependencies,
      findings: result.findings.length,
    })
    depOf.set(result.name, new Set(Object.keys(result.dependenciesOf ?? {})))
  }

  let scanned = 0
  if (!existsSync(modulesDir)) {
    findings.push({
      ruleId: 'SEN-MAN-001', severity: 'medium', category: 'manifest',
      message: `profile "${profile}" 不存在或没有已安装插件(${modulesDir})`,
      file: 'node_modules', line: 1, snippet: '', recommendation: '先安装插件:dsh plugin --profile <name> add <pkg>',
      package: '',
    })
  } else {
    const entries = readdirSync(modulesDir, { withFileTypes: true })
    for (const entry of entries) {
      if (scanned >= maxPlugins) {
        pluginsSkipped.push(entry.name)
        continue
      }
      if (entry.name.startsWith('@') && entry.isDirectory()) {
        if (entry.name === '@deepseek-ai') {
          if (!includeBuiltins) {
            pluginsSkipped.push('@deepseek-ai/* (trusted)')
            continue
          }
        }
        const scopeDir = join(modulesDir, entry.name)
        const inner = readdirSync(scopeDir, { withFileTypes: true })
        for (const sub of inner) {
          if (scanned >= maxPlugins) {
            pluginsSkipped.push(`${entry.name}/${sub.name}`)
            continue
          }
          const pkgDir = join(scopeDir, sub.name)
          const result = scanOnePlugin(pkgDir, perPluginMaxFiles, opts)
          if (result !== null && result.self) {
            pluginsSkipped.push(`${entry.name}/${sub.name} (self)`)
            continue
          }
          if (result !== null) absorb(result, `node_modules/${entry.name}/${sub.name}`)
        }
        continue
      }
      if (isTrustedScope(entry.name) && !includeBuiltins) {
        pluginsSkipped.push(`${entry.name} (trusted)`)
        continue
      }
      const pkgDir = join(modulesDir, entry.name)
      const result = scanOnePlugin(pkgDir, perPluginMaxFiles, opts)
      if (result !== null && result.self) {
        pluginsSkipped.push(`${entry.name} (self)`)
        continue
      }
      if (result !== null) absorb(result, `node_modules/${entry.name}`)
    }
  }

  // direct/transitive 标注:直接依赖之外、且被其他已扫插件依赖的视为 transitive。
  for (const p of plugins) {
    if (p.direct) continue
    p.transitive = [...depOf.values()].some((deps) => deps.has(p.name))
  }

  largestFiles.sort((a, b) => b.bytes - a.bytes)
  manifest = {
    ...manifest,
    ok: true,
    profile: profileManifest,
  }

  return buildReport(
    {
      kind: 'profile',
      path: modulesDir,
      name: profile,
      findings,
      findingsTotal,
      filesAnalyzed,
      filesDiscovered,
      scanComplete,
      scanCoverage: coverage,
      manifest,
      filesScanned: filesAnalyzed,
      filesSkipped: skipped,
      languages,
      largestFiles: largestFiles.slice(0, 5),
      pluginsScanned,
      pluginsSkipped,
      plugins,
      scanMs: Date.now() - started,
    },
    opts.maxFindings,
  )
}

function readJsonSafe(absPath) {
  try {
    return JSON.parse(readFileSync(absPath, 'utf8'))
  } catch {
    return null
  }
}

/** 扫描器自身的包名:profile 审计时排除自己(审计者不出现在被审计名单里)。 */
export const SELF_PACKAGE = 'deepseek-harness-sentinel'

function scanOnePlugin(pkgDir, maxFiles, opts) {
  let realDir = pkgDir
  try {
    realDir = realpathSync(pkgDir)
  } catch {
    return null
  }
  const pkg = readJsonSafe(join(realDir, 'package.json'))
  const name = pkg?.name ?? ''
  if (!name) return null
  // 排除扫描器自身:规则库的字面量会自指命中,审计自己的规则集没有意义。
  if (name === SELF_PACKAGE) return { name, self: true }

  // package mode:dist/build/lib/out 等实际执行产物必须扫描。
  const tree = scanTreeSync(realDir, { maxFiles, maxBytesPerFile: opts.maxBytesPerFile, mode: 'package' })
  const bundle = inspectBundle(realDir)
  const tagged = [
    ...tree.findings.map((f) => ({ ...f, package: name })),
    ...bundle.findings.map((f) => ({ ...f, package: name })),
  ]
  return {
    name,
    version: String(pkg.version ?? ''),
    dependencies: Object.keys(pkg.dependencies ?? {}).length,
    dependenciesOf: pkg.dependencies ?? {},
    findings: tagged,
    findingsTotal: tree.findingsTotal + bundle.findings.length,
    filesAnalyzed: tree.filesAnalyzed,
    filesDiscovered: tree.filesDiscovered,
    scanComplete: tree.scanComplete,
    scanCoverage: tree.scanCoverage,
    skipped: tree.filesSkipped,
    languages: tree.languages,
    largestFiles: tree.largestFiles,
  }
}

// Synchronous variant of scanTree for the profile walker (package mode).
function scanTreeSync(root, opts = {}) {
  const { files, largeFiles, skipped, truncated } = collectFiles(root, opts)
  const findings = []
  let findingsTotal = 0
  const languages = {}
  const largest = []
  let sourceFiles = 0
  let buildFiles = 0
  const store = (list) => {
    for (const f of list) {
      if (findings.length < (opts.maxFindings ?? 300)) findings.push(f)
    }
  }
  for (const file of files) {
    let content
    try {
      content = readFileSync(file.abs, 'utf8')
    } catch {
      continue
    }
    const ext = file.rel.includes('.') ? file.rel.slice(file.rel.lastIndexOf('.') + 1).toLowerCase() : 'text'
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
    for (const rule of RULES) {
      if (rule.category === 'manifest' || rule.category === 'hygiene') continue
      if (rule.category === 'agent' || rule.category === 'taint') continue
      const r = applyRule(rule, file.rel, content)
      findingsTotal += r.total
      if (minified) tagMinified(r.findings)
      store(r.findings)
    }
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
    const ext = lf.rel.includes('.') ? lf.rel.slice(lf.rel.lastIndexOf('.') + 1).toLowerCase() : 'text'
    languages[ext] = (languages[ext] ?? 0) + 1
    if (isBuildPath(lf.rel)) buildFiles += 1
    else sourceFiles += 1
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
