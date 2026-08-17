/**
 * dsh-sentinel public API — shared by the DSH tool plugin and the CLI.
 *
 * Zero runtime dependencies. Node >= 18.17.
 */

import { statSync, readdirSync, readFileSync, existsSync, realpathSync } from 'node:fs'
import { join, resolve, dirname, relative } from 'node:path'
import { homedir } from 'node:os'
import { scanTree, applyRule } from './scanner.js'
import { inspectBundle } from './manifest.js'
import { buildReport, verdictFor } from './report.js'
import { RULES } from './rules.js'

export const VERSION = '0.1.0'
export { RULES } from './rules.js'
export { parsePatchRows, resolvePatchEntry } from './scanner.js'
export { inspectBundle } from './manifest.js'
export { buildReport, verdictFor } from './report.js'

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
 * @param {object} opts - {maxFiles, maxBytesPerFile, maxFindings}
 * @returns {Promise<object>} canonical report
 */
export async function scan(target, opts = {}) {
  const started = Date.now()
  const abs = resolve(target)
  let findings = []
  let filesScanned = 0
  let filesSkipped = { binary: 0, big: 0, dirs: 0 }
  let languages = {}
  let largestFiles = []
  let manifest = { ok: false, name: '', version: '', isBundle: false, patch: '', license: '', description: '' }

  if (existsSync(abs) && statSync(abs).isFile()) {
    const content = readFileSync(abs, 'utf8')
    findings = []
    for (const rule of RULES) {
      if (rule.category === 'manifest' || rule.category === 'hygiene') continue
      findings.push(...applyRule(rule, target, content))
    }
    filesScanned = 1
    largestFiles = [{ file: target, bytes: content.length }]
    const ext = target.includes('.') ? target.slice(target.lastIndexOf('.') + 1) : 'text'
    languages = { [ext]: 1 }
  } else {
    const tree = await scanTree(abs, opts)
    findings = tree.findings
    filesScanned = tree.filesScanned
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
    manifest = bundle.manifest
  }

  return buildReport(
    {
      kind: 'path',
      path: abs,
      name: '',
      findings,
      manifest,
      filesScanned,
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
 * Scans $DSH_HOME/profiles/<name>/node_modules, skipping the trusted
 * @deepseek-ai built-ins (the attack surface is the third-party code).
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

  const findings = []
  const pluginsScanned = []
  const pluginsSkipped = []
  let filesScanned = 0
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

  if (!existsSync(modulesDir)) {
    findings.push({
      ruleId: 'SEN-MAN-001', severity: 'medium', category: 'manifest',
      message: `profile "${profile}" 不存在或没有已安装插件(${modulesDir})`,
      file: 'node_modules', line: 1, snippet: '', recommendation: '先安装插件:dsh plugin --profile <name> add <pkg>',
      package: '',
    })
  } else {
    const entries = readdirSync(modulesDir, { withFileTypes: true })
    let scanned = 0
    for (const entry of entries) {
      if (scanned >= maxPlugins) {
        pluginsSkipped.push(entry.name)
        continue
      }
      // Scoped packages live two levels down: @scope/pkg. The trusted
      // built-in scope is skipped wholesale — the audit targets third-party code.
      if (entry.name.startsWith('@') && entry.isDirectory()) {
        if (entry.name === '@deepseek-ai') {
          pluginsSkipped.push('@deepseek-ai/*')
          continue
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
          if (result !== null) {
            scanned += 1
            pluginsScanned.push(result.name)
            findings.push(...result.findings)
            filesScanned += result.filesScanned
            skipped.binary += result.skipped.binary
            skipped.big += result.skipped.big
            skipped.dirs += result.skipped.dirs
            for (const [k, v] of Object.entries(result.languages)) languages[k] = (languages[k] ?? 0) + v
            largestFiles.push(...result.largestFiles.map((f) => ({ file: `node_modules/${entry.name}/${sub.name}/${f.file}`, bytes: f.bytes })))
          }
        }
        continue
      }
      if (entry.name.startsWith('@deepseek-ai')) {
        pluginsSkipped.push(entry.name)
        continue
      }
      const pkgDir = join(modulesDir, entry.name)
      const result = scanOnePlugin(pkgDir, perPluginMaxFiles, opts)
      if (result !== null) {
        scanned += 1
        pluginsScanned.push(result.name)
        findings.push(...result.findings)
        filesScanned += result.filesScanned
        skipped.binary += result.skipped.binary
        skipped.big += result.skipped.big
        skipped.dirs += result.skipped.dirs
        for (const [k, v] of Object.entries(result.languages)) languages[k] = (languages[k] ?? 0) + v
        largestFiles.push(...result.largestFiles.map((f) => ({ file: `node_modules/${entry.name}/${f.file}`, bytes: f.bytes })))
      }
    }
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
      manifest,
      filesScanned,
      filesSkipped: skipped,
      languages,
      largestFiles: largestFiles.slice(0, 5),
      pluginsScanned,
      pluginsSkipped,
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

  // Collect without re-walking built-in modules twice: reuse scanTree with a
  // tighter per-plugin cap, then merge manifest findings with a package tag.
  const tree = scanTreeSync(realDir, { maxFiles, maxBytesPerFile: opts.maxBytesPerFile })
  const bundle = inspectBundle(realDir)
  const tagged = [
    ...tree.findings.map((f) => ({ ...f, package: name })),
    ...bundle.findings.map((f) => ({ ...f, package: name })),
  ]
  return {
    name,
    findings: tagged,
    filesScanned: tree.filesScanned,
    skipped: tree.filesSkipped,
    languages: tree.languages,
    largestFiles: tree.largestFiles,
  }
}

// Synchronous variant of scanTree for the profile walker (kept local).
import { collectFiles } from './scanner.js'

function scanTreeSync(root, opts = {}) {
  const { files, skipped } = collectFiles(root, opts)
  const findings = []
  const languages = {}
  const largest = []
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
    for (const rule of RULES) {
      if (rule.category === 'manifest' || rule.category === 'hygiene') continue
      findings.push(...applyRule(rule, file.rel, content))
    }
  }
  largest.sort((a, b) => b.bytes - a.bytes)
  return { findings, filesScanned: files.length, filesSkipped: skipped, languages, largestFiles: largest.slice(0, 5) }
}
