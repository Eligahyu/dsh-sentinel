/**
 * 源码 ↔ 发布包差异(Phase 8):SEN-SUPPLY-003 source-package-drift。
 *
 * 对比 GitHub 源码 checkout 与 npm tarball 内容:
 *   - 发布包独有文件(extra files)
 *   - 源码独有文件(missing files,源码有但发布包没有)
 *   - 运行文件被修改(同名文件 hash 不同)
 *   - 发布包多出的二进制
 *   - install scripts 不一致
 *
 * 发现"仓库源码正常、发布包夹带额外代码"的供应链漂移。
 */

import { readdirSync, statSync, readFileSync, existsSync } from 'node:fs'
import { join, relative } from 'node:path'
import { createHash } from 'node:crypto'

function walkFiles(root, skipDirs = new Set(['.git', 'node_modules'])) {
  const out = []
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (skipDirs.has(entry.name)) continue
      const abs = join(dir, entry.name)
      if (entry.isDirectory()) walk(abs)
      else if (entry.isFile()) out.push(relative(root, abs).replace(/\\/g, '/'))
    }
  }
  walk(root)
  return out
}

function hashOf(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex').slice(0, 16)
}

const BINARY_EXT = /\.(?:exe|dll|so|dylib|wasm|node|bin|o|a|class|pyc)$/i

/**
 * 对比源码目录与发布包目录。
 * @param {string} sourceDir - GitHub 源码 checkout
 * @param {string} packageDir - 已解包的 npm tarball 目录
 * @returns {{drift: Array, extraFiles: Array, missingFiles: Array, modifiedFiles: Array, unexpectedBinaries: Array, scriptDiff: Array}}
 */
export function compareSourcePackage(sourceDir, packageDir) {
  const srcFiles = new Set(walkFiles(sourceDir))
  const pkgFiles = new Set(walkFiles(packageDir, new Set(['node_modules'])))
  const extraFiles = [...pkgFiles].filter((f) => !srcFiles.has(f)).sort()
  const missingFiles = [...srcFiles].filter((f) => !pkgFiles.has(f)).sort()
  const modifiedFiles = []
  for (const f of srcFiles) {
    if (!pkgFiles.has(f)) continue
    const s = join(sourceDir, f)
    const p = join(packageDir, f)
    if (statSync(s).size !== statSync(p).size || hashOf(s) !== hashOf(p)) modifiedFiles.push(f)
  }
  const unexpectedBinaries = extraFiles.filter((f) => BINARY_EXT.test(f))
  // install scripts 对比
  const readScripts = (dir) => {
    const p = join(dir, 'package.json')
    if (!existsSync(p)) return null
    try { return JSON.parse(readFileSync(p, 'utf8')).scripts ?? {} } catch { return null }
  }
  const srcScripts = readScripts(sourceDir) ?? {}
  const pkgScripts = readScripts(packageDir) ?? {}
  const scriptDiff = []
  for (const key of new Set([...Object.keys(srcScripts), ...Object.keys(pkgScripts)])) {
    if (srcScripts[key] !== pkgScripts[key]) scriptDiff.push({ script: key, source: srcScripts[key] ?? null, package: pkgScripts[key] ?? null })
  }
  return { extraFiles, missingFiles, modifiedFiles, unexpectedBinaries, scriptDiff }
}

/** 把差异转成 SEN-SUPPLY-003 finding。 */
export function driftFindings(diff, relPath = '') {
  const findings = []
  const push = (message, detail) => {
    findings.push({
      ruleId: 'SEN-SUPPLY-003',
      severity: 'high',
      category: 'supplychain',
      confidence: 'high',
      message,
      file: relPath || 'package',
      line: 1,
      snippet: detail.slice(0, 240),
      recommendation: '对比源码仓库与发布包内容,确认额外/修改文件来源;必要时用构建产物审计取代手工发布。',
      detail,
    })
  }
  if (diff.extraFiles.length > 0) push(`发布包含 ${diff.extraFiles.length} 个源码中不存在的文件`, diff.extraFiles.slice(0, 10).join(', '))
  if (diff.modifiedFiles.length > 0) push(`发布包中 ${diff.modifiedFiles.length} 个运行文件与源码不一致`, diff.modifiedFiles.slice(0, 10).join(', '))
  if (diff.unexpectedBinaries.length > 0) push(`发布包含 ${diff.unexpectedBinaries.length} 个意外二进制`, diff.unexpectedBinaries.join(', '))
  for (const sd of diff.scriptDiff) {
    if (sd.source !== sd.package && sd.package !== null) {
      push(`install 脚本不一致(${sd.script})`, `source=${sd.source ?? '(无)'} package=${sd.package}`)
    }
  }
  return findings
}

/**
 * 源码目录 ↔ npm 发布包对比(diff 子命令)。
 * @param {string} sourceDir - GitHub 源码 checkout
 * @param {string} spec - npm:<pkg> 或 pkg[@version]
 * @returns {Promise<{diff: object, findings: Array, package: string, version: string}>}
 */
export async function diffPackageWithSource(sourceDir, spec) {
  const { acquirePackageDir } = await import('./audit.js')
  const { dir, cleanup, meta } = await acquirePackageDir(spec)
  try {
    const diff = compareSourcePackage(sourceDir, dir)
    return { diff, findings: driftFindings(diff), package: meta.name, version: meta.version }
  } finally {
    cleanup()
  }
}
