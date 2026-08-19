/**
 * tarball 获取 + 隔离解包 + 完整性校验。
 * 红线:解包后不运行 npm install,不执行任何生命周期脚本(preinstall/install/postinstall/prepare)。
 * 解包使用自包含安全解析(engine/package/tar.js):防 traversal / symlink / tar bomb。
 */

import { createHash } from 'node:crypto'
import { readFileSync, rmSync, mkdirSync, readdirSync, renameSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { extractTarballSafe, TarSafetyError } from './tar.js'

/** sha512 base64 integrity(npm 格式)与文件内容比对。 */
export function verifyIntegrity(filePath, integrity) {
  if (!integrity) return { ok: false, reason: 'no-integrity-field' }
  const m = /^sha512-([A-Za-z0-9+/=]+)$/.exec(integrity)
  if (!m) return { ok: false, reason: 'unsupported-integrity-format' }
  const expected = m[1]
  const actual = createHash('sha512').update(readFileSync(filePath)).digest('base64')
  return { ok: actual === expected, actual, expected }
}

/** 文件 sha256 十六进制(报告用)。 */
export function fileSha256(filePath) {
  return createHash('sha256').update(readFileSync(filePath)).digest('hex')
}

/**
 * 下载 tarball 到临时文件并校验 integrity。
 * @returns {Promise<{tarballPath: string, sha256: string, integrityOk: boolean, integrityReason?: string}>}
 */
export async function downloadTarball(tarballUrl, integrity) {
  const tarballPath = join(tmpdir(), `sentinel-pkg-${Date.now()}-${Math.random().toString(36).slice(2)}.tgz`)
  const r = spawnSync('curl.exe', ['-sL', '--max-time', '120', '-o', tarballPath, tarballUrl], { stdio: 'ignore' })
  if (r.status !== 0) {
    rmSync(tarballPath, { force: true })
    throw new Error(`tarball 下载失败:${tarballUrl}`)
  }
  const integrityResult = verifyIntegrity(tarballPath, integrity)
  return {
    tarballPath,
    sha256: fileSha256(tarballPath),
    integrityOk: integrityResult.ok,
    integrityReason: integrityResult.reason,
  }
}

/**
 * 把 tarball 解包到隔离目录(quarantine)。绝不执行包内任何脚本。
 * 任何成功 / 失败 / 异常路径都必须 finally cleanup(调用方负责)。
 * TarSafetyError(或任何解包异常)时自行清理已创建的 quarantine 目录。
 * @returns {Promise<{dir: string, cleanup: () => void, entries: number, unpackedBytes: number}>}
 */
export async function extractTarball(tarballPath) {
  const base = join(tmpdir(), `sentinel-quarantine-${Date.now()}-${Math.random().toString(36).slice(2)}`)
  const extractDir = join(base, 'x')
  mkdirSync(extractDir, { recursive: true })
  let stats
  try {
    stats = extractTarballSafe(tarballPath, extractDir)
  } catch (error) {
    rmSync(base, { recursive: true, force: true }) // P0-6:失败路径不留 quarantine
    throw error
  }
  // npm tarball 内容在 package/ 下;若缺则用整个解包目录。
  const pkgDir = join(extractDir, 'package')
  const dir = readdirSync(extractDir).length === 1 && readdirSync(extractDir)[0] === 'package'
    ? pkgDir
    : extractDir
  const cleanup = () => rmSync(base, { recursive: true, force: true })
  return { dir, cleanup, entries: stats.entries, unpackedBytes: stats.unpackedBytes }
}

/** 把已解包的 package/ 内容平铺到目标目录(与 npm pack 布局一致)。 */
export function flattenPackage(srcDir, destDir) {
  mkdirSync(destDir, { recursive: true })
  for (const entry of readdirSync(srcDir)) {
    renameSync(join(srcDir, entry), join(destDir, entry))
  }
}

export { TarSafetyError }
