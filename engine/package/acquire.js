/**
 * npm 包元数据获取(安装前审计的第一步)。
 * 只读取 package metadata(名称/版本/tarball/integrity),不上传任何源码。
 */

import { readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'

export const NPM_REGISTRY = process.env.SENTINEL_NPM_REGISTRY ?? 'https://registry.npmjs.org'

/** 解析 'name' 或 'name@version' 规格。 */
export function parsePackageSpec(spec) {
  const s = spec.trim()
  const at = s.lastIndexOf('@')
  if (at <= 0) return { name: s, version: null }
  return { name: s.slice(0, at), version: s.slice(at + 1) }
}

/** 沙箱内获取 URL 文本:curl -o 落盘再读(规避管道/重定向限制)。 */
function fetchText(url) {
  const out = join(tmpdir(), `npm-fetch-${Date.now()}-${Math.random().toString(36).slice(2)}.json`)
  const r = spawnSync('curl.exe', ['-s', '--max-time', '30', '-o', out, url], { stdio: 'ignore' })
  let text = null
  if (r.status === 0) {
    try { text = readFileSync(out, 'utf8') } catch { text = null }
  }
  rmSync(out, { force: true })
  return text
}

/**
 * 获取 npm 包元数据(仅 metadata,不下载 tarball)。
 * @param {string} spec - 'name' 或 'name@version'
 * @returns {Promise<{name, version, dist: {tarball, integrity, shasum}, dependencies, scripts}>}
 */
export async function acquireNpmPackage(spec) {
  const { name, version } = parsePackageSpec(spec)
  if (!name) throw new Error(`invalid package spec: ${spec}`)
  const url = version
    ? `${NPM_REGISTRY}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`
    : `${NPM_REGISTRY}/${encodeURIComponent(name)}/latest`
  const text = fetchText(url)
  if (text === null || !text.trim().startsWith('{')) {
    throw new Error(`无法获取 npm 元数据:${name}@${version ?? 'latest'}(注册表不可达或包不存在)`)
  }
  let doc
  try {
    doc = JSON.parse(text)
  } catch {
    throw new Error(`npm 元数据解析失败:${name}@${version ?? 'latest'}`)
  }
  if (!doc.dist?.tarball) throw new Error(`npm 元数据缺少 tarball:${name}@${doc.version ?? version}`)
  return {
    name: doc.name ?? name,
    version: doc.version,
    dist: {
      tarball: doc.dist.tarball,
      integrity: doc.dist.integrity ?? '',
      shasum: doc.dist.shasum ?? '',
    },
    dependencies: doc.dependencies ?? {},
    scripts: doc.scripts ?? {},
  }
}
