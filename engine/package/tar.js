/**
 * Safe tarball extraction(安装前审计的隔离解包)。
 *
 * 防护:
 *   - path traversal:../../evil、绝对路径、盘符(C:\evil)一律拒绝
 *   - symlink / hardlink 条目一律拒绝(symlink escape / hardlink escape)
 *   - tar bomb 限制:条目数 / 解压总字节 / 单文件大小 / 路径长度 / 嵌套深度
 *   - 超限抛 TarSafetyError → 上层 BLOCK-RECOMMENDED 且 scanComplete=false
 *
 * 实现:自包含 tar 解析(gzip 解压 + 512 字节头解析),支持 PAX/GNU 长名。
 * 绝不执行包内任何脚本。
 */

import { gunzipSync } from 'node:zlib'
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs'
import { join, resolve, relative, isAbsolute, sep } from 'node:path'

export class TarSafetyError extends Error {
  constructor(code, detail) {
    super(`unsafe tarball: ${code} — ${detail}`)
    this.name = 'TarSafetyError'
    this.code = code
  }
}

export const TAR_LIMITS = Object.freeze({
  maxCompressedBytes: 100 * 1024 * 1024, // 压缩包上限(防压缩炸弹内存峰值)
  maxEntries: 20000,
  maxUnpackedBytes: 300 * 1024 * 1024,
  maxSingleFileBytes: 50 * 1024 * 1024,
  maxPathLength: 1024,
  maxNestingDepth: 32,
})

function parseOctal(buf, start, len) {
  const s = buf.toString('utf8', start, start + len).replace(/\0/g, '').trim()
  if (!s) return 0
  const v = parseInt(s, 8)
  return Number.isNaN(v) ? 0 : v
}

function cString(buf, start, len) {
  const s = buf.toString('utf8', start, start + len)
  const nul = s.indexOf('\0')
  return nul >= 0 ? s.slice(0, nul) : s.trim()
}

/** 解析 PAX 扩展头中的 path 记录。 */
function paxPathOf(paxBuf) {
  let out = null
  let i = 0
  const text = paxBuf.toString('utf8')
  while (i < text.length) {
    const sp = text.indexOf(' ', i)
    if (sp < 0) break
    const len = parseInt(text.slice(i, sp), 10)
    if (Number.isNaN(len) || len <= 0 || sp + len > text.length) break
    const record = text.slice(sp + 1, sp + len)
    const eq = record.indexOf('=')
    if (eq > 0 && record.slice(0, eq) === 'path') out = record.slice(eq + 1)
    i = sp + len
  }
  return out
}

/** 目标路径安全校验并解析到 destDir 内;违规抛 TarSafetyError。 */
export function safeJoin(destDir, name, limits = TAR_LIMITS) {
  const norm = String(name).replace(/\\/g, '/')
  if (norm.startsWith('/')) throw new TarSafetyError('absolute-path', name)
  if (/^[A-Za-z]:/.test(norm)) throw new TarSafetyError('drive-path', name)
  if (norm.length > limits.maxPathLength) throw new TarSafetyError('path-too-long', name)
  const depth = norm.split('/').filter((p) => p !== '' && p !== '.').length
  if (depth > limits.maxNestingDepth) throw new TarSafetyError('nesting-too-deep', name)
  const abs = resolve(destDir, norm)
  const rel = relative(destDir, abs)
  if (rel === '..' || rel.startsWith('..' + sep) || isAbsolute(rel)) {
    throw new TarSafetyError('path-traversal', name)
  }
  return abs
}

/**
 * 把 tarball 安全解包到 destDir。
 * @returns {{ entries: number, unpackedBytes: number, files: string[] }}
 */
export function extractTarballSafe(tarballPath, destDir, limits = TAR_LIMITS) {
  const raw = readFileSync(tarballPath)
  if (raw.length > limits.maxCompressedBytes) {
    throw new TarSafetyError('tar-too-large', `compressed ${raw.length} bytes > ${limits.maxCompressedBytes}`)
  }
  let data = raw
  if (raw.length >= 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
    try {
      data = gunzipSync(raw)
    } catch (error) {
      throw new TarSafetyError('invalid-gzip', String(error?.message ?? error))
    }
  }

  let offset = 0
  let entries = 0
  let unpackedBytes = 0
  let paxPath = null
  let gnuName = null
  const files = []

  const headerEnd = (size) => offset + 512 + size + ((512 - (size % 512)) % 512)

  while (offset + 512 <= data.length) {
    const header = data.subarray(offset, offset + 512)
    if (header.every((b) => b === 0)) break // 全零块 = 结束
    const name = cString(header, 0, 100)
    const size = parseOctal(header, 124, 12)
    const typeflag = String.fromCharCode(header[156] || 0)
    const linkname = cString(header, 157, 100)
    const prefix = cString(header, 345, 155)
    const contentStart = offset + 512
    const contentEnd = contentStart + size
    if (contentEnd > data.length) throw new TarSafetyError('truncated-entry', name)

    entries += 1
    if (entries > limits.maxEntries) throw new TarSafetyError('too-many-entries', `> ${limits.maxEntries}`)
    unpackedBytes += size
    if (unpackedBytes > limits.maxUnpackedBytes) {
      throw new TarSafetyError('tar-bomb', `unpacked ${unpackedBytes} bytes > ${limits.maxUnpackedBytes}`)
    }
    if (size > limits.maxSingleFileBytes) {
      throw new TarSafetyError('single-file-too-large', `${name} ${size} bytes`)
    }

    if (typeflag === 'L') { // GNU long name
      gnuName = cString(data.subarray(contentStart, contentEnd), 0, contentEnd - contentStart)
    } else if (typeflag === 'x') { // PAX extended header
      paxPath = paxPathOf(data.subarray(contentStart, contentEnd))
    } else if (typeflag === '1' || typeflag === '2') {
      // 硬链接 / 符号链接:一律拒绝(manifest-derived 与包内容都不可信)
      throw new TarSafetyError('link-entry', `${typeflag === '1' ? 'hardlink' : 'symlink'} ${name} -> ${linkname}`)
    } else if (typeflag === '0' || typeflag === '\0' || typeflag === '') {
      let target = prefix ? `${prefix}/${name}` : name
      if (gnuName !== null) { target = gnuName; gnuName = null }
      if (paxPath !== null) { target = paxPath; paxPath = null }
      const abs = safeJoin(destDir, target, limits)
      mkdirSync(join(abs, '..'), { recursive: true })
      writeFileSync(abs, data.subarray(contentStart, contentEnd))
      files.push(target.replace(/\\/g, '/'))
    } else if (typeflag === '5') { // 目录
      const target = prefix ? `${prefix}/${name}` : name
      mkdirSync(safeJoin(destDir, target, limits), { recursive: true })
    }
    // 其他类型(设备/FIFO/global pax)跳过

    offset = headerEnd(size)
  }

  return { entries, unpackedBytes, files }
}
