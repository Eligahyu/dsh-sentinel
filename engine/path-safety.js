/**
 * 路径 containment:manifest(patch / main / exports / 入口名)中的任何路径
 * 都视为不可信输入,禁止解析到扫描根目录之外(如 ../../Users/xxx/.ssh/id_rsa)。
 * 词法归一化 + 前缀校验;Windows 上大小写不敏感。
 */

import { resolve, normalize, sep } from 'node:path'

/** 候选路径逃逸出扫描根目录时抛出。 */
export class PathEscapeError extends Error {
  constructor(candidate) {
    super(`path escapes scan root: ${candidate}`)
    this.name = 'PathEscapeError'
    this.candidate = candidate
  }
}

/** 候选绝对路径是否位于 root(含 root 本身)之内。 */
export function isInsideRoot(root, candidate) {
  const r = normalize(resolve(root))
  const c = normalize(resolve(candidate))
  const rl = r.toLowerCase()
  const cl = c.toLowerCase()
  return cl === rl || cl.startsWith(rl + sep.toLowerCase())
}

/**
 * 把 candidate 解析为 root 内的绝对路径;若逃逸则抛 PathEscapeError。
 * candidate 可以是相对或绝对路径,均按绝对路径校验。
 */
export function resolveInside(root, candidate) {
  const abs = resolve(root, candidate)
  if (!isInsideRoot(root, abs)) throw new PathEscapeError(candidate)
  return abs
}
