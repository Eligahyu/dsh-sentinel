/**
 * Shannon entropy(二进制最低限度审计用)。
 * 高熵通常表示压缩/加密/加壳,但绝不直接判定恶意——只作为复核信号。
 */

/** 计算 buffer 的 Shannon entropy(0-8 bits/byte)。 */
export function shannonEntropy(buf) {
  if (!buf || buf.length === 0) return 0
  const counts = new Uint32Array(256)
  for (let i = 0; i < buf.length; i += 1) counts[buf[i]] += 1
  const len = buf.length
  let h = 0
  for (let i = 0; i < 256; i += 1) {
    if (counts[i] === 0) continue
    const p = counts[i] / len
    h -= p * Math.log2(p)
  }
  return h
}
