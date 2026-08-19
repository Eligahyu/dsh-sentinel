/**
 * Printable strings extraction(二进制最低限度审计用)。
 * 只做静态读取与 ASCII 提取,绝不反编译、绝不执行。
 */

/** 从 buffer 中提取可打印 ASCII 字符串(连续可打印字符 ≥ minLen)。 */
export function printableStrings(buf, { minLen = 4 } = {}) {
  const out = []
  let cur = ''
  for (let i = 0; i < buf.length; i += 1) {
    const b = buf[i]
    if ((b >= 0x20 && b <= 0x7e) || b === 0x09) {
      cur += String.fromCharCode(b)
    } else {
      if (cur.length >= minLen) out.push(cur)
      cur = ''
    }
  }
  if (cur.length >= minLen) out.push(cur)
  return out
}
