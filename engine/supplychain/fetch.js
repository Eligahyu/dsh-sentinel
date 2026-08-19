/**
 * 下载层 URL 安全校验(P1-2 §11.3-11.5)。
 *
 * 静态 scanner 只能做"字符串分类";这里是真实网络客户端,
 * 对 hostname 做 DNS 解析并逐地址检查,拒绝解析到私有/保留地址的下载。
 *
 * 严格模式默认关闭(strict=false 时不做任何网络动作),避免破坏合法的
 * 内网 registry 镜像场景;由调用方显式开启(SENTINEL_STRICT_DNS=1 或参数)。
 *
 * 已知限制(§11.5,DNS TOCTOU):
 *   DNS validation reduces SSRF risk but does not fully eliminate DNS
 *   rebinding — 校验后到实际连接之间 DNS 可能被换绑。v0.4 不宣称绝对防护;
 *   完整消除需要自定义 dispatcher 绑定已验证 IP(未来版本)。
 */

import { lookup } from 'node:dns/promises'
import { normalizeHostname } from '../semantic/harness.js'

/** IPv4/IPv6 是否属于私有/保留地址(SSRF 相关集合)。 */
export function isPrivateIp(ip) {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip)
  if (v4) {
    const a = Number(v4[1])
    const b = Number(v4[2])
    if (a === 0 || a === 10 || a === 127) return true
    if (a === 169 && b === 254) return true // link-local(含云元数据 169.254.169.254)
    if (a === 172 && b >= 16 && b <= 31) return true
    if (a === 192 && b === 168) return true
    if (a >= 224) return true // 组播/保留
    return false
  }
  const lower = ip.toLowerCase()
  if (lower === '::' || lower === '::1') return true
  if (lower.startsWith('::ffff:')) return true // IPv4-mapped(内嵌 IPv4 已含私有判定)
  if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true // ULA fc00::/7
  if (/^fe[89ab][0-9a-f]:/.test(lower)) return true // link-local fe80::/10
  if (lower.startsWith('2001:db8:')) return true // documentation 段
  return false
}

/**
 * 严格模式下校验 URL hostname:自身为私有地址或 DNS 解析出任一私有地址 → 抛错。
 * 返回解析结果(all:true);非严格模式直接返回 []。
 * @param {string} url
 * @param {object} [opts] - {strict: boolean}
 * @returns {Promise<Array<{address: string, family: number}>>}
 */
export async function assertPublicDns(url, { strict = false } = {}) {
  if (!strict) return []
  let host
  try {
    host = normalizeHostname(new URL(url).hostname)
  } catch {
    throw new Error(`SSRF guard: invalid URL ${url}`)
  }
  if (!host) throw new Error(`SSRF guard: empty hostname in ${url}`)
  if (isPrivateIp(host)) {
    throw new Error(`SSRF guard: private address target ${host}`)
  }
  let addrs
  try {
    addrs = await lookup(host, { all: true })
  } catch (error) {
    throw new Error(`SSRF guard: DNS lookup failed for ${host} (${error.code ?? error.message})`)
  }
  const bad = addrs.filter((a) => isPrivateIp(a.address))
  if (bad.length > 0) {
    throw new Error(`SSRF guard: ${host} resolves to private address(es): ${bad.map((a) => a.address).join(', ')}`)
  }
  return addrs
}

/** strict DNS 开关:环境变量 SENTINEL_STRICT_DNS=1 或显式参数。 */
export function strictDnsEnabled(explicit) {
  if (typeof explicit === 'boolean') return explicit
  return process.env.SENTINEL_STRICT_DNS === '1'
}
