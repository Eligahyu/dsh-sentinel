/**
 * Binary / WASM 最低限度审计(metadata-level,不反编译)。
 *
 * 对 .wasm/.exe/.dll/.so/.dylib/.node 等可执行原生二进制:
 *   magic bytes / size / sha256 / entropy / printable strings / extension
 *
 * 红线:只读字节、提取 ASCII 字符串,绝不执行、绝不反编译、绝不加载。
 * 二进制 presence 只是"需要人工复核"的信号,不是恶意判定。
 */

import { printableStrings } from './strings.js'
import { shannonEntropy } from './entropy.js'

/** 高危信号:命中即 high(外传端点 / 凭据标记)。 */
export const HIGH_SIGNALS = [
  { re: /webhook\.site|requestbin|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|ngrok|oast\.(?:me|online|fun|pro)|interact\.sh|pipedream|pastebin/i, label: 'exfil-endpoint' },
  { re: /AWS_|OPENAI_API_KEY|DEEPSEEK_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN|github_pat_|ghp_|AKIA|sk-ant-|xox[baprs]-/i, label: 'credential-marker' },
]

/** 中危信号:命中即 medium(通用 shell 工具 / 凭据路径)。 */
export const MEDIUM_SIGNALS = [
  { re: /\b(?:curl|wget|powershell|cmd\.exe|bash|sh|nc|ncat|socat)\b/i, label: 'shell-tool' },
  { re: /\.ssh|\.npmrc|\.aws|\.netrc|kubeconfig|id_rsa|id_ed25519/i, label: 'credential-path' },
]

/** 依据 magic bytes 分类文件种类(采样前 8 字节)。 */
export function classifyBinary(buf) {
  const magic = [...buf.slice(0, 8)].map((b) => b.toString(16).padStart(2, '0')).join('')
  if (buf.length >= 4 && buf[0] === 0x00 && buf[1] === 0x61 && buf[2] === 0x73 && buf[3] === 0x6d) {
    return { kind: 'wasm', magic }
  }
  if (buf.length >= 2 && buf[0] === 0x4d && buf[1] === 0x5a) return { kind: 'pe', magic } // MZ
  if (buf.length >= 4 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return { kind: 'elf', magic }
  if (buf.length >= 4 && buf[0] === 0xca && buf[1] === 0xfe && buf[2] === 0xba && buf[3] === 0xbe) return { kind: 'mach-o', magic }
  if (buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) return { kind: 'zip', magic }
  return { kind: 'unknown', magic }
}

/**
 * 对二进制采样 buffer 做 metadata 审计。
 * @param {Buffer} buf - 文件头采样(前 64KB 即可)
 * @returns {{kind, magic, entropy, highSignals: string[], mediumSignals: string[]}}
 */
export function auditBinarySample(buf, ext = '') {
  const cls = classifyBinary(buf)
  const entropy = shannonEntropy(buf)
  const strings = printableStrings(buf)
  const highSignals = HIGH_SIGNALS
    .filter((s) => strings.some((str) => s.re.test(str)))
    .map((s) => s.label)
  const mediumSignals = MEDIUM_SIGNALS
    .filter((s) => strings.some((str) => s.re.test(str)))
    .map((s) => s.label)
  return {
    kind: cls.kind,
    magic: cls.magic,
    entropy: Number(entropy.toFixed(3)),
    highSignals,
    mediumSignals,
  }
}
