/**
 * Secret 脱敏:报告中的 snippet 可能原样包含 sk-xxx / ghp_xxx / JWT / AWS key /
 * PEM 私钥等,直接写进 JSON / CI 日志会造成二次泄露。所有输出前必须 redact。
 * redactSecrets 永远开启(不可配置关闭)。
 */

import { createHash } from 'node:crypto'

/** 已知 secret 形态(与 SEN-CRED-003 检测一致,但这里用于脱敏)。 */
export const SECRET_SHAPES = [
  { name: 'OpenAI/DeepSeek API key', re: /\bsk-[A-Za-z0-9_-]{12,}\b/g },
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{12,}\b/g },
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'GitHub personal access token', re: /\bghp_[A-Za-z0-9]{36}\b/g },
  { name: 'GitHub fine-grained PAT', re: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g },
  { name: 'npm access token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  { name: 'JWT-style token', re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  // PEM 私钥块整体脱敏(header 到 footer 之间全部内容)
  { name: 'PEM private key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]{0,6000}?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g },
]

/** 单个 secret 的稳定指纹(绝不包含原文)。 */
export function secretFingerprint(value) {
  return createHash('sha256').update(value).digest('hex').slice(0, 24)
}

/** 保留首 6 位与末 4 位,中间替换为 ****。 */
function redactOne(value) {
  if (value.length <= 12) return value.slice(0, 2) + '****'
  return value.slice(0, 6) + '****' + value.slice(-4)
}

/**
 * 对文本中的所有已知 secret 形态做脱敏。
 * @param {string} text - 原始文本(如 finding snippet)。
 * @returns {{ text: string, redacted: boolean, fingerprints: string[] }}
 */
export function redactSecrets(text) {
  if (typeof text !== 'string' || text.length === 0) {
    return { text, redacted: false, fingerprints: [] }
  }
  let redacted = false
  const fingerprints = []
  let out = text
  for (const shape of SECRET_SHAPES) {
    shape.re.lastIndex = 0
    out = out.replace(shape.re, (m) => {
      redacted = true
      if (fingerprints.length < 5) fingerprints.push(secretFingerprint(m))
      return redactOne(m)
    })
  }
  return { text: out, redacted, fingerprints }
}
