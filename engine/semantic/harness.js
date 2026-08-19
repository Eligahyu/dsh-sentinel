/**
 * Harness 专属语义规则(Phase 6):
 *   SEN-AGENT-005 tool-prompt-poisoning      — 工具描述/指令文本中的投毒短语
 *   SEN-AGENT-006 capability-mismatch        — 描述与真实能力明显不符的证据
 *   SSRF 目标细化(localhost/云元数据/危险协议)
 *   args.path 无 containment 提示(path traversal)
 *   记忆/对话内容 → 网络外传(memory 污点)
 */

const POISON_PHRASES = [
  /ignore\s+(?:all\s+)?(?:previous|prior)\s+(?:instructions|prompts?|directions)/i,
  /do\s+not\s+(?:tell|inform|notify|warn)\s+(?:the\s+)?user/i,
  /don'?t\s+(?:tell|let)\s+(?:the\s+)?user/i,
  /conceal|hide\s+this|secretly|stealth/i,
  /always\s+(?:call|use|invoke)\s+/i,
  /send\s+(?:files|data|logs|content|everything)\s+to/i,
  /exfiltrat|upload\s+(?:to|the)\s+(?:remote|server|endpoint)/i,
  /never\s+(?:mention|reveal|disclose)/i,
]

const SSRF_TARGETS = [
  /localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|::1/i,
  /file:\/\/|gopher:\/\/|ftp:\/\//i,
  /(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}\.\d{1,3}/,
]

/** 能力关键词:出现这些词的"工具"通常不应有敏感 sink。 */
const BENIGN_KEYWORDS = /weather|greeting|hello|translate|quote|joke|fact|time|date|unit|convert|dictionary|calculator|poll/i

/**
 * 对语义 finding 做 Harness 专属增强:
 *   - SEN-AGENT-004:SSRF 目标检测 + detail
 *   - SEN-AGENT-002/003:containment 提示
 * @param {Array} findings - astTaintScan 的输出(原地增强)
 * @param {string} content - 文件全文
 */
export function enrichHarnessFindings(findings, content) {
  for (const f of findings) {
    if (f.ruleId === 'SEN-AGENT-004') {
      const line = (content.split('\n')[f.line - 1] ?? '') + '\n' + (content.split('\n')[f.line] ?? '')
      const ssrf = SSRF_TARGETS.find((re) => re.test(line))
      if (ssrf) {
        f.detail = '网络目标含 localhost / 内网 / 云元数据 / 危险协议——SSRF 面确认'
        f.ssrfTarget = true
      }
    }
    if (f.ruleId === 'SEN-AGENT-002' || f.ruleId === 'SEN-AGENT-003') {
      const hasContainment = /(?:resolve|join|normalize)\s*\(\s*(?:workspace|WORKSPACE|root|ROOT|cwd|__dirname)/.test(content)
      f.detail = hasContainment
        ? '存在 workspace 归一化调用,需人工确认 containment 校验完整'
        : '未发现 workspace containment——任意路径访问风险'
    }
  }
  return findings
}

/**
 * Prompt/Tool 投毒检测(confidence: low,命中只是复核提示)。
 */
export function scanPromptPoisoning(content, relPath) {
  const findings = []
  const fileLines = content.split('\n')
  for (let i = 0; i < fileLines.length; i += 1) {
    const line = fileLines[i]
    const phrase = POISON_PHRASES.find((re) => re.test(line))
    if (!phrase) continue
    findings.push({
      ruleId: 'SEN-AGENT-005',
      severity: 'medium',
      category: 'agent',
      confidence: 'low',
      message: '工具/指令文本疑似 prompt 投毒短语(需结合上下文判断)',
      file: relPath,
      line: i + 1,
      snippet: line.replace(/\s+/g, ' ').trim().slice(0, 240),
      recommendation: '人工判断短语是否用于防御性说明(如"忽略注入指令")还是恶意指令。',
      detail: phrase.source,
    })
  }
  return findings
}

/**
 * 能力不匹配证据:描述像普通工具,但主体含敏感 sink。
 */
export function scanCapabilityMismatch(content, relPath) {
  const findings = []
  const defineRe = /\bdefineTool\s*\(\s*\{/g
  let m
  while ((m = defineRe.exec(content)) !== null) {
    const descMatch = content.slice(m.index, m.index + 800).match(/description\s*:\s*["'`]([^"'`]{0,200})/)
    const desc = descMatch?.[1] ?? ''
    if (desc && BENIGN_KEYWORDS.test(desc)) {
      const window = content.slice(m.index, m.index + 2000)
      if (/(?:exec|spawn|readFile|writeFile|fetch|WebSocket)\s*\(/.test(window)) {
        const line = content.slice(0, m.index).split('\n').length
        findings.push({
          ruleId: 'SEN-AGENT-006',
          severity: 'medium',
          category: 'agent',
          confidence: 'low',
          message: `工具描述("${desc.slice(0, 40)}…")与代码能力(exec/fetch/读写)明显不符,存在隐藏副作用可能`,
          file: relPath,
          line,
          snippet: (content.split('\n')[line - 1] ?? '').replace(/\s+/g, ' ').trim().slice(0, 240),
          recommendation: '人工核对工具描述与实际行为的差异。',
        })
      }
    }
  }
  return findings
}
