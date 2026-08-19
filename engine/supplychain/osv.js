/**
 * OSV 漏洞查询(Phase 8):--advisories,默认关闭。
 * 只上传 package name + version,绝不上传源码。
 * 查询失败/离线时静默降级(报告标注 advisories: 'unavailable')。
 */

import { readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'

export const OSV_API = 'https://api.osv.dev/v1/query'

/**
 * 查询某个包的已知漏洞。
 * @param {string} name
 * @param {string} version
 * @returns {Promise<{status: 'ok'|'unavailable', vulnerabilities: Array}>}
 */
export async function queryOsv(name, version) {
  const outPath = join(tmpdir(), `osv-out-${Date.now()}-${Math.random().toString(36).slice(2)}.json`)
  const bodyFile = join(tmpdir(), `osv-body-${Date.now()}-${Math.random().toString(36).slice(2)}.json`)
  let vulnerabilities = []
  let status = 'unavailable'
  try {
    writeFileSync(bodyFile, JSON.stringify({ package: { name, ecosystem: 'npm' }, version }), 'utf8')
    const r = spawnSync('curl.exe', ['-s', '--max-time', '20', '-X', 'POST', '-H', 'Content-Type: application/json',
      '--data', `@${bodyFile}`, '-o', outPath, OSV_API], { stdio: 'ignore' })
    if (r.status === 0) {
      const doc = JSON.parse(readFileSync(outPath, 'utf8'))
      vulnerabilities = (doc.vulns ?? []).map((v) => ({
        id: v.id,
        summary: v.summary ?? '',
        severity: v.severity?.[0]?.score ? `CVSS ${v.severity[0].score}` : '',
        modified: v.modified ?? '',
      }))
      status = 'ok'
    }
  } catch {
    status = 'unavailable'
  } finally {
    rmSync(outPath, { force: true })
    rmSync(bodyFile, { force: true })
  }
  return { status, vulnerabilities }
}

/** 把 OSV 结果并入报告。 */
export function attachAdvisories(report, result) {
  report.advisories = {
    status: result.status,
    vulnerabilities: result.vulnerabilities,
  }
  if (result.status === 'ok' && result.vulnerabilities.length > 0) {
    report.findings.push(...result.vulnerabilities.map((v) => ({
      id: 'SEN-OSV-001',
      severity: 'medium',
      category: 'supplychain',
      confidence: 'high',
      message: `已知漏洞:${v.id} — ${v.summary}`,
      file: 'package.json',
      line: 1,
      snippet: v.summary.slice(0, 200),
      recommendation: '升级到修复版本;如无法升级,评估缓解措施。',
    })))
  }
  return report
}
