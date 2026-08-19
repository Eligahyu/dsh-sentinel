/**
 * DSH bundle manifest inspection: package.json + cordis.patch.yml compliance.
 *
 * Produces SEN-MAN-* findings plus a normalized `manifest` object included in
 * every report. Never executes any of the scanned code.
 */

import { existsSync, readFileSync, statSync } from 'node:fs'
import { join, dirname, basename } from 'node:path'
import { parsePatchRows, resolvePatchEntry, readMaybe, hasExportContract } from './scanner.js'
import { resolveInside } from './path-safety.js'

export function readJson(absPath) {
  const text = readMaybe(absPath)
  if (text === null) return null
  try {
    return JSON.parse(text)
  } catch {
    return { __parseError: true }
  }
}

/** A finding-shaped object for manifest problems. */
function finding(ruleId, severity, category, message, file, line = 1, recommendation = '') {
  return { ruleId, severity, category, message, file, line, snippet: '', recommendation }
}

/**
 * Inspect a package root for DSH bundle compliance.
 * @param {string} root - absolute path to the scanned package/repo root.
 * @returns {{ manifest: object, findings: Array }}
 */
export function inspectBundle(root) {
  const findings = []
  const pkgPath = join(root, 'package.json')
  const pkg = readJson(pkgPath)

  if (pkg === null) {
    findings.push(finding('SEN-MAN-001', 'medium', 'manifest', '未找到 package.json,扫描目标不是 npm 包结构', 'package.json'))
    return {
      manifest: { ok: false, name: '', version: '', isBundle: false, patch: '', license: '', description: '' },
      findings,
    }
  }
  if (pkg.__parseError) {
    findings.push(finding('SEN-MAN-001', 'medium', 'manifest', 'package.json 无法解析(JSON 语法错误)', 'package.json'))
    return {
      manifest: { ok: false, name: String(pkg.name ?? ''), version: '', isBundle: false, patch: '', license: '', description: '' },
      findings,
    }
  }

  const name = String(pkg.name ?? '')
  const version = String(pkg.version ?? '')
  const isBundle = Boolean(pkg.dsh?.bundle)
  const patchRel = isBundle ? String(pkg.dsh.bundle.patch ?? '') : ''
  const license = String(pkg.license ?? '')
  const description = String(pkg.description ?? '')

  if (!isBundle) {
    findings.push(finding('SEN-MAN-002', 'high', 'manifest', '不是 DSH bundle(缺少 dsh.bundle 声明)', 'package.json', 1,
      '若目标是 DSH 插件,补上 dsh.bundle.patch 声明;否则此仓库无法以插件形式安装。'))
  }

  if (isBundle && patchRel) {
    let patchAbs
    try {
      // containment:patch 路径必须解析在包根之内。
      patchAbs = resolveInside(root, patchRel)
    } catch {
      findings.push(finding('SEN-MAN-009', 'critical', 'manifest',
        `dsh.bundle.patch 路径逃逸扫描根目录:${patchRel}`, 'package.json', 1,
        '拒绝该包或修复 manifest 路径;所有路径必须解析在包根目录之内。'))
      patchAbs = null
    }
    if (patchAbs !== null && !existsSync(patchAbs)) {
      findings.push(finding('SEN-MAN-003', 'high', 'manifest', `声明的 patch 文件不存在:${patchRel}`, 'package.json', 1,
        '核对 files 列表与 patch 路径。'))
    } else if (patchAbs !== null) {
      const patchText = readMaybe(patchAbs) ?? ''
      const rows = parsePatchRows(patchText)
      if (rows.length === 0) {
        findings.push(finding('SEN-MAN-004', 'medium', 'manifest', 'patch 为空或无法解析出任何行(id + name)', patchRel))
      }
      for (const row of rows) {
        // A row with neither id nor name is malformed; a row with only id is a
        // legitimate config/disabled override of a base row.
        if (!row.id && !row.name) {
          findings.push(finding('SEN-MAN-004', 'medium', 'manifest', 'patch 中存在缺少 id 与 name 的行', patchRel))
          continue
        }
        if (!row.name) continue
        if (row.name.startsWith('cordis:') || row.name.startsWith('@deepseek-ai/')) continue
        let entry
        try {
          entry = resolvePatchEntry(root, row.name, name)
        } catch {
          findings.push(finding('SEN-MAN-009', 'critical', 'manifest',
            `patch 入口名逃逸扫描根目录:${row.name}`, patchRel, 1,
            '拒绝该包或修复 manifest 路径;所有路径必须解析在包根目录之内。'))
          continue
        }
        if (entry === null) {
          findings.push(finding('SEN-MAN-005', 'medium', 'manifest', `patch 引用的插件模块无法解析:${row.name}`, patchRel))
          continue
        }
        if (!hasExportContract(entry)) {
          findings.push(finding('SEN-MAN-006', 'high', 'manifest', `插件入口无效(缺少 name 或 apply 导出):${row.name}`, row.name.replace(/\\/g, '/')))
        }
      }
    }
  }

  if (!license) {
    findings.push(finding('SEN-MAN-007', 'low', 'hygiene', '缺少许可证(license 字段)', 'package.json'))
  }
  if (!description) {
    findings.push(finding('SEN-MAN-008', 'low', 'hygiene', '缺少描述(description 字段)', 'package.json'))
  }

  const manifest = {
    ok: findings.every((f) => f.severity !== 'high' && f.severity !== 'critical'),
    name,
    version,
    isBundle,
    patch: patchRel,
    license,
    description,
  }
  return { manifest, findings }
}
