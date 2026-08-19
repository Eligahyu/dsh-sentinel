/**
 * 安装前审计(Phase 3):npm:<pkg> / audit-install 的核心。
 *
 * 流程:获取元数据 → 下载 tarball → integrity 校验 → 隔离解包(不执行任何脚本)
 * → 静态扫描(package mode)→ 供应链信息 → 风险判定 ALLOW / REVIEW / BLOCK-RECOMMENDED。
 *
 * 红线:不运行 npm install,不执行 preinstall/install/postinstall/prepare,
 * 不把包代码上传到任何第三方。
 */

import { acquireNpmPackage } from './acquire.js'
import { downloadTarball, extractTarball } from './tarball.js'
import { scan } from '../index.js'

export const AUDIT_VERDICTS = ['ALLOW', 'REVIEW', 'BLOCK-RECOMMENDED']

/** 风险分 → 安装建议。绝不说 "malicious",只给建议。 */
export function auditVerdictFor(score) {
  if (score <= 19) return 'ALLOW'
  if (score <= 49) return 'REVIEW'
  return 'BLOCK-RECOMMENDED'
}

/**
 * 可复用 API:安装前审计任意 npm 包(§5.3 预留的 dsh plugin add 钩子接口)。
 * @param {string} spec - 'name' 或 'name@version'
 * @param {object} opts - {maxFiles, maxFindings, advisories, provenance}
 * @returns {Promise<object>} {report, audit: {package, version, verdict, tarballSha256, integrityOk, ...}}
 */
export async function auditPackageBeforeInstall(spec, opts = {}) {
  const meta = await acquireNpmPackage(spec)
  const dl = await downloadTarball(meta.dist.tarball, meta.dist.integrity)
  const { dir, cleanup } = await extractTarball(dl.tarballPath)
  try {
    const report = await scan(dir, { mode: 'package', ...opts })
    const audit = {
      package: meta.name,
      version: meta.version,
      verdict: auditVerdictFor(report.summary.score),
      tarballSha256: dl.sha256,
      integrityOk: dl.integrityOk,
      ...(dl.integrityReason ? { integrityReason: dl.integrityReason } : {}),
      dependencyCount: Object.keys(meta.dependencies ?? {}).length,
      installScripts: Object.keys(meta.scripts ?? {}).filter((s) =>
        ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'].includes(s)),
      ...(opts.provenance ? { provenance: meta.attestations } : {}),
    }
    report.supplyChain = {
      package: meta.name,
      version: meta.version,
      tarballSha256: dl.sha256,
      integrity: meta.dist.integrity,
      dependencyCount: audit.dependencyCount,
      installScripts: audit.installScripts,
      ...(opts.provenance ? { provenance: meta.attestations } : {}),
    }
    // OSV 漏洞查询(默认关闭;仅上传包名+版本)
    if (opts.advisories) {
      const { queryOsv, attachAdvisories } = await import('../supplychain/osv.js')
      attachAdvisories(report, await queryOsv(meta.name, meta.version))
    }
    return { report, audit }
  } finally {
    cleanup()
  }
}

/**
 * CLI/工具入口:解析 'npm:<pkg>' 或裸包名规格。
 * @returns {Promise<object>} auditPackageBeforeInstall 的结果
 */
export async function auditNpmSpec(spec, opts = {}) {
  const clean = spec.startsWith('npm:') ? spec.slice(4) : spec
  return auditPackageBeforeInstall(clean, opts)
}

/** 仅获取并解包(供源码-发布包 diff 使用),不执行完整审计。 */
export async function acquirePackageDir(spec) {
  const clean = spec.startsWith('npm:') ? spec.slice(4) : spec
  const meta = await acquireNpmPackage(clean)
  const dl = await downloadTarball(meta.dist.tarball, meta.dist.integrity)
  const { dir, cleanup } = await extractTarball(dl.tarballPath)
  return { dir, cleanup, meta, dl }
}
