/**
 * 安装前审计(Phase 3):npm:<pkg> / audit-install 的核心。
 *
 * 流程:获取元数据 → 下载 tarball → integrity 校验 → 隔离解包(不执行任何脚本,
 * 安全 tar 解析:防 traversal / symlink / tar bomb)→ 静态扫描(package mode)
 * → 供应链信息 → 风险判定 ALLOW / REVIEW / BLOCK-RECOMMENDED。
 *
 * 红线:不运行 npm install,不执行 preinstall/install/postinstall/prepare,
 * 不把包代码上传到任何第三方。
 */

import { acquireNpmPackage } from './acquire.js'
import { downloadTarball, extractTarball, TarSafetyError } from './tarball.js'
import { detectLockfile, countDependencies } from '../supplychain/lockfile.js'
import { scan } from '../index.js'
import { buildReport } from '../report.js'

export const AUDIT_VERDICTS = ['ALLOW', 'REVIEW', 'BLOCK-RECOMMENDED']

/** 风险分 → 安装建议。绝不说 "malicious",只给建议。 */
export function auditVerdictFor(score) {
  if (score <= 19) return 'ALLOW'
  if (score <= 49) return 'REVIEW'
  return 'BLOCK-RECOMMENDED'
}

/** tarball 被安全层阻止(恶意打包)时的最小报告。 */
function buildBlockedReport(meta, dl, error) {
  const findings = [{
    ruleId: 'SEN-SUPPLY-005',
    severity: 'critical',
    category: 'supplychain',
    confidence: 'high',
    message: `tarball 解包被安全层阻止(${error.code ?? 'unsafe-tarball'})`,
    file: 'package',
    line: 1,
    snippet: String(error?.message ?? error).slice(0, 240),
    recommendation: '拒绝安装;路径逃逸/链接条目/超限压缩是恶意或异常打包的典型特征。',
  }]
  const report = buildReport({
    kind: 'path',
    path: '(quarantine-blocked)',
    name: meta.name,
    findings,
    findingsTotal: findings.length,
    filesAnalyzed: 0,
    filesDiscovered: 1,
    scanComplete: false,
    scanCoverage: { sourceFiles: 0, buildFiles: 0, binaryFiles: 0, largeFiles: 0, parseFailures: 0, hardSkippedFiles: 0 },
    manifest: { ok: false, name: meta.name, version: meta.version, isBundle: false, patch: '', license: '', description: '' },
    filesSkipped: { binary: 0, big: 0, dirs: 0, ignored: 0 },
    scanMs: 0,
  })
  report.supplyChain = {
    package: meta.name,
    version: meta.version,
    tarballSha256: dl.sha256,
    integrity: 'blocked-before-extract',
    dependencyCount: Object.keys(meta.dependencies ?? {}).length,
    installScripts: [],
  }
  return report
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

  // 解包被安全层阻止(traversal / symlink / tar bomb)→ BLOCK + scanComplete=false。
  let extraction
  try {
    extraction = await extractTarball(dl.tarballPath)
  } catch (error) {
    if (error instanceof TarSafetyError) {
      const report = buildBlockedReport(meta, dl, error)
      const audit = {
        package: meta.name,
        version: meta.version,
        verdict: 'BLOCK-RECOMMENDED',
        tarballSha256: dl.sha256,
        integrityOk: dl.integrityOk,
        ...(dl.integrityReason ? { integrityReason: dl.integrityReason } : {}),
        dependencyCount: Object.keys(meta.dependencies ?? {}).length,
        installScripts: Object.keys(meta.scripts ?? {}).filter((s) =>
          ['preinstall', 'install', 'postinstall', 'prepare', 'prepublish'].includes(s)),
        extractionError: String(error?.message ?? error),
      }
      return { report, audit }
    }
    throw error
  }

  const { dir, cleanup } = extraction
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

    // integrity 不匹配 → SEN-SUPPLY-004 + 至少 REVIEW(不能 ALLOW)。
    if (!dl.integrityOk) {
      report.findings.unshift({
        id: 'SEN-SUPPLY-004',
        severity: 'high',
        category: 'supplychain',
        confidence: 'high',
        message: `tarball integrity 与 registry 声明不一致(${dl.integrityReason ?? 'sha512-mismatch'})`,
        file: 'package.json',
        line: 1,
        snippet: 'integrity verification failed',
        recommendation: '拒绝安装;从可信渠道重新获取并复核来源。',
      })
      report.summary.findingsTotal += 1
      report.summary.totalFindings += 1
      report.summary.bySeverity.high = (report.summary.bySeverity.high ?? 0) + 1
      report.summary.byCategory.supplychain = (report.summary.byCategory.supplychain ?? 0) + 1
      report.summary.byContext.source = (report.summary.byContext.source ?? 0) + 1
      const s = Math.min(100, report.summary.score + 20)
      report.summary.score = s
      const { verdictFor } = await import('../report.js')
      report.summary.verdict = verdictFor(s).label
      if (audit.verdict === 'ALLOW') audit.verdict = 'REVIEW'
    }

    // lockfile 识别与依赖统计(§23)。
    const lockfileName = detectLockfile(dir)
    if (lockfileName) {
      report.supplyChain.lockfile = lockfileName
      Object.assign(report.supplyChain, countDependencies(dir, lockfileName))
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
