/**
 * dsh-sentinel — DSH plugin entry.
 *
 * Registers two model-facing tools:
 *   - sentinel_scan           : audit any directory / plugin repo
 *   - sentinel_scan_profile   : audit every user-installed third-party plugin
 *                               in a profile ($DSH_HOME/profiles/<name>)
 *
 * The scanner engine is dependency-free and read-only: it never executes any
 * of the scanned code.
 *
 * Loader protocol: export `name` + `apply(ctx)`; peer deps
 * (@deepseek-ai/cordis, @deepseek-ai/dsh-tools) resolve from the installation
 * via the launcher-maintained flat module fallback.
 */

import { defineTool } from '@deepseek-ai/dsh-tools'
import { scan, scanProfile, VERSION } from '../engine/index.js'

export const name = 'sentinel'

/** The tools registry must be ready before we register. */
export const inject = ['tools']

const OUTPUT_SCHEMA = { type: 'json' }

/** Project a canonical report into model-facing text.
 *
 * The DSH tools framework calls `output.render(args, value)` — the canonical
 * value is the SECOND argument.
 */
function renderReport(_args, value) {
  const s = value.summary
  const emoji = { safe: '✅', review: '👀', risky: '⚠️', dangerous: '🚨' }[s.verdict] ?? '❓'
  const lines = []
  lines.push(`${emoji} dsh-sentinel ${value.version} — ${s.verdict.toUpperCase()} (risk score ${s.score}/100)`)
  if (s.scanComplete === false) {
    lines.push('⚠ INCOMPLETE SCAN — 扫描不完整(文件数/大小受限),结果仅代表已分析部分')
  }
  lines.push(`scanned ${s.filesAnalyzed}/${s.filesDiscovered} files · ${s.findingsTotal} findings (returned ${s.findingsReturned}): ` +
    `critical ${s.bySeverity.critical} · high ${s.bySeverity.high} · medium ${s.bySeverity.medium} · low ${s.bySeverity.low} · info ${s.bySeverity.info}`)
  const m = value.manifest
  if (m?.name) {
    lines.push(`manifest: ${m.name}${m.version ? `@${m.version}` : ''} · isBundle=${m.isBundle}${m.patch ? ` · patch=${m.patch}` : ''}`)
  }
  if (value.target.kind === 'profile') {
    lines.push(`profile: ${value.profile.name} · third-party plugins scanned: ${value.profile.pluginsScanned.length}` +
      (value.profile.pluginsSkipped.length > 0 ? ` (skipped ${value.profile.pluginsSkipped.length} built-ins/others)` : ''))
  }
  const top = value.findings.filter((f) => f.severity === 'critical' || f.severity === 'high').slice(0, 12)
  if (top.length > 0) {
    lines.push('')
    lines.push('Top findings:')
    for (const f of top) {
      const loc = f.package ? `${f.package}:${f.file}:${f.line}` : `${f.file}:${f.line}`
      const tag = f.testFile ? ' (test)' : ''
      lines.push(`  [${f.severity}] ${f.id} ${loc}${tag} — ${f.message}`)
    }
  }
  if (value.findings.length > top.length) {
    lines.push(`  … and ${value.findings.length - top.length} more findings (see the report JSON for all ${s.totalFindings})`)
  }
  if (s.verdict !== 'safe') {
    lines.push('')
    lines.push('Advice: review every finding before installing; heuristic scan, not a security guarantee.')
  }
  return [{ type: 'text', text: lines.join('\n') }]
}

export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'sentinel_scan',
    description:
      'Security & health audit of a directory or plugin repository (static heuristic scan: code execution, ' +
      'credential access, exfiltration endpoints, obfuscation, install scripts, DSH bundle manifest compliance). ' +
      'Returns a structured report with risk score 0-100 and verdict safe/review/risky/dangerous. ' +
      'Read-only: never executes the scanned code. Use before installing or recommending any third-party DSH plugin.',
    parameters: {
      path: {
        type: 'string',
        required: true,
        description: 'Absolute or workspace-relative path to the plugin directory or repository to audit.',
      },
      maxFiles: {
        type: 'integer',
        description: 'Optional cap on scanned files (default 3000).',
      },
      mode: {
        type: 'string',
        description: 'Scan mode: source (default, skips dist/build) | package (includes build artifacts) | profile.',
      },
    },
    output: {
      schema: OUTPUT_SCHEMA,
      render: renderReport,
    },
    timeoutMs: 120000,
    async execute(args) {
      return scan(args.path, { maxFiles: args.maxFiles ?? undefined, mode: args.mode ?? undefined })
    },
  }))

  ctx.tools.register(defineTool({
    name: 'sentinel_scan_profile',
    description:
      'Audit every user-installed third-party plugin in a DSH profile ($DSH_HOME/profiles/<name>/node_modules). ' +
      'Trusted @deepseek-ai built-ins are skipped — the audit targets the third-party attack surface. ' +
      'Returns the same structured report as sentinel_scan with a per-package finding tag.',
    parameters: {
      profile: {
        type: 'string',
        required: true,
        description: 'Profile name to audit (e.g. "web"). Defaults to $DSH_HOME/profiles/<name>.',
      },
      maxPlugins: {
        type: 'integer',
        description: 'Optional cap on scanned plugins (default 12).',
      },
    },
    output: {
      schema: OUTPUT_SCHEMA,
      render: renderReport,
    },
    timeoutMs: 180000,
    async execute(args) {
      return scanProfile(args.profile, { maxPlugins: args.maxPlugins ?? undefined })
    },
  }))

  ctx.logger?.info(`[sentinel] dsh-sentinel ${VERSION} loaded — sentinel_scan / sentinel_scan_profile registered`)
}
