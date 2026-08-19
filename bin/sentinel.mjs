#!/usr/bin/env node
/**
 * dsh-sentinel CLI — standalone plugin security scanner.
 *
 * Usage:
 *   dsh-sentinel <path> [--json] [--out <file>] [--max-files <n>]
 *   dsh-sentinel --profile <name> [--json] [--out <file>] [--max-plugins <n>]
 *   dsh-sentinel --rules
 *
 * Exit codes (CI-friendly):
 *   0  verdict safe | review
 *   1  verdict risky | dangerous
 *   2  usage error / scan failure
 */

import { scan, scanProfile, RULES, VERSION } from '../engine/index.js'
import { SEVERITY_ORDER } from '../engine/rules.js'

const VERDICT_EMOJI = { safe: '✅', review: '👀', risky: '⚠️', dangerous: '🚨' }
const SEV_LABEL = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'low', info: 'info' }

function color(code, text, enabled) {
  return enabled ? `\u001b[${code}m${text}\u001b[0m` : text
}

function usage(out) {
  out.write(`dsh-sentinel ${VERSION} — 给 DSH 插件拍 X 光 / plugin security & health scanner

Usage:
  dsh-sentinel <path>                 scan a plugin repo/directory (or single file)
  dsh-sentinel --profile <name>       audit third-party plugins in a DSH profile
  dsh-sentinel --rules                print the rule catalog

Options:
  --json          emit the canonical report as JSON
  --out <file>    write the report to a file (JSON), print a summary to stdout
  --max-files <n> cap scanned files (default 3000)
  --max-plugins <n> cap plugins scanned per profile (default 12)
  --mode <mode>   scan mode: source(默认,跳过 dist/build) | package(扫构建产物) | profile
  -h, --help      show this help

Exit codes: 0 = safe/review, 1 = risky/dangerous, 2 = usage error.
`)
}

function formatText(report, out) {
  const s = report.summary
  const tty = Boolean(out.isTTY)
  const emoji = VERDICT_EMOJI[s.verdict] ?? '❓'
  const sevColor = { safe: 32, review: 33, risky: 33, dangerous: 31 }[s.verdict] ?? 0
  const banner = `${emoji} ${color(sevColor, s.verdict.toUpperCase(), tty)} — risk score ${s.score}/100`
  out.write(`\n${banner}\n`)
  out.write('─'.repeat(Math.min(72, banner.length + 12)) + '\n')
  if (s.scanComplete === false) {
    out.write(`${color(31, '⚠ INCOMPLETE SCAN — 扫描不完整,结果仅代表已分析部分', tty)}\n`)
  }
  out.write(`target        ${report.target.kind === 'profile' ? `profile "${report.target.name}"` : report.target.path}\n`)
  const m = report.manifest
  if (m?.name) out.write(`manifest      ${m.name}${m.version ? `@${m.version}` : ''} · isBundle=${m.isBundle}${m.patch ? ` · patch=${m.patch}` : ''}\n`)
  if (report.target.kind === 'profile') {
    out.write(`plugins       ${report.profile.pluginsScanned.join(', ') || '(none)'}\n`)
    if (report.profile.pluginsSkipped.length > 0) out.write(`skipped       ${report.profile.pluginsSkipped.length} (built-ins / others)\n`)
  }
  out.write(`files         ${s.filesAnalyzed}/${s.filesDiscovered} analyzed` +
    ` (${report.scanCoverage?.buildFiles ?? 0} build · ${report.scanCoverage?.largeFiles ?? 0} large-lite · ${s.filesSkipped ?? 0} binary)\n`)
  out.write(`findings      ${s.findingsTotal} total(返回 ${s.findingsReturned}) · ` +
    SEVERITY_ORDER.map((sev) => `${SEV_LABEL[sev]} ${s.bySeverity[sev]}`).join(' · ') + '\n')
  out.write(`context       source ${s.byContext?.source ?? 0} · test ${s.byContext?.test ?? 0} (test 文件命中降一级计分)\n`)
  out.write(`categories    ` +
    Object.entries(s.byCategory).filter(([, n]) => n > 0).map(([c, n]) => `${c} ${n}`).join(' · ') + '\n')
  out.write(`scan time     ${s.scanMs} ms\n`)

  if (report.findings.length > 0) {
    out.write('\nfindings:\n')
    for (const f of report.findings) {
      const loc = f.package ? `${f.package}:${f.file}:${f.line}` : `${f.file}:${f.line}`
      const sev = SEV_LABEL[f.severity].padEnd(8)
      const sevCode = { critical: 31, high: 33, medium: 33, low: 0, info: 0 }[f.severity] ?? 0
      const tag = `${f.testFile ? ' (test)' : ''}${f.bundleFile ? ' (bundle)' : ''}${f.redacted ? ' (secret redacted)' : ''}`
      out.write(`  ${color(sevCode, sev, tty)} ${f.id} ${loc}${tag}\n`)
      out.write(`    ${f.message}\n`)
      if (f.snippet) out.write(`    ${f.snippet.slice(0, 120)}${f.snippet.length > 120 ? '…' : ''}\n`)
    }
    if (report.findings.length < s.findingsTotal) {
      out.write(`  … ${s.findingsTotal - report.findings.length} more findings(总数 ${s.findingsTotal})\n`)
    }
  } else {
    out.write('\n当前启用规则未发现问题;这不等价于插件已被证明安全。\n')
    out.write('No findings detected by enabled rules; this does not prove the plugin is safe.\n')
  }
  out.write('\n')
}

export async function main(argv, io = { stdout: process.stdout, stderr: process.stderr }) {
  const { stdout, stderr } = io
  const args = [...argv]
  const opts = { json: false, out: null, maxFiles: undefined, maxPlugins: undefined, configPath: null, includeBuiltins: false }
  const positional = []
  for (let i = 0; i < args.length; i += 1) {
    const a = args[i]
    switch (a) {
      case '--json': opts.json = true; break
      case '--out': opts.out = args[++i]; break
      case '--max-files': opts.maxFiles = Number(args[++i]); break
      case '--max-plugins': opts.maxPlugins = Number(args[++i]); break
      case '--config': opts.configPath = args[++i]; break
      case '--include-builtins': opts.includeBuiltins = true; break
      case '--rules': {
        for (const r of RULES) {
          stdout.write(`${r.id} [${r.severity.padEnd(8)}] ${r.category.padEnd(12)} ${r.name} — ${r.message}\n`)
        }
        return 0
      }
      case '--mode': {
        const mode = args[++i]
        if (!['source', 'package', 'profile'].includes(mode)) {
          stderr.write(`dsh-sentinel: --mode must be source|package|profile (got ${mode})\n`)
          return 2
        }
        opts.mode = mode
        break
      }
      case '-h': case '--help': usage(stdout); return 0
      default:
        if (a.startsWith('--profile')) {
          opts.profile = args[++i]
        } else if (a.startsWith('-')) {
          stderr.write(`dsh-sentinel: unknown option ${a}\n`)
          usage(stderr)
          return 2
        } else {
          positional.push(a)
        }
    }
  }

  const run = (async () => {
    // 配置:默认 ← sentinel.config.json ← CLI 覆盖
    const { loadConfig, mergeOverrides } = await import('../engine/config.js')
    const { config } = loadConfig({ configPath: opts.configPath })
    const effective = mergeOverrides(config, {
      mode: opts.mode,
      maxFiles: opts.maxFiles,
      includeBuiltins: opts.includeBuiltins ? true : undefined,
    })
    if (opts.profile !== undefined) {
      return scanProfile(opts.profile, {
        maxPlugins: opts.maxPlugins,
        maxFiles: effective.maxFiles,
        includeBuiltins: effective.includeBuiltins,
        trustedScopes: config.trustedScopes,
      })
    }
    if (positional.length === 0) {
      usage(stderr)
      return null
    }
    return scan(positional[0], { maxFiles: effective.maxFiles, mode: effective.mode })
  })()

  try {
    const result = await run
    if (result === null) return 2
    if (opts.out) {
      const { writeFileSync } = await import('node:fs')
      writeFileSync(opts.out, JSON.stringify(result, null, 2) + '\n')
      stdout.write(`report written to ${opts.out}\n`)
      formatText(result, stdout)
    } else if (opts.json) {
      stdout.write(JSON.stringify(result, null, 2) + '\n')
    } else {
      formatText(result, stdout)
    }
    return result.summary.verdict === 'risky' || result.summary.verdict === 'dangerous' ? 1 : 0
  } catch (error) {
    stderr.write(`dsh-sentinel: ${error?.message ?? String(error)}\n`)
    return 2
  }
}

// Direct execution (works on Windows too — compare via pathToFileURL).
import { pathToFileURL } from 'node:url'
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const code = await main(process.argv.slice(2))
  process.exit(code)
}
