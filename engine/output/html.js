/**
 * HTML 报告(Phase 8):单文件、无外部依赖、可直接分享。
 * 必须明确显示 Scan complete: YES / NO。
 */

import { VERSION } from '../version.js'

const VERDICT_EMOJI = { safe: '✅', review: '👀', risky: '⚠️', dangerous: '🚨' }

export function toHtml(report) {
  const s = report.summary
  const rows = (report.findings ?? []).map((f) => `
    <tr class="sev-${f.severity}">
      <td>${escapeHtml(f.id)}</td>
      <td>${f.severity}</td>
      <td>${f.confidence ?? 'medium'}</td>
      <td>${escapeHtml(f.message)}</td>
      <td>${escapeHtml(f.file)}:${f.line ?? 1}</td>
      <td><code>${escapeHtml(f.snippet ?? '')}</code></td>
      <td>${escapeHtml(f.recommendation ?? '')}</td>
    </tr>`).join('')

  const pluginsRows = (report.profile?.plugins ?? []).map((p) => `
    <tr><td>${escapeHtml(p.name)}</td><td>${p.version}</td><td>${p.direct ? 'direct' : (p.transitive ? 'transitive' : 'other')}</td>
    <td>${p.dependencies}</td><td>${p.findings}</td></tr>`).join('')

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>dsh-sentinel 安全审计报告 — ${s.verdict.toUpperCase()}</title>
<style>
body{font-family:system-ui,-apple-system,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#1f2328}
h1{font-size:22px}.banner{padding:16px 20px;border-radius:10px;font-weight:700;font-size:18px}
.banner.safe{background:#e6f4ea;color:#137333}.banner.review{background:#fef7e0;color:#b06000}
.banner.risky{background:#fdecea;color:#c5221f}.banner.dangerous{background:#c5221f;color:#fff}
table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}
th,td{border:1px solid #d0d7de;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f6f8fa}.sev-critical{background:#fdecea}.sev-high{background:#fff4e5}
code{white-space:pre-wrap;word-break:break-all;font-size:12px}
.meta{color:#57606a;font-size:13px}.warn{color:#c5221f;font-weight:700}
</style>
</head>
<body>
<h1>${VERDICT_EMOJI[s.verdict] ?? ''} dsh-sentinel 安全审计报告 <span class="meta">v${escapeHtml(VERSION)}</span></h1>
<div class="banner ${s.verdict}">${s.verdict.toUpperCase()} — risk score ${s.score}/100</div>
<p class="meta">
  target: ${escapeHtml(report.target.path)}<br>
  scan complete: <b>${s.scanComplete ? 'YES' : 'NO'}</b>${s.scanComplete ? '' : ' <span class="warn">⚠ INCOMPLETE SCAN — 结果仅代表已分析部分</span>'}<br>
  files: ${s.filesAnalyzed}/${s.filesDiscovered} analyzed (build ${report.scanCoverage?.buildFiles ?? 0} · large-lite ${report.scanCoverage?.largeFiles ?? 0} · binary ${report.scanCoverage?.binaryFiles ?? 0})<br>
  findings: ${s.findingsTotal} total · returned ${s.findingsReturned}${s.findingsTruncated ? ' · <b>truncated</b>' : ''}<br>
  severity: critical ${s.bySeverity.critical} · high ${s.bySeverity.high} · medium ${s.bySeverity.medium} · low ${s.bySeverity.low} · info ${s.bySeverity.info}<br>
  ${report.manifest?.name ? `manifest: ${escapeHtml(report.manifest.name)}@${report.manifest.version} · isBundle=${report.manifest.isBundle}<br>` : ''}
  scanned at: ${escapeHtml(report.scannedAt)}
</p>
${report.profile?.plugins?.length ? `<h2>Plugins(${report.profile.plugins.length})</h2>
<table><tr><th>name</th><th>version</th><th>type</th><th>deps</th><th>findings</th></tr>${pluginsRows}</table>` : ''}
<h2>Findings (${report.findings.length})</h2>
<table>
<tr><th>ID</th><th>severity</th><th>conf</th><th>message</th><th>location</th><th>snippet</th><th>recommendation</th></tr>
${rows || '<tr><td colspan="7">当前启用规则未发现问题;这不等价于插件已被证明安全。</td></tr>'}
</table>
<p class="meta">启发式静态扫描 ≠ 安全保证。本报告由 dsh-sentinel ${escapeHtml(VERSION)} 生成。</p>
</body>
</html>`
}

function escapeHtml(text) {
  return String(text ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}
