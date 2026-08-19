/**
 * 专业版 Phase-1 测试:扫描完整性 / scan mode / 大文件 lite / 路径 containment /
 * 严格入口契约 / secret 脱敏 / 语义引擎(SEN-AGENT)/ 版本单一来源。
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { scan, scanProfile, VERSION, semanticScan } from '../engine/index.js'
import { resolveInside, isInsideRoot, PathEscapeError } from '../engine/path-safety.js'
import { redactSecrets } from '../engine/redact.js'
import { main } from '../bin/sentinel.mjs'

const ids = (report) => new Set(report.findings.map((f) => f.id))

// ─────────────────────────── 扫描完整性 ───────────────────────────

test('maxFindings 只限报告条数,不提前停止分析', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'prof-complete-'))
  try {
    for (let f = 0; f < 4; f += 1) {
      const lines = []
      for (let i = 0; i < 8; i += 1) lines.push(`fetch('https://api.example.com/x${f}-${i}')`)
      writeFileSync(join(tmp, `f${f}.js`), lines.join('\n') + '\n')
    }
    const report = await scan(tmp, { maxFindings: 10 })
    const s = report.summary
    assert.ok(s.findingsTotal > 10, `findingsTotal=${s.findingsTotal} 应大于 10`)
    assert.equal(s.findingsReturned, 10)
    assert.equal(s.findingsTruncated, true)
    assert.equal(s.scanComplete, true)
    assert.equal(s.filesAnalyzed, 4, '全部文件都被分析')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('不完整扫描(maxFiles 截断)强制标记且不能显示 safe', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'prof-incomplete-'))
  try {
    for (let f = 0; f < 3; f += 1) writeFileSync(join(tmp, `f${f}.js`), 'const x = 1\n')
    const report = await scan(tmp, { maxFiles: 1 })
    const s = report.summary
    assert.equal(s.scanComplete, false)
    assert.equal(s.incompleteScan, true)
    assert.notEqual(s.verdict, 'safe', '不完整扫描绝不能显示 clean')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── scan mode ───────────────────────────

test('package mode 扫描 dist/build 构建产物,source mode 跳过', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'prof-mode-'))
  try {
    mkdirSync(join(tmp, 'dist'), { recursive: true })
    mkdirSync(join(tmp, 'src'), { recursive: true })
    writeFileSync(join(tmp, 'src', 'index.js'), "export const name = 'x'\nexport function apply() {}\n")
    writeFileSync(join(tmp, 'dist', 'index.js'), "exec('rm -rf $HOME')\n")
    const src = await scan(tmp, { mode: 'source' })
    assert.ok(!ids(src).has('SEN-FS-001'), 'source mode 跳过 dist')
    const pkg = await scan(tmp, { mode: 'package' })
    assert.ok(ids(pkg).has('SEN-FS-001'), 'package mode 必须扫描 dist')
    assert.equal(pkg.scanCoverage.buildFiles, 1)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── 大文件 lite ───────────────────────────

test('大文件不跳过:lite 分析并标记 analysisMode', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'prof-large-'))
  try {
    const pad = '// padding line\n'.repeat(45000) // ~585KB
    writeFileSync(join(tmp, 'bundle.js'), pad + "eval(atob('eA=='))\n")
    const report = await scan(tmp, { maxBytesPerFile: 512 * 1024 })
    assert.equal(report.scanCoverage.largeFiles, 1)
    const lite = report.findings.find((f) => f.analysisMode === 'large-file-lite')
    assert.ok(lite, '大文件命中应标记 large-file-lite')
    assert.ok(lite.id.startsWith('SEN-EXEC'), `lite 应命中执行类规则,got ${lite.id}`)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── 路径 containment ───────────────────────────

test('manifest 路径逃逸 → SEN-MAN-009', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'prof-escape-'))
  try {
    writeFileSync(join(tmp, 'package.json'), JSON.stringify({
      name: 'evil', version: '0.0.1',
      dsh: { bundle: { patch: '../../outside.yml' } },
    }))
    const report = await scan(tmp)
    assert.ok(ids(report).has('SEN-MAN-009'), 'patch 逃逸必须命中 SEN-MAN-009')

    // patch 入口名逃逸
    const tmp2 = mkdtempSync(join(tmpdir(), 'prof-escape2-'))
    writeFileSync(join(tmp2, 'package.json'), JSON.stringify({
      name: 'evil2', version: '0.0.1', dsh: { bundle: { patch: './cordis.patch.yml' } },
    }))
    writeFileSync(join(tmp2, 'cordis.patch.yml'),
      "- insert:\n    - id: e\n      name: '../escape'\n")
    const report2 = await scan(tmp2)
    assert.ok(ids(report2).has('SEN-MAN-009'), 'patch 入口名逃逸必须命中 SEN-MAN-009')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('path-safety 工具函数', () => {
  const root = 'C:/proj/pkg'
  assert.equal(isInsideRoot(root, 'C:/proj/pkg/lib/index.js'), true)
  assert.equal(isInsideRoot(root, 'C:/proj/pkg'), true)
  assert.equal(isInsideRoot(root, 'C:/proj/other/x.js'), false)
  assert.equal(isInsideRoot(root, 'C:/proj/pkgx/evil.js'), false, '前缀相似但不是子目录')
  assert.equal(resolveInside(root, './lib/x.js'), 'C:/proj/pkg/lib/x.js'.replace(/\//g, '\\'))
  assert.throws(() => resolveInside(root, '../../etc/passwd'), PathEscapeError)
})

// ─────────────────────────── 严格入口契约 ───────────────────────────

test('入口契约必须同时具备 name 与 apply', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'prof-contract-'))
  try {
    const mk = async (entryBody, expectInvalid) => {
      mkdirSync(join(tmp, 'pkg'), { recursive: true })
      writeFileSync(join(tmp, 'pkg', 'package.json'), JSON.stringify({
        name: 'pkg', version: '0.0.1', main: 'index.js',
        dsh: { bundle: { patch: './cordis.patch.yml' } },
      }))
      writeFileSync(join(tmp, 'pkg', 'cordis.patch.yml'), "- insert:\n    - id: p\n      name: 'pkg'\n")
      writeFileSync(join(tmp, 'pkg', 'index.js'), entryBody)
      const report = await scan(join(tmp, 'pkg'))
      assert.equal(ids(report).has('SEN-MAN-006'), expectInvalid, entryBody.slice(0, 40))
      rmSync(join(tmp, 'pkg'), { recursive: true, force: true })
    }
    await mk("export const name = 'x'\n", true)                                   // 只有 name
    await mk('export function apply() {}\n', true)                                // 只有 apply
    await mk("module.exports = { notName: 1 }\n", true)                           // CJS 无键
    await mk("module.exports = { name: 'x', apply() {} }\n", false)               // CJS 双键
    await mk("exports.default = { name: 'x', apply() {} }\n", false)              // CJS default 双键
    await mk("export const name = 'x'\nexport function apply() {}\n", false)      // ESM 双导出
    await mk("export default { name: 'x', apply(ctx) {} }\n", false)              // default 对象
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── secret 脱敏 ───────────────────────────

test('secret 必须脱敏:报告不包含完整 secret', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'prof-redact-'))
  try {
    const secret = 'sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    writeFileSync(join(tmp, 'k.js'), `const key = '${secret}'\n`)
    const report = await scan(join(tmp, 'k.js'))
    const f = report.findings.find((x) => x.id === 'SEN-CRED-003')
    assert.ok(f, '硬编码密钥应命中')
    assert.equal(f.redacted, true)
    assert.ok(!f.snippet.includes(secret.slice(10)), 'snippet 不得含完整 secret')
    assert.ok(f.snippet.includes('****'), 'snippet 应含脱敏标记')
    assert.ok(f.secretFingerprints.length > 0, '应有指纹')
    assert.ok(!JSON.stringify(report).includes(secret), '整个报告不得含完整 secret')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

test('redactSecrets 工具函数', () => {
  const r = redactSecrets('token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij key=sk-proj-12345678901234567890')
  assert.equal(r.redacted, true)
  assert.ok(!r.text.includes('ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'))
  assert.ok(r.fingerprints.length >= 2)
  assert.ok(r.fingerprints[0].length === 24)
})

// ─────────────────────────── 语义引擎(SEN-AGENT)───────────────────────────

test('SEN-AGENT-001:args.command → exec(positive)', async () => {
  const src = `
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'run',
    async execute(args) {
      exec(args.command)
    },
  }))
}`
  const f = semanticScan(src, 'plugin/index.js')
  assert.ok(f.some((x) => x.ruleId === 'SEN-AGENT-001' && x.severity === 'critical'))
  const hit = f.find((x) => x.ruleId === 'SEN-AGENT-001')
  assert.deepEqual(hit.source, { type: 'tool-argument', name: 'args.command' })
  assert.equal(hit.sink.callee, 'exec')
})

test('SEN-AGENT-001:安全形式不误报(negative)', async () => {
  const src = `
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'gitStatus',
    async execute() {
      spawn('git', ['status'])
    },
  }))
}`
  const f = semanticScan(src, 'plugin/index.js')
  assert.equal(f.filter((x) => x.ruleId === 'SEN-AGENT-001').length, 0)
})

test('SEN-AGENT-001:别名 + 多步变量传播(evasion)', async () => {
  const src = `
const { exec: run } = require('child_process')
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'x',
    async execute(args) {
      const a = args.command
      const b = a
      run(b)
    },
  }))
}`
  const f = semanticScan(src, 'plugin/index.js')
  assert.ok(f.some((x) => x.ruleId === 'SEN-AGENT-001' && x.sink.callee === 'run'), '别名 run(b) 必须命中')
})

test('SEN-AGENT-002/003/004:args → fs/网络', async () => {
  const src = `
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'io',
    async execute(args) {
      const data = readFileSync(args.path)
      writeFileSync(args.out, data)
      fetch(args.url)
    },
  }))
}`
  const f = semanticScan(src, 'plugin/index.js')
  assert.ok(f.some((x) => x.ruleId === 'SEN-AGENT-002'), 'args.path → readFile')
  assert.ok(f.some((x) => x.ruleId === 'SEN-AGENT-003'), 'args.out → writeFile')
  assert.ok(f.some((x) => x.ruleId === 'SEN-AGENT-004'), 'args.url → fetch')
})

test('语义引擎与完整扫描集成:真实文件命中', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'prof-semantic-'))
  try {
    mkdirSync(join(tmp, 'src'), { recursive: true })
    writeFileSync(join(tmp, 'src', 'index.js'), `
export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'run',
    async execute(args) {
      exec(args.command)
    },
  }))
}`)
    const report = await scan(join(tmp, 'src'))
    const f = report.findings.find((x) => x.id === 'SEN-AGENT-001')
    assert.ok(f, '完整扫描应包含语义命中')
    assert.equal(f.line, 6, '命中行应为 exec 调用行')
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})

// ─────────────────────────── 版本单一来源 ───────────────────────────

test('VERSION 单一来源:与 package.json 一致', async () => {
  const { readFileSync } = await import('node:fs')
  const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
  assert.equal(VERSION, pkg.version)
})

// ─────────────────────────── CLI ───────────────────────────

test('CLI:--mode package 生效,不完整扫描标记输出', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'prof-cli-'))
  try {
    mkdirSync(join(tmp, 'dist'), { recursive: true })
    writeFileSync(join(tmp, 'dist', 'a.js'), "exec('rm -rf $HOME')\n")
    writeFileSync(join(tmp, 'root.js'), 'const x = 1\n')
    const capture = () => {
      const buf = { out: '' }
      const stream = { write(s) { buf.out += s }, isTTY: false }
      return { stdout: stream, stderr: stream, buf }
    }
    const io1 = capture()
    const code1 = await main([tmp, '--mode', 'package', '--json'], io1)
    const r1 = JSON.parse(io1.buf.out)
    assert.ok(r1.findings.some((f) => f.id === 'SEN-FS-001'), 'package mode 扫到 dist 命中')

    const io2 = capture()
    await main([tmp, '--mode', 'source', '--json'], io2)
    const r2 = JSON.parse(io2.buf.out)
    assert.ok(!r2.findings.some((f) => f.id === 'SEN-FS-001'), 'source mode 跳过 dist')

    // 不完整扫描文本输出带 INCOMPLETE 标记(package mode,maxFiles=1 截断)
    const io3 = capture()
    await main([tmp, '--mode', 'package', '--max-files', '1'], io3)
    assert.match(io3.buf.out, /INCOMPLETE SCAN/)
    assert.equal(code1, 1)
  } finally {
    rmSync(tmp, { recursive: true, force: true })
  }
})
