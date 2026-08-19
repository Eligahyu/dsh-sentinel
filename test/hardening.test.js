// v0.4 final release hardening suite.
// Covers P0/P1 fixes from dsh-sentinel-v0.4-final-release-hardening.md.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { FindingBuffer, scanTree, collectFiles } from '../engine/scanner.js'
import { computeRuntimeEntries } from '../engine/index.js'
import { PathEscapeError, resolveInside } from '../engine/path-safety.js'

// ---- P0-1: FindingBuffer 反向淘汰 ----

test('buffer:critical 后 info 不得淘汰 critical', () => {
  const b = new FindingBuffer(1)
  b.add({ severity: 'critical', id: 'critical' })
  b.add({ severity: 'info', id: 'info' })
  const out = b.drain()
  assert.equal(out.length, 1)
  assert.equal(out[0].severity, 'critical')
})

test('buffer:info 后 critical 必须替换 info', () => {
  const b = new FindingBuffer(1)
  b.add({ severity: 'info', id: 'info' })
  b.add({ severity: 'critical', id: 'critical' })
  const out = b.drain()
  assert.equal(out.length, 1)
  assert.equal(out[0].severity, 'critical')
})

test('buffer:all critical + incoming info 不改变内容', () => {
  const b = new FindingBuffer(2)
  b.add({ severity: 'critical', id: 'c1' })
  b.add({ severity: 'critical', id: 'c2' })
  b.add({ severity: 'info', id: 'i1' })
  const out = b.drain()
  assert.equal(out.length, 2)
  assert.deepEqual(out.map((f) => f.id), ['c1', 'c2'])
})

test('buffer:high 后 medium 不得淘汰 high,medium 后 high 必须替换 medium', () => {
  const b = new FindingBuffer(1)
  b.add({ severity: 'high', id: 'h1' })
  b.add({ severity: 'medium', id: 'm1' })
  assert.equal(b.drain()[0].severity, 'high')

  const b2 = new FindingBuffer(1)
  b2.add({ severity: 'medium', id: 'm1' })
  b2.add({ severity: 'high', id: 'h1' })
  assert.equal(b2.drain()[0].severity, 'high')
})

test('buffer:同优先级满时保留最先出现', () => {
  const b = new FindingBuffer(1)
  b.add({ severity: 'medium', id: 'first' })
  b.add({ severity: 'medium', id: 'second' })
  const out = b.drain()
  assert.equal(out.length, 1)
  assert.equal(out[0].id, 'first')
})

test('buffer:混合场景最终保留最高优先级集合', () => {
  const b = new FindingBuffer(3)
  b.add({ severity: 'info', id: 'i1' })
  b.add({ severity: 'low', id: 'l1' })
  b.add({ severity: 'medium', id: 'm1' })
  b.add({ severity: 'high', id: 'h1' }) // 替换 info
  b.add({ severity: 'critical', id: 'c1' }) // 替换 low
  b.add({ severity: 'info', id: 'i2' }) // 被拒
  const out = b.drain()
  assert.equal(out.length, 3)
  assert.deepEqual(out.map((f) => f.id), ['c1', 'h1', 'm1'])
})

// ---- P0-2: read/hash/analysis failure 虚假 complete ----

function makeTree() {
  const root = mkdtempSync(join(tmpdir(), 'sentinel-hardening-'))
  writeFileSync(join(root, 'a.js'), 'console.log("hello")\n')
  mkdirSync(join(root, 'sub'))
  writeFileSync(join(root, 'sub', 'b.js'), 'const x = 1\n')
  writeFileSync(join(root, 'payload.wasm'), Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]))
  return root
}

const denied = (code) => {
  const e = new Error(`denied (${code})`)
  e.code = code
  return e
}

test('read failure → 不计入 filesAnalyzed + scanComplete=false + coverageSkips', async () => {
  const root = makeTree()
  const res = await scanTree(root, {
    __io: { readFile: () => { throw denied('EACCES') } },
  })
  assert.equal(res.scanComplete, false)
  assert.equal(res.scanCoverage.readFailures, 2) // a.js + sub/b.js(wasm 走 hash 通道)
  assert.equal(res.filesAnalyzed, 1) // 只有 payload.wasm(hash 通道)成功
  assert.ok(res.coverageSkips.length >= 2)
  assert.equal(res.coverageSkips[0].stage, 'read')
  assert.ok(res.coverageSkips.every((f) => f.reason === 'EACCES'))
})

test('binary hash failure → 不计入 filesAnalyzed + scanComplete=false', async () => {
  const root = makeTree()
  const res = await scanTree(root, {
    __io: { hashFile: async () => { throw denied('EACCES') } },
  })
  assert.equal(res.scanComplete, false)
  assert.equal(res.scanCoverage.hashFailures, 1)
  assert.equal(res.scanCoverage.analysisFailures, 1)
  assert.ok(res.coverageSkips.some((f) => f.stage === 'hash' && f.path.endsWith('payload.wasm')))
})

test('目录 readdir failure → traversalFailures + scanComplete=false', async () => {
  const root = makeTree()
  const res = await scanTree(root, {
    __io: { readdir: () => { throw denied('EACCES') } },
  })
  assert.equal(res.scanComplete, false)
  assert.equal(res.scanCoverage.traversalFailures, 1)
  assert.equal(res.traversalFailures[0].stage, 'walk')
})

test('collectFiles:readdir 失败不再 silent', () => {
  const root = makeTree()
  const res = collectFiles(root, { __io: { readdir: () => { throw denied('EACCES') } } })
  assert.equal(res.traversalFailures.length, 1)
  assert.equal(res.traversalFailures[0].reason, 'EACCES')
})

test('正常树:filesAnalyzed 等于成功分析数,scanComplete=true', async () => {
  const root = makeTree()
  const res = await scanTree(root)
  assert.equal(res.scanComplete, true)
  assert.equal(res.scanCoverage.readFailures, 0)
  assert.equal(res.scanCoverage.analysisFailures, 0)
  assert.equal(res.coverageSkips.length, 0)
  assert.ok(res.filesAnalyzed >= 3) // a.js + sub/b.js + payload.wasm
})

// ---- P0-3: computeRuntimeEntries patch containment ----

function makeBundle(opts = {}) {
  const root = mkdtempSync(join(tmpdir(), 'sentinel-bundle-'))
  const pkg = {
    name: 'test-bundle',
    version: '1.0.0',
    main: opts.main ?? 'index.js',
    ...(opts.exports ? { exports: opts.exports } : {}),
    ...(opts.bin ? { bin: opts.bin } : {}),
    dsh: { bundle: { patch: opts.patch ?? 'cordis.patch.yml' } },
  }
  writeFileSync(join(root, 'package.json'), JSON.stringify(pkg))
  writeFileSync(join(root, 'index.js'), 'export const name = "t"\nexport function apply() {}\n')
  if (opts.patch !== undefined) {
    writeFileSync(join(root, opts.patch.split('/').pop()), '- insert:\n    - id: t\n      name: test-bundle/plugin\n')
    writeFileSync(join(root, 'plugin.js'), 'export const name = "p"\nexport function apply() {}\n')
  }
  return root
}

test('patch 逃逸到 bundle root 外:不读取、不加入、不抛未处理异常', () => {
  const root = makeBundle({ patch: '../../secret.yml' })
  writeFileSync(join(root, '../../secret.yml'), 'should never be read: secret')
  let out
  assert.doesNotThrow(() => { out = computeRuntimeEntries(root) })
  assert.ok(![...out].some((p) => p.includes('secret')))
  // 正常条目仍解析
  assert.ok(out.has('index.js'))
})

test('patch 缺失(mustExist):跳过 patch rows,不抛异常', () => {
  const root = makeBundle({ patch: 'missing.patch.yml' })
  let out
  assert.doesNotThrow(() => { out = computeRuntimeEntries(root) })
  assert.ok(out.has('index.js'))
})

test('main 逃逸:不加入 runtime entries', () => {
  const root = makeBundle({ main: '../../outside.js' })
  writeFileSync(join(root, '../../outside.js'), 'export const name = "x"\nexport function apply() {}\n')
  const out = computeRuntimeEntries(root)
  assert.ok(![...out].some((p) => p.includes('outside')))
})

test('bin 逃逸:不加入 runtime entries', () => {
  const root = makeBundle({ bin: { 'test-bundle': '../../evil-bin.js' } })
  const out = computeRuntimeEntries(root)
  assert.ok(![...out].some((p) => p.includes('evil-bin')))
})

test('resolveInside mustExist:逃逸与缺失都抛 PathEscapeError,合法存在路径返回 abs', () => {
  const root = makeBundle()
  assert.throws(() => resolveInside(root, '../../x.js', { mustExist: true }), PathEscapeError)
  assert.throws(() => resolveInside(root, 'nope.js', { mustExist: true }), PathEscapeError)
  const abs = resolveInside(root, 'index.js', { mustExist: true })
  assert.ok(abs.endsWith('index.js'))
})
