import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { buildDependencyGraph } from '../engine/supplychain/dependency-graph.js'
import { scan } from '../engine/index.js'

function writeLock(root) {
  writeFileSync(join(root, 'package.json'), JSON.stringify({
    name: 'fixture-plugin',
    dependencies: { alpha: '^1.0.0' },
    devDependencies: { 'test-only': '^2.0.0' },
  }))
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({
    name: 'fixture-plugin', lockfileVersion: 3, requires: true,
    packages: {
      '': { name: 'fixture-plugin', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, devDependencies: { 'test-only': '^2.0.0' } },
      'node_modules/alpha': { version: '1.2.0', resolved: 'https://registry.npmjs.org/alpha/-/alpha-1.2.0.tgz', integrity: 'sha512-alpha', dependencies: { beta: '^1.0.0' }, hasInstallScript: true },
      'node_modules/beta': { version: '1.4.0', integrity: 'sha512-beta' },
      'node_modules/test-only': { version: '2.1.0', dev: true, integrity: 'sha512-test' },
    },
  }))
}

test('dependency graph normalizes npm lockfile nodes and edges', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-graph-'))
  try {
    writeLock(root)
    const graph = buildDependencyGraph(root)
    assert.equal(graph.complete, true)
    assert.equal(graph.ecosystem, 'npm')
    assert.equal(graph.nodes.length, 3)
    const alpha = graph.nodes.find((n) => n.name === 'alpha')
    assert.equal(alpha.version, '1.2.0')
    assert.equal(alpha.direct, true)
    assert.equal(alpha.hasInstallScript, true)
    assert.ok(graph.edges.some((e) => e.from === alpha.id && e.to.includes('beta')))
    assert.equal(graph.nodes.find((n) => n.name === 'test-only').dev, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('dependency graph marks malformed lockfiles incomplete instead of guessing', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-bad-'))
  try {
    mkdirSync(join(root, 'node_modules'), { recursive: true })
    writeFileSync(join(root, 'package-lock.json'), '{not-json')
    const graph = buildDependencyGraph(root)
    assert.equal(graph.complete, false)
    assert.ok(graph.failures.some((f) => f.reason === 'parse-error'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('dependency graph returns explicit unsupported state for non-npm lockfiles', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-other-'))
  try {
    writeFileSync(join(root, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n')
    const graph = buildDependencyGraph(root)
    assert.equal(graph.complete, false)
    assert.ok(graph.failures.some((f) => f.reason === 'unsupported-lockfile'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('scan report exposes the normalized dependency graph when a lockfile exists', async () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-dependency-report-'))
  try {
    writeLock(root)
    const report = await scan(root)
    assert.equal(report.analysisLayers.dependencyGraph.complete, true)
    assert.equal(report.analysisLayers.dependencyGraph.nodes.length, 3)
    assert.equal(report.supplyChain.dependencyGraph.nodes, 3)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
