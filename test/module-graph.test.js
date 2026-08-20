import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { buildModuleGraph } from '../engine/semantic/module-graph.js'
import { scan } from '../engine/index.js'

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'dsh-module-graph-'))
  mkdirSync(join(root, 'plugin'), { recursive: true })
  mkdirSync(join(root, 'lib'), { recursive: true })
  mkdirSync(join(root, 'pkg'), { recursive: true })
  writeFileSync(join(root, 'plugin', 'index.js'), [
    "import { run } from '../lib/runner'",
    "import tool from '../pkg'",
    "import external from 'external-package'",
    'run(tool, external)',
  ].join('\n'))
  writeFileSync(join(root, 'lib', 'runner.js'), 'export function run() {}\n')
  writeFileSync(join(root, 'pkg', 'package.json'), JSON.stringify({
    name: 'local-pkg',
    exports: { '.': './entry.js' },
  }))
  writeFileSync(join(root, 'pkg', 'entry.js'), 'export default {}\n')
  return root
}

test('module graph resolves relative, extensionless, directory, and external imports', () => {
  const root = fixture()
  try {
    const graph = buildModuleGraph(root, ['plugin/index.js', 'lib/runner.js', 'pkg/entry.js'])
    assert.equal(graph.complete, true)
    assert.equal(graph.nodes.length, 3)
    assert.ok(graph.edges.some((e) => e.from === 'plugin/index.js' && e.to === 'lib/runner.js'))
    assert.ok(graph.edges.some((e) => e.from === 'plugin/index.js' && e.to === 'pkg/entry.js'))
    assert.ok(graph.unresolved.some((e) => e.specifier === 'external-package' && e.external === true))
    assert.equal(graph.failures.length, 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('module graph rejects imports that escape the scan root', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'plugin', 'escape.js'), "import x from '../../outside.js'\nexport default x\n")
    const graph = buildModuleGraph(root, ['plugin/escape.js'])
    assert.equal(graph.complete, false)
    assert.ok(graph.failures.some((f) => f.reason === 'path-escape'))
    assert.equal(graph.edges.length, 0)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('module graph reports parse and missing-file failures without throwing', () => {
  const root = fixture()
  try {
    writeFileSync(join(root, 'broken.js'), 'export function ( {')
    const graph = buildModuleGraph(root, ['broken.js', 'missing.js'])
    assert.equal(graph.complete, false)
    assert.ok(graph.failures.some((f) => f.reason === 'parse-error'))
    assert.ok(graph.failures.some((f) => f.reason === 'missing-file'))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

test('scan report exposes the module graph analysis layer', async () => {
  const root = fixture()
  try {
    const report = await scan(root)
    assert.ok(report.analysisLayers.moduleGraph.nodes.length >= 3)
    assert.ok(report.analysisLayers.moduleGraph.edges.length >= 2)
    assert.equal(report.analysisLayers.moduleGraph.complete, true)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
