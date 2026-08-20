import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const manifest = JSON.parse(readFileSync(new URL('../docs/benchmarks/public-corpus-manifest.json', import.meta.url)))

test('public corpus manifest is pinned and contains only reproducibility metadata', () => {
  assert.equal(manifest.schemaVersion, 2)
  assert.equal(manifest.acquisition, 'full-shallow-clone')
  assert.equal(manifest.installsExecuted, false)
  assert.equal(manifest.sourceCount, manifest.sources.length)
  assert.ok(manifest.sourceCount >= 6)
  for (const source of manifest.sources) {
    assert.match(source.repository, /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/)
    assert.match(source.commit, /^[0-9a-f]{40}$/)
    assert.ok(source.packageName)
    assert.ok(source.sourceFiles > 0)
    assert.ok(source.files >= source.sourceFiles)
    assert.match(source.metadataSha256, /^[0-9a-f]{64}$/)
  }
})
