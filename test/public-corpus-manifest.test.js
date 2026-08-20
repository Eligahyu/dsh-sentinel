import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const manifest = JSON.parse(readFileSync(new URL('../docs/benchmarks/public-corpus-manifest.json', import.meta.url)))

test('public corpus manifest is pinned and contains only reproducibility metadata', () => {
  assert.equal(manifest.schemaVersion, 1)
  assert.equal(manifest.sourceCount, manifest.sources.length)
  assert.ok(manifest.sourceCount >= 30)
  assert.ok(manifest.fileCount >= manifest.sourceCount)
  for (const source of manifest.sources) {
    assert.match(source.repository, /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/)
    assert.match(source.ref.branch, /^(main|master)$/)
    assert.match(source.ref.commit, /^[0-9a-f]{40}$/)
    assert.equal(source.fileCount, source.files.length)
    for (const file of source.files) {
      assert.ok(file.path)
      assert.equal(typeof file.bytes, 'number')
      assert.match(file.sha256, /^[0-9a-f]{64}$/)
    }
  }
})
