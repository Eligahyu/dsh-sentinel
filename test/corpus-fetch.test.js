import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  assertCorpusPayload,
  cloneArgs,
  validateRepositoryTree,
} from '../scripts/corpus-utils.mjs'

test('corpus payload validation rejects CDN and HTML error bodies', () => {
  assert.throws(
    () => assertCorpusPayload('plugin/index.js', "Couldn't find the requested file /plugin/index.js"),
    /transport error payload/,
  )
  assert.throws(
    () => assertCorpusPayload('package.json', '<!doctype html><title>404 Not Found</title>'),
    /transport error payload/,
  )
  assert.throws(
    () => assertCorpusPayload('package.json', '{not-json}'),
    /invalid package.json/,
  )
  assert.doesNotThrow(() => assertCorpusPayload('package.json', '{"name":"valid-plugin"}'))
})

test('full corpus clone is shallow, filtered, tag-free and never installs dependencies', () => {
  const args = cloneArgs('https://github.com/example/dsh-plugin.git', 'C:/scratch/plugin')
  assert.deepEqual(args.slice(0, 2), ['clone', '--depth'])
  assert.ok(args.includes('--filter=blob:none'))
  assert.ok(args.includes('--no-tags'))
  assert.ok(args.includes('--single-branch'))
  assert.ok(!args.some((arg) => /npm|install|ci/i.test(arg)))
})

test('repository validation requires valid metadata and real source while ignoring .git internals', () => {
  const root = mkdtempSync(join(tmpdir(), 'dsh-corpus-validate-'))
  try {
    mkdirSync(join(root, '.git', 'objects'), { recursive: true })
    writeFileSync(join(root, '.git', 'objects', 'fake.js'), "Couldn't find the requested file")
    writeFileSync(join(root, 'package.json'), '{"name":"fixture"}')
    assert.throws(() => validateRepositoryTree(root), /no scan-relevant source files/)

    mkdirSync(join(root, 'src'), { recursive: true })
    writeFileSync(join(root, 'src', 'index.ts'), 'export const value: number = 1\n')
    const result = validateRepositoryTree(root)
    assert.equal(result.packageName, 'fixture')
    assert.equal(result.sourceFiles, 1)

    writeFileSync(join(root, 'src', 'bad.js'), 'Package size exceeded the configured limit')
    assert.throws(() => validateRepositoryTree(root), /transport error payload/)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
