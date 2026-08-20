import assert from 'node:assert/strict'
import { test } from 'node:test'
import { verifyPackageProvenance } from '../engine/supplychain/provenance.js'

test('provenance is unavailable when registry metadata has no attestations', () => {
  const result = verifyPackageProvenance({ name: 'demo', version: '1.0.0', attestations: [] })
  assert.equal(result.status, 'unavailable')
  assert.equal(result.verified, false)
  assert.deepEqual(result.reasons, ['no-attestation'])
})

test('matching provenance evidence is verified against expected package facts', () => {
  const result = verifyPackageProvenance({
    name: 'demo',
    version: '1.0.0',
    attestations: [{
      type: 'https://in-toto.io/Statement/v1',
      issuer: 'https://token.actions.githubusercontent.com',
      digest: 'abc123',
      sourceRepository: 'https://github.com/acme/demo',
      sourceCommit: 'deadbeef',
      workflow: 'release.yml',
    }],
  }, {
    expectedRepository: 'https://github.com/acme/demo',
    expectedCommit: 'deadbeef',
    expectedWorkflow: 'release.yml',
    expectedDigest: 'abc123',
  })
  assert.equal(result.status, 'verified')
  assert.equal(result.verified, true)
  assert.equal(result.sourceRepository, 'https://github.com/acme/demo')
})

test('mismatched provenance is invalid and explains every mismatch', () => {
  const result = verifyPackageProvenance({
    attestations: [{
      type: 'provenance', issuer: 'issuer', digest: 'wrong',
      sourceRepository: 'https://github.com/other/demo', sourceCommit: 'old', workflow: 'old.yml',
    }],
  }, {
    expectedRepository: 'https://github.com/acme/demo',
    expectedCommit: 'new', expectedWorkflow: 'release.yml', expectedDigest: 'right',
  })
  assert.equal(result.status, 'invalid')
  assert.equal(result.verified, false)
  assert.equal(result.reasons.length, 4)
  assert.ok(result.reasons.every((reason) => reason.startsWith('mismatch-')))
})

test('malformed evidence cannot be treated as verified', () => {
  const result = verifyPackageProvenance({ attestations: [{ type: 'present' }] })
  assert.equal(result.status, 'invalid')
  assert.equal(result.verified, false)
  assert.ok(result.reasons.includes('missing-issuer'))
})
