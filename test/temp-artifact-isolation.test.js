import assert from 'node:assert/strict'
import { test } from 'node:test'
import { temporaryArtifactName } from '../engine/package/tarball.js'

test('temporary tar artifacts are scoped to the creating process', () => {
  const pid = String(process.pid)
  assert.match(temporaryArtifactName('pkg', '.tgz'), new RegExp(`^sentinel-pkg-${pid}-[0-9]+-[a-z0-9]+\\.tgz$`))
  assert.match(temporaryArtifactName('quarantine'), new RegExp(`^sentinel-quarantine-${pid}-[0-9]+-[a-z0-9]+$`))
})
