/**
 * Deterministic, metadata-only provenance assessment.
 * This does not claim cryptographic verification: the registry is the source
 * of the attestation and the scanner only compares its signed subject facts.
 */

function firstAttestation(metadata) {
  return Array.isArray(metadata?.attestations) ? metadata.attestations[0] : null
}

function value(entry, ...keys) {
  for (const key of keys) {
    if (typeof entry?.[key] === 'string' && entry[key]) return entry[key]
  }
  return ''
}

export function verifyPackageProvenance(metadata, expected = {}) {
  const attestation = firstAttestation(metadata)
  if (!attestation) {
    return { status: 'unavailable', verified: false, reasons: ['no-attestation'] }
  }

  const issuer = value(attestation, 'issuer')
  const sourceRepository = value(attestation, 'sourceRepository', 'repository')
  const sourceCommit = value(attestation, 'sourceCommit', 'commit')
  const workflow = value(attestation, 'workflow', 'workflowPath')
  const digest = value(attestation, 'digest', 'sha256')
  const reasons = []

  if (!issuer) reasons.push('missing-issuer')
  if (expected.expectedRepository && !sourceRepository) reasons.push('missing-source-repository')
  if (expected.expectedCommit && !sourceCommit) reasons.push('missing-source-commit')
  if (expected.expectedWorkflow && !workflow) reasons.push('missing-workflow')
  if (expected.expectedDigest && !digest) reasons.push('missing-digest')
  if (expected.expectedRepository && sourceRepository && sourceRepository !== expected.expectedRepository) reasons.push('mismatch-source-repository')
  if (expected.expectedCommit && sourceCommit && sourceCommit !== expected.expectedCommit) reasons.push('mismatch-source-commit')
  if (expected.expectedWorkflow && workflow && workflow !== expected.expectedWorkflow) reasons.push('mismatch-workflow')
  if (expected.expectedDigest && digest && digest !== expected.expectedDigest) reasons.push('mismatch-digest')

  const verified = reasons.length === 0 && Boolean(issuer)
  return {
    status: verified ? 'verified' : 'invalid',
    verified,
    ...(issuer ? { issuer } : {}),
    ...(sourceRepository ? { sourceRepository } : {}),
    ...(sourceCommit ? { sourceCommit } : {}),
    ...(workflow ? { workflow } : {}),
    ...(digest ? { digest } : {}),
    reasons,
  }
}
