/** Stable report contracts for optional professional analysis layers. */

const LAYER_DEFAULTS = Object.freeze({
  moduleGraph: { complete: true, nodes: 0, edges: 0, unresolved: 0, failures: [] },
  dependencyGraph: { complete: true, nodes: 0, edges: 0, unresolved: 0, failures: [] },
  capabilityGraph: { complete: true, tools: 0, capabilities: [], attackPaths: 0, failures: [] },
  sbom: { status: 'not-requested', format: null, components: 0, digest: null, failures: [] },
  provenance: { status: 'not-requested', verified: false, reasons: [] },
})

function clone(value) {
  return JSON.parse(JSON.stringify(value))
}

/** Return a backward-compatible, fully populated layer object. */
export function emptyAnalysisLayers() {
  return clone(LAYER_DEFAULTS)
}

/** Merge partial layer output while retaining stable defaults. */
export function normalizeAnalysisLayers(input = {}) {
  const layers = emptyAnalysisLayers()
  for (const name of Object.keys(layers)) {
    if (input[name] && typeof input[name] === 'object') {
      layers[name] = { ...layers[name], ...input[name] }
    }
  }
  return layers
}

/** Reasons that make a report incomplete, suitable for CI and human review. */
export function incompleteLayerReasons(layers) {
  const reasons = []
  const label = (name) => name.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)
  for (const [name, layer] of Object.entries(layers ?? {})) {
    if (layer?.complete === false) reasons.push(label(name))
    if (Array.isArray(layer?.failures) && layer.failures.length > 0) {
      if (!reasons.includes(label(name))) reasons.push(label(name))
    }
  }
  return reasons
}

/** Throw on malformed public report contracts; used by tests/release gates. */
export function assertReportContract(report) {
  if (!report || report.schemaVersion !== 2) throw new Error('report schemaVersion must be 2')
  const layers = report.analysisLayers
  if (!layers || typeof layers !== 'object') throw new Error('report analysisLayers missing')
  for (const name of Object.keys(LAYER_DEFAULTS)) {
    if (!layers[name] || typeof layers[name] !== 'object') throw new Error(`report analysis layer missing: ${name}`)
  }
  if (report.summary?.scanComplete === true && incompleteLayerReasons(layers).length > 0) {
    throw new Error('complete report cannot contain failed analysis layers')
  }
  if (!Array.isArray(report.summary?.incompleteReasons)) throw new Error('summary incompleteReasons missing')
  return true
}
