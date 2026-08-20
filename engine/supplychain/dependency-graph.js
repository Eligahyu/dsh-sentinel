/** Normalize package-manager metadata into a dependency graph. */

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    return null
  }
}

function packageNameFromKey(key) {
  const marker = 'node_modules/'
  const index = key.lastIndexOf(marker)
  return index >= 0 ? key.slice(index + marker.length) : key
}

function directNames(root) {
  return new Set([
    ...Object.keys(root.dependencies ?? {}),
    ...Object.keys(root.optionalDependencies ?? {}),
    ...Object.keys(root.peerDependencies ?? {}),
    ...Object.keys(root.devDependencies ?? {}),
  ])
}

function dependencyKinds(root, name) {
  return {
    direct: directNames(root).has(name),
    dev: Object.prototype.hasOwnProperty.call(root.devDependencies ?? {}, name),
    optional: Object.prototype.hasOwnProperty.call(root.optionalDependencies ?? {}, name),
    peer: Object.prototype.hasOwnProperty.call(root.peerDependencies ?? {}, name),
  }
}

function candidateKeys(parentKey, dependency) {
  const out = []
  if (parentKey) {
    const slash = parentKey.lastIndexOf('/node_modules/')
    const parentPackageRoot = slash >= 0 ? parentKey.slice(0, slash + '/node_modules/'.length) : `${parentKey}/node_modules/`
    out.push(`${parentPackageRoot}${dependency}`)
  }
  out.push(`node_modules/${dependency}`)
  return [...new Set(out)]
}

function unsupportedLockfile(dir) {
  for (const name of ['pnpm-lock.yaml', 'yarn.lock', 'bun.lock', 'bun.lockb']) {
    if (existsSync(join(dir, name))) return name
  }
  return null
}

/**
 * Build an exact npm package-lock v2/v3 graph. Unsupported lockfiles return
 * an explicit incomplete result instead of fabricated dependency counts.
 */
export function buildDependencyGraph(dir) {
  const lockPath = join(dir, 'package-lock.json')
  if (!existsSync(lockPath)) {
    const unsupported = unsupportedLockfile(dir)
    return {
      ecosystem: unsupported?.startsWith('bun') ? 'bun' : unsupported?.startsWith('pnpm') ? 'pnpm' : 'yarn',
      lockfile: unsupported,
      nodes: [],
      edges: [],
      failures: [{ reason: unsupported ? 'unsupported-lockfile' : 'missing-lockfile', path: unsupported ?? 'package-lock.json' }],
      complete: false,
    }
  }
  const doc = readJson(lockPath)
  if (!doc || ![2, 3].includes(doc.lockfileVersion) || !doc.packages || typeof doc.packages !== 'object') {
    return { ecosystem: 'npm', lockfile: 'package-lock.json', nodes: [], edges: [], failures: [{ reason: 'parse-error', path: 'package-lock.json' }], complete: false }
  }

  const root = doc.packages[''] ?? readJson(join(dir, 'package.json')) ?? {}
  const entries = Object.entries(doc.packages).filter(([key]) => key !== '')
  const byKey = new Map(entries.map(([key]) => [key, { key, ...doc.packages[key] }]))
  const nodes = entries.map(([key, entry]) => {
    const name = entry.name ?? packageNameFromKey(key)
    const kinds = dependencyKinds(root, name)
    return {
      id: key,
      name,
      version: String(entry.version ?? ''),
      ecosystem: 'npm',
      direct: kinds.direct,
      dev: Boolean(entry.dev || kinds.dev),
      optional: Boolean(entry.optional || kinds.optional),
      peer: Boolean(kinds.peer),
      integrity: entry.integrity ?? null,
      resolved: entry.resolved ?? null,
      hasInstallScript: Boolean(entry.hasInstallScript),
      scripts: entry.scripts ?? null,
      parents: [],
      children: [],
    }
  })
  const nodeByKey = new Map(nodes.map((node) => [node.id, node]))
  const edges = []
  const failures = []
  for (const [parentKey, entry] of byKey) {
    const dependencies = {
      ...(entry.dependencies ?? {}),
      ...(entry.optionalDependencies ?? {}),
      ...(entry.peerDependencies ?? {}),
    }
    for (const name of Object.keys(dependencies)) {
      const childKey = candidateKeys(parentKey, name).find((candidate) => nodeByKey.has(candidate))
      if (!childKey) {
        failures.push({ reason: 'unresolved-dependency', from: parentKey, name })
        continue
      }
      const parent = nodeByKey.get(parentKey)
      const child = nodeByKey.get(childKey)
      const edge = { from: parentKey, to: childKey, name, kind: entry.optionalDependencies?.[name] ? 'optional' : entry.peerDependencies?.[name] ? 'peer' : 'runtime' }
      edges.push(edge)
      parent.children.push(childKey)
      child.parents.push(parentKey)
    }
  }
  return {
    ecosystem: 'npm',
    lockfile: 'package-lock.json',
    lockfileVersion: doc.lockfileVersion,
    root: { name: root.name ?? '', version: String(root.version ?? ''), directDependencies: directNames(root).size },
    nodes,
    edges,
    failures,
    complete: failures.length === 0,
  }
}

export function dependencyPaths(graph, targetName) {
  const targets = new Set((graph?.nodes ?? []).filter((node) => node.name === targetName).map((node) => node.id))
  const paths = []
  const visit = (id, path = []) => {
    const node = graph.nodes.find((n) => n.id === id)
    if (!node) return
    const next = [...path, node]
    if (node.direct || node.parents.length === 0) {
      paths.push(next.map((n) => `${n.name}@${n.version}`))
      return
    }
    for (const parent of node.parents) visit(parent, next)
  }
  for (const id of targets) visit(id)
  return paths
}
