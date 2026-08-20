/**
 * Read-only JavaScript/TypeScript module graph.
 *
 * This module never imports a target module. It parses import declarations and
 * resolves only files contained by the scan root. External packages are kept
 * as unresolved edges so callers can distinguish a graph gap from a package
 * boundary.
 */

import { createHash } from 'node:crypto'
import { existsSync, readFileSync, statSync } from 'node:fs'
import { dirname, extname, join, relative, resolve } from 'node:path'
import { parseJavaScript, walk, staticString } from './ast.js'
import { resolveInside } from '../path-safety.js'

const SOURCE_EXTENSIONS = ['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']

function relPath(root, abs) {
  return relative(root, abs).replace(/\\/g, '/')
}

function hash(content) {
  return createHash('sha256').update(content).digest('hex')
}

function packageExportTarget(pkg, subpath = '.') {
  const exports = pkg?.exports
  if (typeof exports === 'string') return exports
  if (!exports || typeof exports !== 'object' || Array.isArray(exports)) return null
  const entry = exports[subpath] ?? (subpath === '.' ? exports['.'] : null)
  if (typeof entry === 'string') return entry
  if (entry && typeof entry === 'object') {
    return entry.import ?? entry.require ?? entry.default ?? null
  }
  return null
}

function readPackage(abs) {
  try {
    return JSON.parse(readFileSync(join(abs, 'package.json'), 'utf8'))
  } catch {
    return null
  }
}

function resolveContained(root, candidate) {
  try {
    return resolveInside(root, candidate)
  } catch (error) {
    return { error }
  }
}

/** Resolve a source specifier without executing package code. */
export function resolveModuleSpecifier(root, importer, specifier) {
  if (typeof specifier !== 'string' || specifier.length === 0) return { kind: 'external', specifier }
  if (!specifier.startsWith('.') && !specifier.startsWith('/')) {
    return { kind: 'external', specifier }
  }

  const base = resolve(root, dirname(join(root, importer)), specifier)
  const contained = resolveContained(root, base)
  if (contained?.error) return { kind: 'failure', specifier, reason: 'path-escape', error: contained.error }

  const candidates = []
  const addFileCandidates = (abs) => {
    if (extname(abs)) candidates.push(abs)
    else for (const ext of SOURCE_EXTENSIONS) candidates.push(abs + ext)
  }
  addFileCandidates(contained)
  if (existsSync(contained) && statSync(contained).isDirectory()) {
    const pkg = readPackage(contained)
    const target = packageExportTarget(pkg, '.')
    if (typeof target === 'string') {
      const exported = resolveContained(root, resolve(contained, target))
      if (exported?.error) return { kind: 'failure', specifier, reason: 'path-escape', error: exported.error }
      addFileCandidates(exported)
    }
    for (const ext of SOURCE_EXTENSIONS) candidates.push(join(contained, `index${ext}`))
  }

  for (const candidate of candidates) {
    const safe = resolveContained(root, candidate)
    if (safe?.error) return { kind: 'failure', specifier, reason: 'path-escape', error: safe.error }
    if (existsSync(safe) && statSync(safe).isFile()) {
      return { kind: 'internal', specifier, abs: safe }
    }
  }
  return { kind: 'failure', specifier, reason: 'missing-file' }
}

function importSpecifiers(ast) {
  const out = []
  walk(ast, (node) => {
    if (node.type === 'ImportDeclaration') {
      const specifier = staticString(node.source)
      if (specifier !== null) out.push({ specifier, start: node.source.start })
    } else if (node.type === 'ExportNamedDeclaration' || node.type === 'ExportAllDeclaration') {
      const specifier = staticString(node.source)
      if (specifier !== null) out.push({ specifier, start: node.source.start })
    } else if (node.type === 'ImportExpression') {
      const specifier = staticString(node.source)
      if (specifier !== null) out.push({ specifier, start: node.source.start })
    }
  })
  return out
}

function nodeFor(root, abs, content, ast) {
  return {
    path: relPath(root, abs),
    bytes: Buffer.byteLength(content),
    sha256: hash(content),
    parser: ast ? 'acorn' : 'unparsed',
    imports: ast ? importSpecifiers(ast).map((x) => x.specifier) : [],
  }
}

/**
 * Build a bounded module graph from seed files and their static imports.
 * @param {string} root scan root
 * @param {string[]} files relative seed paths
 * @returns {{nodes: object[], edges: object[], unresolved: object[], failures: object[], complete: boolean}}
 */
export function buildModuleGraph(root, files = []) {
  const rootAbs = resolve(root)
  const nodes = []
  const edges = []
  const unresolved = []
  const failures = []
  const queue = [...new Set(files.map((f) => String(f).replace(/\\/g, '/')))]
  const seen = new Set()

  while (queue.length > 0) {
    const rel = queue.shift()
    if (seen.has(rel)) continue
    seen.add(rel)
    let abs
    try {
      abs = resolveInside(rootAbs, rel)
    } catch (error) {
      failures.push({ path: rel, reason: 'path-escape', detail: error?.message })
      continue
    }
    if (!existsSync(abs) || !statSync(abs).isFile()) {
      failures.push({ path: rel, reason: 'missing-file' })
      continue
    }
    let content
    try {
      content = readFileSync(abs, 'utf8')
    } catch (error) {
      failures.push({ path: rel, reason: 'read-error', detail: error?.code ?? error?.message })
      continue
    }
    const ast = parseJavaScript(content)
    nodes.push(nodeFor(rootAbs, abs, content, ast))
    if (!ast) {
      failures.push({ path: rel, reason: 'parse-error' })
      continue
    }
    for (const item of importSpecifiers(ast)) {
      const result = resolveModuleSpecifier(rootAbs, rel, item.specifier)
      if (result.kind === 'external') {
        unresolved.push({ from: rel, specifier: item.specifier, external: true, start: item.start })
        continue
      }
      if (result.kind === 'failure') {
        failures.push({ path: rel, specifier: item.specifier, reason: result.reason })
        continue
      }
      const target = relPath(rootAbs, result.abs)
      edges.push({ from: rel, to: target, specifier: item.specifier, start: item.start, kind: 'static-import' })
      if (!seen.has(target)) queue.push(target)
    }
  }

  return {
    nodes,
    edges,
    unresolved,
    failures,
    complete: failures.length === 0,
  }
}
