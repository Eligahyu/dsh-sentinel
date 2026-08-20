import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const SOURCE_FILE = /\.(?:[cm]?[jt]sx?|mts|cts|vue|svelte|py|rb|php|pl|sh|bash|zsh|ps1|go|rs|java|kt|m|mm|swift)$/i
const TEXT_FILE = /(?:^|\/)(?:package\.json|cordis\.patch\.ya?ml)$|\.(?:[cm]?[jt]sx?|mts|cts|vue|svelte|json|ya?ml|md|txt)$/i
const SKIP_DIRS = new Set(['.git', 'node_modules'])
const TRANSPORT_ERROR = [
  /^Couldn't find the requested file\b/i,
  /^Package size exceeded the configured limit\b/i,
  /^Failed to fetch\b/i,
  /^Invalid URL\b/i,
  /^<!doctype html\b/i,
  /^<html(?:\s|>)/i,
]

/** Reject transport/CDN error bodies before they can become scanner corpus. */
export function assertCorpusPayload(path, payload) {
  const text = Buffer.isBuffer(payload) ? payload.toString('utf8') : String(payload ?? '')
  const trimmed = text.trimStart()
  if (TRANSPORT_ERROR.some((pattern) => pattern.test(trimmed))) {
    throw new Error(`transport error payload: ${path}`)
  }
  if (String(path).replaceAll('\\', '/').endsWith('/package.json') || String(path).replaceAll('\\', '/') === 'package.json') {
    try {
      const parsed = JSON.parse(text)
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('not an object')
    } catch (error) {
      throw new Error(`invalid package.json: ${error?.message ?? error}`)
    }
  }
  return text
}

/** Arguments for a source-only shallow clone. No dependency or lifecycle command is involved. */
export function cloneArgs(repository, destination) {
  return [
    'clone',
    '--depth', '1',
    '--filter=blob:none',
    '--no-tags',
    '--single-branch',
    repository,
    destination,
  ]
}

function filesUnder(root, dir = root) {
  const files = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory() && SKIP_DIRS.has(entry.name)) continue
    const abs = join(dir, entry.name)
    if (entry.isDirectory()) files.push(...filesUnder(root, abs))
    else if (entry.isFile()) files.push({ abs, rel: relative(root, abs).replaceAll('\\', '/') })
  }
  return files
}

/** Validate a fully checked-out repository before including it in corpus scans. */
export function validateRepositoryTree(root) {
  const files = filesUnder(root)
  const pkgFile = files.find((file) => file.rel === 'package.json')
  if (!pkgFile) throw new Error('repository missing package.json')
  const pkgText = assertCorpusPayload(pkgFile.rel, readFileSync(pkgFile.abs))
  const pkg = JSON.parse(pkgText)
  let sourceFiles = 0
  for (const file of files) {
    if (SOURCE_FILE.test(file.rel)) sourceFiles += 1
    if (TEXT_FILE.test(file.rel) && statSync(file.abs).size <= 5 * 1024 * 1024) {
      assertCorpusPayload(file.rel, readFileSync(file.abs))
    }
  }
  if (sourceFiles === 0) throw new Error('repository has no scan-relevant source files')
  return {
    packageName: typeof pkg.name === 'string' ? pkg.name : '',
    sourceFiles,
    files: files.length,
  }
}
