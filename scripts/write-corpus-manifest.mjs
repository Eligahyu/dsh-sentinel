import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { spawnSync } from 'node:child_process'

const ROOT = join(process.cwd(), 'scratch', 'corpus')
const OUT = join(process.cwd(), 'docs', 'benchmarks', 'public-corpus-manifest.json')

function sha256(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex')
}

function resolveCommit(repo) {
  for (const branch of ['main', 'master']) {
    const tmp = join(process.env.TEMP ?? process.cwd(), `dsh-gh-${process.pid}-${Math.random().toString(36).slice(2)}.atom`)
    const result = spawnSync('curl.exe', ['-s', '--max-time', '8', '-o', tmp, `https://github.com/${repo}/commits/${branch}.atom`], { stdio: 'ignore' })
    try {
      if (result.status === 0 && existsSync(tmp)) {
        const matches = readFileSync(tmp, 'utf8').match(/[0-9a-f]{40}/g) ?? []
        if (matches.length > 0) return { branch, commit: matches[0] }
      }
    } finally { rmSync(tmp, { force: true }) }
  }
  return { branch: null, commit: null }
}

function filesUnder(dir, prefix = '') {
  const out = []
  for (const entry of readdirSync(dir).sort()) {
    const abs = join(dir, entry)
    const rel = prefix ? `${prefix}/${entry}` : entry
    if (statSync(abs).isDirectory()) out.push(...filesUnder(abs, rel))
    else out.push({ path: rel.replaceAll('\\', '/'), bytes: statSync(abs).size, sha256: sha256(abs) })
  }
  return out
}

if (!existsSync(ROOT)) throw new Error('scratch/corpus 不存在，请先运行 fetch-corpus')
mkdirSync(join(process.cwd(), 'docs', 'benchmarks'), { recursive: true })
const sources = []
for (const dirName of readdirSync(ROOT).sort()) {
  const dir = join(ROOT, dirName)
  if (!statSync(dir).isDirectory() || dirName.startsWith('_')) continue
  const repo = dirName.replace('__', '/')
  const files = filesUnder(dir)
  const { branch, commit } = resolveCommit(repo)
  sources.push({
    repository: `https://github.com/${repo}`,
    ref: commit ? { branch, commit } : { branch: null, commit: null },
    files,
    fileCount: files.length,
  })
}

const manifest = {
  schemaVersion: 1,
  purpose: 'Public DSH plugin corpus for reproducible scanner regression and benchmark runs.',
  policy: 'Only public source metadata and file hashes are committed; downloaded source stays in ignored scratch/corpus.',
  sourceCount: sources.length,
  fileCount: sources.reduce((sum, source) => sum + source.fileCount, 0),
  sources,
}
writeFileSync(OUT, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
console.log(`写入 ${OUT}: sources=${manifest.sourceCount} files=${manifest.fileCount}`)
