import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { validateRepositoryTree } from './corpus-utils.mjs'

const ROOT = resolve(process.env.DSH_CORPUS_ROOT || join(process.cwd(), 'scratch', 'corpus-full'))
const SOURCES = join(ROOT, '_sources.json')
const OUT = join(process.cwd(), 'docs', 'benchmarks', 'public-corpus-manifest.json')

if (!existsSync(SOURCES)) throw new Error(`${SOURCES} 不存在，请先运行 fetch-corpus`)
const fetched = JSON.parse(readFileSync(SOURCES, 'utf8'))
if (fetched.mode !== 'full-shallow-clone' || fetched.installsExecuted !== false) {
  throw new Error('refusing to publish metadata from a partial or executable corpus')
}

const sources = fetched.sources.map((source) => {
  const root = join(ROOT, source.repository.replace('/', '__'))
  const validation = validateRepositoryTree(root)
  const identity = JSON.stringify({
    repository: source.repository,
    commit: source.commit,
    packageName: validation.packageName,
    sourceFiles: validation.sourceFiles,
    files: validation.files,
  })
  return {
    repository: `https://github.com/${source.repository}`,
    commit: source.commit,
    packageName: validation.packageName,
    sourceFiles: validation.sourceFiles,
    files: validation.files,
    metadataSha256: createHash('sha256').update(identity).digest('hex'),
  }
}).sort((a, b) => a.repository.localeCompare(b.repository))

const manifest = {
  schemaVersion: 2,
  purpose: 'Pinned public DSH plugin corpus for source-complete scanner regression runs.',
  acquisition: 'full-shallow-clone',
  installsExecuted: false,
  sourceCount: sources.length,
  sources,
}

mkdirSync(join(process.cwd(), 'docs', 'benchmarks'), { recursive: true })
writeFileSync(OUT, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
console.log(`写入 ${OUT}: sources=${manifest.sourceCount}`)
