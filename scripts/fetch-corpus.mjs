/**
 * Fetch a source-complete DSH corpus without executing repository code.
 *
 * Safety properties:
 * - shallow, blob-filtered Git clone; no submodules
 * - no npm install/ci and no lifecycle scripts
 * - clone into a process-scoped partial directory, validate, then rename
 * - old CDN corpus is left untouched in scratch/corpus
 *
 * Usage:
 *   node scripts/fetch-corpus.mjs
 *   DSH_CORPUS_LIMIT=5 node scripts/fetch-corpus.mjs
 *   DSH_CORPUS_REPOS=owner/repo,owner/repo node scripts/fetch-corpus.mjs
 */
import { existsSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { basename, join, relative, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { cloneArgs, validateRepositoryTree } from './corpus-utils.mjs'

const DEFAULT_REPOSITORIES = [
  'AX1202/ax-feishu-bridge',
  'Anionex/dsh-turn-rewind',
  'Anionex/dsh-vision-toolkit',
  'anysearch-team/anysearch-dsh',
  'flymysql/dsh-remote',
  'liustack/modlens',
  'LoserFox/distill',
  'NanmiCoder/dsh-agent-teams',
  'Noob-stupid/dsh-plugin-hub',
  'omdsh-dev/dsh-at-file',
  'omdsh-dev/dsh-custom-tool',
  'omdsh-dev/dsh-mnemon',
  'tencent-connect/dsh-qqbot',
  'zhuiyueya/dsh-im-gateway',
]

const ROOT = resolve(process.env.DSH_CORPUS_ROOT || join(process.cwd(), 'scratch', 'corpus-full'))
const requested = process.env.DSH_CORPUS_REPOS
  ? process.env.DSH_CORPUS_REPOS.split(',').map((value) => value.trim()).filter(Boolean)
  : DEFAULT_REPOSITORIES
const limit = Number.parseInt(process.env.DSH_CORPUS_LIMIT || String(requested.length), 10)
const repositories = requested.slice(0, Number.isFinite(limit) && limit > 0 ? limit : requested.length)
mkdirSync(ROOT, { recursive: true })

function destinationFor(repository) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repository)) throw new Error(`invalid GitHub repository: ${repository}`)
  return join(ROOT, repository.replace('/', '__'))
}

function assertDisposable(path) {
  const rel = relative(ROOT, resolve(path))
  if (!rel || rel.startsWith('..') || rel.includes(':') || !basename(path).includes(`.partial-${process.pid}-`)) {
    throw new Error(`refusing to remove path outside corpus partial scope: ${path}`)
  }
}

function git(args, options = {}) {
  return spawnSync('git', args, {
    cwd: options.cwd,
    encoding: 'utf8',
    windowsHide: true,
    env: {
      ...process.env,
      GIT_TERMINAL_PROMPT: '0',
      GIT_LFS_SKIP_SMUDGE: '1',
    },
  })
}

const sources = []
for (const repository of repositories) {
  const destination = destinationFor(repository)
  if (existsSync(destination)) {
    try {
      const validation = validateRepositoryTree(destination)
      const revision = git(['rev-parse', 'HEAD'], { cwd: destination })
      if (revision.status !== 0) throw new Error(revision.stderr.trim() || 'git rev-parse failed')
      sources.push({ repository, commit: revision.stdout.trim(), ...validation, reused: true })
      console.log(`- ${repository}: validated existing clone (${validation.sourceFiles} source files)`)
    } catch (error) {
      console.error(`✗ ${repository}: existing clone invalid: ${error?.message ?? error}`)
    }
    continue
  }

  const partial = `${destination}.partial-${process.pid}-${Math.random().toString(36).slice(2)}`
  try {
    const repositoryUrl = `https://github.com/${repository}.git`
    const cloned = git(cloneArgs(repositoryUrl, partial))
    if (cloned.status !== 0) throw new Error(cloned.stderr.trim() || `git clone exited ${cloned.status}`)
    const validation = validateRepositoryTree(partial)
    const revision = git(['rev-parse', 'HEAD'], { cwd: partial })
    if (revision.status !== 0) throw new Error(revision.stderr.trim() || 'git rev-parse failed')
    renameSync(partial, destination)
    sources.push({ repository, commit: revision.stdout.trim(), ...validation, reused: false })
    console.log(`✓ ${repository}@${revision.stdout.trim().slice(0, 12)} (${validation.sourceFiles} source files)`)
  } catch (error) {
    console.error(`✗ ${repository}: ${error?.message ?? error}`)
  } finally {
    if (existsSync(partial)) {
      assertDisposable(partial)
      rmSync(partial, { recursive: true, force: true })
    }
  }
}

const metadata = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  mode: 'full-shallow-clone',
  installsExecuted: false,
  root: ROOT,
  requested: repositories.length,
  accepted: sources.length,
  sources,
}
writeFileSync(join(ROOT, '_sources.json'), `${JSON.stringify(metadata, null, 2)}\n`, 'utf8')
console.log(`\nCorpus ready: accepted=${sources.length}/${repositories.length} root=${ROOT}`)
if (sources.length === 0) process.exitCode = 1
