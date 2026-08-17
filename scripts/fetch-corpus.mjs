// 通过 jsDelivr CDN 抓取生态 Top 插件关键文件(两阶段,curl 实现)。
// 用法:node scripts/fetch-corpus.mjs
import { mkdirSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'

const ROOT = join(process.cwd(), 'scratch', 'corpus')
mkdirSync(ROOT, { recursive: true })

const PLUGINS = [
  'Nagi-ovo/dsh-ads',
  'NanmiCoder/dsh-agent-teams',
  'vlln/whale-girl',
  'csyangwen/dsh-memory-evolve',
  'Small-tailqwq/dsh-deep-whale',
  'ccch1mneyyy/working-activity',
  'zhu1090093659/dsh-web-ui',
]

// 沙箱限制:不能通过管道捕获子进程 stdout,curl 用 -o 直接落盘再读文件。
const TMP = join(tmpdir(), 'dsh-corpus-tmp')
mkdirSync(TMP, { recursive: true })

/** Fetch text via curl -o; returns content or null. */
function curl(url) {
  const tmpFile = join(TMP, `fetch-${Date.now()}-${Math.random().toString(36).slice(2)}`)
  const r = spawnSync('curl.exe', ['-s', '--max-time', '12', '-o', tmpFile, url], { stdio: 'ignore' })
  let content = null
  if (r.status === 0 && existsSync(tmpFile)) {
    const stat = readFileSync(tmpFile)
    if (stat.length > 0) content = stat.toString('utf8')
  }
  rmSync(tmpFile, { force: true })
  return content
}

function save(repo, rel, branch, content) {
  const dir = join(ROOT, repo.replace('/', '__'))
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, rel.replace(/[\\/:]/g, '__')), content, 'utf8')
}

let fetched = 0
let misses = 0
for (const repo of PLUGINS) {
  const dir = join(ROOT, repo.replace('/', '__'))
  // 已抓过(有 package.json)的跳过。
  if (existsSync(join(dir, 'package.json'))) {
    console.log(`- ${repo}: 已抓取,跳过`)
    continue
  }
  // 阶段 1:package.json(main → master)
  let branch = 'main'
  let pkg = curl(`https://cdn.jsdelivr.net/gh/${repo}@${branch}/package.json`)
  if (pkg === null) {
    branch = 'master'
    pkg = curl(`https://cdn.jsdelivr.net/gh/${repo}@${branch}/package.json`)
  }
  if (pkg === null) {
    console.log(`✗ ${repo}: package.json 两个分支都取不到`)
    misses += 1
    continue
  }
  save(repo, 'package.json', branch, pkg)
  fetched += 1

  // 阶段 2:从 manifest 解析入口 + 常见兜底
  const candidates = ['cordis.patch.yml', 'README.md']
  try {
    const parsed = JSON.parse(pkg)
    if (typeof parsed.main === 'string') candidates.push(parsed.main)
    const exp = parsed.exports
    if (exp && typeof exp === 'object') {
      for (const v of Object.values(exp)) {
        if (typeof v === 'string') candidates.push(v)
        else if (v && typeof v === 'object' && typeof v.default === 'string') candidates.push(v.default)
      }
    }
  } catch { /* 忽略解析失败 */ }
  candidates.push('plugin/index.js', 'plugin/index.ts', 'lib/index.js', 'src/index.ts', 'src/index.js')

  const seen = new Set()
  for (let raw of candidates) {
    if (seen.has(raw)) continue
    seen.add(raw)
    if (raw.startsWith('./')) raw = raw.slice(2)
    if (!/\.(js|ts|yml|md|json)$/.test(raw)) continue
    const content = curl(`https://cdn.jsdelivr.net/gh/${repo}@${branch}/${raw}`)
    if (content !== null) {
      save(repo, raw, branch, content)
      fetched += 1
    } else {
      misses += 1
    }
  }
  console.log(`✓ ${repo} (${branch}) 累计 fetched=${fetched}`)
}

console.log(`\n完成:fetched=${fetched} misses=${misses}`)
