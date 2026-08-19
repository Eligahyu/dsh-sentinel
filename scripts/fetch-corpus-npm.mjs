/**
 * 通过 npm 注册表抓取完整插件包(比 jsDelivr 猜文件快且全)。
 * 对每个关键词:npm search → 选最匹配的包 → npm pack → 解压到 corpus/<repo>。
 * 用法:node scripts/fetch-corpus-npm.mjs
 *
 * 沙箱限制:Node 不能通过管道捕获子进程 stdout,所以搜索输出用
 * cmd 重定向到文件再读取(curl -o 同款思路)。
 */
import { mkdirSync, readdirSync, rmSync, existsSync, renameSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'

const ROOT = join(process.cwd(), 'scratch', 'corpus')
mkdirSync(ROOT, { recursive: true })

const TARGETS = [
  ['xmanrui/dsh-im', 'dsh-im'],
  ['tencent-connect/dsh-qqbot', 'dsh-qqbot'],
  ['omdsh-dev/dsh-lark', 'dsh-lark'],
  ['AX1202/ax-feishu-bridge', 'feishu-bridge'],
  ['chushixixin/dsh-harness-mcp-server', 'dsh-harness-mcp'],
  ['flymysql/dsh-remote', 'dsh-remote'],
  ['Chinesezjc/dsh-interconnect', 'dsh-interconnect'],
  ['THEWOLFWALKER/dsh-notifier', 'dsh-notifier'],
  ['titanwings/dsh-automation', 'dsh-automation'],
  ['bowenliang123/dsh-context', 'dsh-context'],
  ['liustack/modsearch', 'modsearch'],
  ['omdsh-dev/dsh-notification', 'dsh-notification'],
]

/** 运行命令,stdout 经 cmd 重定向到文件后读取(规避沙箱管道限制)。 */
function capture(cmdArgs, cwd) {
  const out = join(tmpdir(), `cap-${Date.now()}-${Math.random().toString(36).slice(2)}.out`)
  const line = cmdArgs.map((a) => (/\s/.test(a) ? `"${a}"` : a)).join(' ')
  const r = spawnSync('cmd.exe', ['/c', `${line} > "${out}" 2> NUL`], { cwd, stdio: 'ignore' })
  let content = null
  if (r.status === 0) {
    try { content = readFileSync(out, 'utf8') } catch { content = null }
  }
  rmSync(out, { force: true })
  return content
}

for (const [repo, keyword] of TARGETS) {
  const dirName = repo.replace('/', '__')
  const destDir = join(ROOT, dirName)
  if (existsSync(join(destDir, 'package.json'))) {
    console.log(`- ${repo}: 已有,跳过`)
    continue
  }
  const searchOut = capture(['npm.cmd', 'search', keyword, '--json'], process.cwd())
  let candidates = []
  try { candidates = JSON.parse(searchOut ?? '[]') } catch { candidates = [] }
  if (candidates.length === 0) {
    console.log(`✗ ${repo}: npm search "${keyword}" 无结果`)
    continue
  }
  const score = (c) => {
    let s = 0
    const n = c.name.toLowerCase()
    const d = (c.description ?? '').toLowerCase()
    const k = keyword.toLowerCase()
    if (n.includes(k) || n.replace(/[-_]/g, '').includes(k.replace(/[-_]/g, ''))) s += 3
    if (d.includes('dsh') || d.includes('deepseek')) s += 2
    if (n.includes('dsh') || n.includes('deepseek')) s += 1
    return s
  }
  candidates.sort((a, b) => score(b) - score(a))
  const pick = candidates[0]
  if (score(pick) === 0) {
    console.log(`✗ ${repo}: 结果不相关(${candidates.map((c) => c.name).slice(0, 3).join(', ')})`)
    continue
  }
  const tmp = join(tmpdir(), `pkg-${Date.now()}-${Math.random().toString(36).slice(2)}`)
  mkdirSync(tmp, { recursive: true })
  const pack = spawnSync('npm.cmd', ['pack', pick.name, '--pack-destination', tmp], { stdio: 'ignore' })
  if (pack.status !== 0) {
    console.log(`✗ ${repo}: npm pack ${pick.name} 失败`)
    rmSync(tmp, { recursive: true, force: true })
    continue
  }
  const tgz = readdirSync(tmp).find((f) => f.endsWith('.tgz'))
  const extractDir = join(tmp, 'x')
  mkdirSync(extractDir, { recursive: true })
  const tar = tgz
    ? spawnSync('tar.exe', ['-xf', join(tmp, tgz), '-C', extractDir], { stdio: 'ignore' })
    : { status: 1 }
  if (tar.status !== 0) { rmSync(tmp, { recursive: true, force: true }); continue }
  mkdirSync(destDir, { recursive: true })
  for (const entry of readdirSync(join(extractDir, 'package'))) {
    renameSync(join(extractDir, 'package', entry), join(destDir, entry))
  }
  rmSync(tmp, { recursive: true, force: true })
  console.log(`✓ ${repo}: npm 包 ${pick.name}@${pick.version} → ${dirName}`)
}

console.log('完成')
