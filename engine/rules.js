/**
 * dsh-sentinel rule catalog.
 *
 * Every rule is a heuristic: a finding means "a human should look at this",
 * never "this plugin is malicious". Severities weight the final 0-100 score —
 * a single critical finding (50) already lands in `risky`, two in `dangerous`:
 *
 *   critical 50 · high 20 · medium 8 · low 3 · info 0
 *
 * Line patterns are tested per line; content patterns are tested once against
 * the whole file. `filePattern` restricts a rule to matching relative paths.
 * Findings inside test files are tagged `testFile` and scored one level lower
 * (see engine/report.js) — test fixtures are usually deliberate.
 */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']

export const SEVERITY_WEIGHT = Object.freeze({
  critical: 50,
  high: 20,
  medium: 8,
  low: 3,
  info: 0,
})

export const CATEGORIES = Object.freeze([
  'execution',
  'credentials',
  'exfiltration',
  'obfuscation',
  'install',
  'filesystem',
  'network',
  'manifest',
  'hygiene',
])

/** Shared fragment: any JS-adjacent code file. */
const CODE = /\.(?:[cm]?js|jsx|ts|tsx|mts|cts|py|rb|php|pl|sh|bash|zsh|ps1|go|rs|java|kt|m|mm|swift|vue|svelte)$/i

/** Hardcoded-secret detector used by SEN-CRED-003 (kept private, exported below). */
const SECRET_PATTERNS = [
  { name: 'OpenAI/DeepSeek-style API key', re: /\bsk-[A-Za-z0-9_-]{20,}\b/ },
  { name: 'AWS access key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub personal access token', re: /\bghp_[A-Za-z0-9]{36}\b/ },
  { name: 'Slack token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'JWT-style token', re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
]

export const RULES = Object.freeze([
  // ─────────────────────────── execution ───────────────────────────
  {
    id: 'SEN-EXEC-001',
    name: 'remote-code-download',
    severity: 'critical',
    category: 'execution',
    message: '下载远程代码并执行(remote code download & execute)',
    description: '发现从网络获取内容后直接交给执行器(exec/spawn/eval/Function/shell)的模式。这是供应链攻击最典型的形状。',
    recommendation: '拒绝安装,除非你能逐行审查网络载荷并信任其来源。任何"下载即执行"的插件都不应进入你的 profile。',
    filePattern: CODE,
    contentPatterns: [
      {
        re: /(?:child_process|cp|exec|execSync|execFile|spawn|spawnSync|system|popen|run)\s*\(\s*["'`]?(?:[^"'`)]{0,120}?)(?:curl|wget|powershell\s+-c|cmd\s+\/c|bash\s+-c|sh\s+-c)[^"'`)]{0,120}?["'`]?\s*\)/i,
        note: 'exec 类调用里出现 curl/wget/远程管道',
      },
      {
        re: /(?:exec|execSync|spawn|spawnSync|eval|new\s+Function|Function)\s*\([^)]{0,400}(?:https?:\/\/|fetch\s*\()/is,
        note: '执行器参数中出现 URL 或 fetch 调用',
      },
      {
        re: /(?:fetch|axios|https?\.request)\s*\([^)]{0,200}?\)\s*\.then\s*\([^)]{0,200}?(?:eval|Function|exec)\s*\(/is,
        note: '先请求后执行的链式调用',
      },
      {
        re: /(?:require|import)\s*\(\s*["'`](?:https?:|data:)/i,
        note: '从 URL 动态加载模块',
      },
    ],
  },
  {
    id: 'SEN-EXEC-002',
    name: 'shell-execution',
    severity: 'medium',
    category: 'execution',
    message: '使用 shell 执行(child_process / system 调用)',
    description: '插件调用系统命令。部分 DSH 插件(终端、构建类)确有正当需求,但这是插件越权的最高频入口,必须逐处审查。',
    recommendation: '确认每个执行点都是功能必需、命令与参数均为静态常量(不含拼接的用户输入/环境变量),且沙箱外执行需用户知情。',
    filePattern: CODE,
    linePatterns: [
      { re: /(?:child_process|cp)\s*\.\s*(?:exec|execSync|execFile|spawn|spawnSync|fork)\s*\(/ },
      { re: /(?<![.\w$])(?:exec|execSync|spawn|spawnSync)\s*\(/ },
      { re: /\b(?:system|popen|shell_exec|os\.system|subprocess\.(?:run|Popen|call))\s*\(/ },
    ],
  },
  {
    id: 'SEN-EXEC-003',
    name: 'dynamic-code-eval',
    severity: 'high',
    category: 'execution',
    message: '动态代码执行(eval / Function / vm / 编译钩子)',
    description: 'eval、new Function、vm.runIn*、Module._compile、process.binding 等动态执行机制。配合网络或解码即高危。',
    recommendation: '审查动态执行的内容来源;任何来自网络、环境变量或解码字符串的动态执行都应视为危险。',
    filePattern: CODE,
    linePatterns: [
      { re: /(?<![.\w$])(?:eval|Function)\s*\(/ },
      { re: /\bvm\s*\.\s*(?:runIn|compileFunction|createScript)/ },
      { re: /\bprocess\s*\.\s*binding\s*\(/ },
      { re: /\bModule\s*\.\s*_compile\s*\(/ },
      { re: /(?<![.\w$])(?:eval|exec)\s*\(\s*(?:atob|Buffer\.from|base64|decodeURIComponent|unescape)/i },
    ],
    // Known-safe idioms on the same line suppress the finding: the classic
    // `new Function("return this")()` / `new Function("")()` globalThis
    // detection pattern used by bundled code.
    excludes: [
      /new\s+Function\s*\(\s*["']\s*["']\s*\)/,
      /new\s+Function\s*\(\s*["']return\s+(?:this|globalThis)["']\s*\)/,
    ],
  },
  {
    id: 'SEN-EXEC-004',
    name: 'eval-of-decoded',
    severity: 'high',
    category: 'execution',
    message: '对解码内容执行(eval(atob(...)) 等)',
    description: '先 base64/URI 解码再执行,是绕过静态检测的经典混淆手段。',
    recommendation: '视为恶意特征:正常插件不需要对解码后的字符串执行代码。',
    filePattern: CODE,
    contentPatterns: [
      {
        re: /(?:eval|Function|exec|runInNewContext)\s*\(\s*(?:atob|Buffer\.from|base64decode|decodeURIComponent|unescape|fromCharCode)\s*\(/i,
      },
    ],
  },

  // ─────────────────────────── credentials ───────────────────────────
  {
    id: 'SEN-CRED-001',
    name: 'credential-file-read',
    severity: 'critical',
    category: 'credentials',
    message: '读取凭据文件(SSH 私钥 / AWS / npmrc / kubeconfig 等)',
    description: '代码读取 ~/.ssh、~/.aws/credentials、.npmrc、.netrc、kubeconfig、docker config、.git-credentials 等敏感文件。',
    recommendation: '拒绝安装。DSH 插件没有读取用户私钥的任何正当理由。',
    filePattern: CODE,
    linePatterns: [
      {
        re: /(?:readFile|readFileSync|createReadStream|openSync|require\s*\(\s*["'`])[^;\n]{0,160}?(?:\.ssh[\\\/]|id_rsa|id_ed25519|\.aws[\\\/]|credentials|\.npmrc|\.netrc|\.kube[\\\/]|\.docker[\\\/]config|\.git-credentials)/i,
      },
      {
        re: /(?:\.ssh[\\\/]|id_rsa|id_ed25519|\.aws[\\\/]credentials|\.npmrc|\.netrc|\.kube[\\\/]|\.git-credentials)[^;\n]{0,120}?(?:readFile|cat|type\s+)/i,
      },
    ],
  },
  {
    id: 'SEN-CRED-002',
    name: 'env-credential-access',
    severity: 'high',
    category: 'credentials',
    message: '读取环境变量中的凭据(API key / token / secret)',
    description: '代码访问 process.env 中名称含 API_KEY/TOKEN/SECRET/PASSWORD 或知名厂商前缀(DeepSeek/OpenAI/Anthropic/GitHub/AWS)的变量。',
    recommendation: '确认凭据读取是否功能必需(如官方 API 客户端),以及凭据是否仅用于本机调用、绝不出网。',
    filePattern: CODE,
    linePatterns: [
      {
        re: /process\s*\.\s*env\s*\.?\s*\[?["'`]?[A-Za-z_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE_KEY|AUTH)[A-Za-z_]*["'`]?\]?/i,
      },
      {
        re: /process\s*\.\s*env\s*\.?\s*\[?["'`]?(?:DEEPSEEK|OPENAI|ANTHROPIC|GITHUB|AWS|AZURE|GOOGLE|HF_|HUGGING)[A-Za-z_]*["'`]?\]?/i,
      },
    ],
  },
  {
    id: 'SEN-CRED-003',
    name: 'hardcoded-secret',
    severity: 'high',
    category: 'credentials',
    message: '疑似硬编码密钥',
    description: '代码中出现形似真实 API key / token 的字符串(sk-…、AKIA…、ghp_…、JWT 等)。',
    recommendation: '从仓库中移除并轮换该密钥。若为文档示例,应使用明显占位符(如 sk-xxx…)。',
    filePattern: CODE,
    linePatterns: SECRET_PATTERNS.map((p) => ({ re: p.re, note: p.name })),
  },
  {
    id: 'SEN-CRED-004',
    name: 'dotenv-loading',
    severity: 'medium',
    category: 'credentials',
    message: '加载 .env / dotenv',
    description: '插件读取 .env 或环境文件。本机开发场景常见,但需确认 .env 内容不会离开本机。',
    recommendation: '确认加载 .env 后仅在本机进程内使用,不随网络请求或日志外传。',
    filePattern: CODE,
    linePatterns: [
      { re: /\b(?:dotenv|loadEnvFile)\s*\(/ },
      { re: /(?:readFileSync|readFile|parse)[^;\n]{0,60}?["'`]\.env["'`]/i },
      { re: /\brequire\s*\(\s*["']dotenv["']\s*\)/ },
    ],
  },
  {
    id: 'SEN-CRED-005',
    name: 'credential-file-write',
    severity: 'medium',
    category: 'credentials',
    message: '写入凭据文件',
    description: '代码向 .ssh/.aws/.npmrc 等敏感路径写入内容(注入密钥或篡改配置)。',
    recommendation: '确认写入目标与用途;向用户凭据目录写入任何内容都应视为高风险行为。',
    filePattern: CODE,
    linePatterns: [
      {
        re: /(?:writeFile|writeFileSync|appendFile|createWriteStream|chmod)\s*\([^)]{0,160}?(?:\.ssh[\\\/]|id_rsa|id_ed25519|\.aws[\\\/]|\.npmrc|\.netrc|\.git-credentials)/i,
      },
    ],
  },

  // ─────────────────────────── exfiltration ───────────────────────────
  {
    id: 'SEN-EXFIL-001',
    name: 'suspicious-endpoint',
    severity: 'critical',
    category: 'exfiltration',
    message: '可疑数据外传端点(webhook / pastebin / 隧道 / 监听服务)',
    description: '代码向已知的"接收任意数据"类服务发起请求:webhook.site、requestbin、pastebin、Discord webhook、Telegram bot、ngrok/serveo 隧道、oast/interactsh 等。',
    recommendation: '拒绝安装。正常插件不会把数据发往这些端点。',
    filePattern: CODE,
    linePatterns: [
      {
        re: /https?:\/\/[^"'`\s)]{0,120}?(?:webhook\.site|requestbin\.com|pastebin\.com|discord(?:app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|ngrok\.(?:io|app)|serveo\.net|localtunnel\.me|smee\.io|oast\.(?:me|online|fun|pro)|interact\.sh|webhook\.cc|pipedream\.net|requestcatcher\.com)/i,
      },
      {
        re: /(?:fetch|axios|XMLHttpRequest|sendBeacon|http\.request|https\.request)\s*\([^)]{0,200}?(?:webhook\.site|requestbin|pastebin|discord|api\.telegram|ngrok|serveo|oast\.|interact\.sh)/i,
      },
    ],
  },
  {
    id: 'SEN-EXFIL-002',
    name: 'network-with-secrets',
    severity: 'high',
    category: 'exfiltration',
    message: '网络调用携带凭据或环境变量',
    description: '网络请求的参数/头/体中拼接了 process.env 或密钥变量,存在把凭据外传的风险。',
    recommendation: '确认请求目标完全可信,且凭据绝不出本机。任何将 env 拼进 URL 查询参数的行为都应视为危险。',
    filePattern: CODE,
    contentPatterns: [
      {
        re: /(?:fetch|axios|XMLHttpRequest|sendBeacon|http\.request|https\.request)[^;]{0,300}process\s*\.\s*env[^;]{0,200}/is,
      },
      {
        re: /(?:fetch|axios|XMLHttpRequest|sendBeacon|https?\.request)\s*\([^)]{0,120}?["'`][^"'`]{0,120}?=[^"'`]{0,60}(?:api[_-]?key|token|secret|password|authorization)/is,
      },
    ],
  },
  {
    id: 'SEN-EXFIL-003',
    name: 'encoded-env-in-network',
    severity: 'medium',
    category: 'exfiltration',
    message: '网络调用中编码(加密/base64)处理凭据',
    description: '请求前对 env/密钥做 base64 或编码处理,通常用于规避 URL 字符限制或检测。',
    recommendation: '确认编码目的;若为"让凭据不那么显眼"而编码,按外传处理。',
    filePattern: CODE,
    contentPatterns: [
      {
        re: /(?:atob|btoa|Buffer\.from\s*\(\s*[^)]{0,80}base64|encodeURIComponent)[^;]{0,200}?process\s*\.\s*env[^;]{0,120}/is,
      },
    ],
  },

  // ─────────────────────────── obfuscation ───────────────────────────
  {
    id: 'SEN-OBF-001',
    name: 'encoded-payload',
    severity: 'high',
    category: 'obfuscation',
    message: '代码中存在大段编码载荷(base64 / 十六进制 / unicode 转义)',
    description: '源码中出现超过 200 字符的 base64、连续 40+ 个 \\x 十六进制转义或 20+ 个 \\u unicode 转义。混淆是恶意插件最常见的自我保护手段。',
    recommendation: '先解码再判断:若解码结果是可读代码或数据且无文档说明,按恶意处理。',
    filePattern: CODE,
    linePatterns: [
      { re: /[A-Za-z0-9+/]{200,}={0,2}/ },
      { re: /(?:\\x[0-9a-fA-F]{2}){40,}/ },
      { re: /(?:\\u[0-9a-fA-F]{4}){20,}/ },
      { re: /(?:\b[A-Za-z0-9+/]{80,}\b)/ },
    ],
  },
  {
    id: 'SEN-OBF-002',
    name: 'minified-single-line',
    severity: 'medium',
    category: 'obfuscation',
    message: '超长单行代码(疑似压缩混淆)',
    description: '单个代码行超过 30KB。合法插件也可能打包产物,但超长单行是隐藏恶意逻辑的常用手法,需人工解压审阅。',
    recommendation: '格式化后审阅;若为构建产物,对比其与源码仓库的对应关系。',
    filePattern: CODE,
    linePatterns: [{ re: /^.{30000,}$/ }],
  },
  {
    id: 'SEN-OBF-003',
    name: 'decode-then-exec',
    severity: 'low',
    category: 'obfuscation',
    message: '解码函数与动态执行混用',
    description: 'decodeURIComponent/unescape/fromCharCode 与 eval/Function 出现在同一文件。',
    recommendation: '确认用途;此类组合常见于混淆载荷。',
    filePattern: CODE,
    contentPatterns: [
      {
        re: /(?:decodeURIComponent|unescape|String\.fromCharCode)[^;]{0,300}?(?:eval|Function|exec)\s*\(/is,
      },
    ],
  },

  // ─────────────────────────── install scripts ───────────────────────────
  {
    id: 'SEN-INST-001',
    name: 'install-script-present',
    severity: 'high',
    category: 'install',
    message: '存在安装生命周期脚本(preinstall / install / postinstall / prepare)',
    description: 'npm 安装时会自动执行这些脚本,且运行在用户完整权限下、不在任何沙箱之内——这是供应链攻击的经典投放点。',
    recommendation: '逐行审阅脚本内容;不确定就拒绝安装。可先以 --ignore-scripts 安装再手动审查。',
    filePattern: /package\.json$/i,
    contentPatterns: [
      {
        re: /"(?:preinstall|install|postinstall|prepare|prepublish)"\s*:\s*"[^"]{1,400}"/i,
      },
    ],
  },
  {
    id: 'SEN-INST-002',
    name: 'install-script-network',
    severity: 'critical',
    category: 'install',
    message: '安装脚本下载并执行远程内容',
    description: '安装脚本中包含 curl/wget/网络地址/base64/chmod 等,典型形状是 curl … | bash。',
    recommendation: '拒绝安装。安装即执行远程代码的插件不可信。',
    filePattern: /package\.json$/i,
    contentPatterns: [
      {
        re: /"(?:preinstall|install|postinstall|prepare|prepublish)"\s*:\s*"[^"]{0,400}?(?:curl|wget|https?:|base64|chmod\s+\+x|eval)[^"]{0,200}"/i,
      },
    ],
  },

  // ─────────────────────────── filesystem ───────────────────────────
  {
    id: 'SEN-FS-001',
    name: 'destructive-command',
    severity: 'critical',
    category: 'filesystem',
    message: '危险删除命令(rm -rf 指向主目录 / 根目录等)',
    description: '删除命令的目标是 ~、/、C:\、/home、/root、/etc 等关键路径。',
    recommendation: '拒绝安装。任何指向用户主目录或系统目录的递归删除都是恶意特征。',
    filePattern: CODE,
    linePatterns: [
      {
        re: /(?:rm|del)\s+(?:-rf|-fr|-\s*r\s*f|[-/]s\s+[-/]q)[^;&|]{0,80}?(?:~|\/home\/|\/root|\/etc\/|\/usr\/|C:\\|%USERPROFILE%|%HOMEDRIVE%|\$HOME|\\$home)/i,
      },
      {
        re: /(?:rm|del)\s+(?:-rf|-fr)[^;&|]{0,80}?["'`]?\s*(?:\/|\.\s*;|[A-Za-z]:[\\/])\s*["'`]?/i,
      },
    ],
  },
  {
    id: 'SEN-FS-002',
    name: 'write-outside-workspace',
    severity: 'medium',
    category: 'filesystem',
    message: '写入工作区之外的绝对路径',
    description: '代码向 /etc、C:\、用户主目录等绝对路径写入文件。',
    recommendation: '确认写入目标;插件默认应只写自己的数据目录。',
    filePattern: CODE,
    linePatterns: [
      {
        re: /(?:writeFile|writeFileSync|appendFile|createWriteStream|mkdir|mkdirSync)\s*\([^)]{0,120}?(?:["'`]\/etc\/|["'`]\/usr\/|["'`]\/var\/|["'`]\/home\/|["'`]C:\\|["'`][A-Za-z]:\\|process\.env\.HOME|os\.homedir\s*\(\s*\)\s*\+)/i,
      },
    ],
  },
  {
    id: 'SEN-FS-003',
    name: 'permission-mutation',
    severity: 'medium',
    category: 'filesystem',
    message: '修改权限 / 提权(chmod / chown / sudo / setuid)',
    description: '代码修改文件权限或以更高权限执行。',
    recommendation: '确认必要性;插件代码中出现 sudo/提权应视为高度可疑。',
    filePattern: CODE,
    linePatterns: [
      { re: /\b(?:chmod|chown|sudo|setuid|setgid|chflags)\s*\(|["'`](?:chmod|chown|sudo|setuid)[ "'`]/i },
    ],
  },
  {
    id: 'SEN-FS-004',
    name: 'tempfile-in-exec',
    severity: 'low',
    category: 'filesystem',
    message: '执行命令中使用临时目录(/tmp 等)',
    description: 'shell 命令写入 /tmp 或 %TEMP%——配合下载执行是常见攻击链。',
    recommendation: '确认临时文件用途与清理逻辑。',
    filePattern: CODE,
    linePatterns: [
      { re: /(?:exec|execSync|spawn|spawnSync|system|popen)\s*\([^)]{0,160}?(?:\/tmp\/|%TEMP%|os\.tmpdir|mkdtemp)/i },
    ],
  },

  // ─────────────────────────── network ───────────────────────────
  {
    id: 'SEN-NET-001',
    name: 'network-call',
    severity: 'medium',
    category: 'network',
    message: '发起网络请求(fetch / http / WebSocket / 套接字)',
    description: '插件存在出网能力。本身不一定是恶意(搜索、API 客户端等),但必须逐处确认请求目标与携带数据。',
    recommendation: '列出所有请求端点;确认无凭据、无工作区内容外传。',
    filePattern: CODE,
    linePatterns: [
      { re: /\b(?:fetch|axios|XMLHttpRequest|sendBeacon|WebSocket|EventSource)\s*\(/ },
      { re: /\b(?:http|https)\.(?:request|get)\s*\(/ },
      { re: /\b(?:net|dgram)\.(?:connect|createConnection|createSocket)\s*\(/ },
    ],
  },
  {
    id: 'SEN-NET-002',
    name: 'hardcoded-ip',
    severity: 'low',
    category: 'network',
    message: '代码中出现非本机的硬编码 IP 地址',
    description: '源码中直接出现公网 IPv4 字面量(排除 127.x / 10.x / 192.168.x / 172.16-31.x / 0.x / 255.x)。',
    recommendation: '确认该地址的用途与归属。',
    filePattern: CODE,
    linePatterns: [
      {
        re: /["'`](?!127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?!\.)["'`]/,
      },
    ],
  },

  // ─────────────────────────── manifest / DSH bundle compliance ───────────────────────────
  {
    id: 'SEN-MAN-001',
    name: 'missing-package-manifest',
    severity: 'medium',
    category: 'manifest',
    message: '未找到 package.json',
    description: '扫描目标不是 npm 包结构,无法作为 DSH bundle 安装。',
    recommendation: '确认扫描的是插件仓库根目录。',
  },
  {
    id: 'SEN-MAN-002',
    name: 'not-a-dsh-bundle',
    severity: 'high',
    category: 'manifest',
    message: '不是 DSH bundle(缺少 dsh.bundle 声明)',
    description: 'package.json 中没有 dsh.bundle,`dsh plugin add` 不会激活其任何层。',
    recommendation: '若目标是 DSH 插件,补上 dsh.bundle.patch 声明;否则此仓库无法以插件形式安装。',
  },
  {
    id: 'SEN-MAN-003',
    name: 'patch-file-missing',
    severity: 'high',
    category: 'manifest',
    message: '声明的 patch 文件不存在',
    description: 'dsh.bundle.patch 指向的文件在包内缺失,安装后插件层不会生效(或安装失败)。',
    recommendation: '核对 files 列表与 patch 路径。',
  },
  {
    id: 'SEN-MAN-004',
    name: 'patch-row-invalid',
    severity: 'medium',
    category: 'manifest',
    message: 'patch 中存在缺少 id 或 name 的行',
    description: 'cordis.patch.yml 的行解析失败,loader 可能拒绝该层。',
    recommendation: '检查 patch 的 YAML 结构(id + name 必填)。',
  },
  {
    id: 'SEN-MAN-005',
    name: 'patch-entry-unresolvable',
    severity: 'medium',
    category: 'manifest',
    message: 'patch 引用的插件模块无法解析',
    description: 'patch 行 name 指向的子路径在包内不存在(或未在 exports 中声明)。',
    recommendation: '核对 name 子路径与 exports 映射。',
  },
  {
    id: 'SEN-MAN-006',
    name: 'plugin-entry-invalid',
    severity: 'high',
    category: 'manifest',
    message: '插件入口无效(缺少 name 或 apply 导出)',
    description: '入口模块未导出 Cordis 插件协议要求的 name/apply,加载会失败或静默无行为。',
    recommendation: '补上 export const name 与 export function apply(ctx)。',
  },
  {
    id: 'SEN-MAN-007',
    name: 'license-missing',
    severity: 'low',
    category: 'hygiene',
    message: '缺少许可证(license 字段)',
    description: 'package.json 未声明 license,安装与再分发存在法律风险。',
    recommendation: '补上 license 字段(如 MIT)。',
  },
  {
    id: 'SEN-MAN-008',
    name: 'description-missing',
    severity: 'low',
    category: 'hygiene',
    message: '缺少描述(description 字段)',
    description: 'package.json 未声明 description。',
    recommendation: '补上简短描述。',
  },
])

/** Rules that are purely manifest/hygiene and produce one finding per target. */
export const MANIFEST_RULES = Object.freeze(RULES.filter((r) => r.category === 'manifest' || r.category === 'hygiene'))

export function severityWeight(severity) {
  return SEVERITY_WEIGHT[severity] ?? 0
}
