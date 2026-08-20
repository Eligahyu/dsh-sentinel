const RULE_CAPABILITIES = new Map([
  ['SEN-AGENT-001', 'shell'],
  ['SEN-AGENT-002', 'filesystem-read'],
  ['SEN-AGENT-003', 'filesystem-write'],
  ['SEN-AGENT-004', 'network'],
  ['SEN-TAINT-001', 'credential-access'],
  ['SEN-TAINT-002', 'workspace-read'],
  ['SEN-TAINT-003', 'decode'],
  ['SEN-TAINT-004', 'shell'],
  ['SEN-TAINT-005', 'filesystem-write'],
])

const CAPABILITY_ORDER = [
  'credential-access', 'decode', 'filesystem-read', 'filesystem-write',
  'network', 'shell', 'workspace-read',
]

function capabilityForFinding(finding) {
  return RULE_CAPABILITIES.get(finding?.ruleId) ?? finding?.sink?.kind ?? ''
}

function sortedCapabilities(values) {
  return [...new Set(values)].sort((a, b) => CAPABILITY_ORDER.indexOf(a) - CAPABILITY_ORDER.indexOf(b) || a.localeCompare(b))
}

/** Build a stable, metadata-only capability graph from scanner evidence. */
export function buildCapabilityGraph(findings = []) {
  const toolMap = new Map()
  const pathMap = new Map()
  for (const finding of findings) {
    const capability = capabilityForFinding(finding)
    if (!capability) continue
    const toolName = finding.toolName || '(unbound)'
    const tool = toolMap.get(toolName) ?? { name: toolName, capabilities: [], findingCount: 0 }
    tool.capabilities.push(capability)
    tool.findingCount += 1
    toolMap.set(toolName, tool)
    if (finding.attackChainId) {
      const path = pathMap.get(finding.attackChainId) ?? { id: finding.attackChainId, capabilities: [], findingCount: 0 }
      path.capabilities.push(capability)
      path.findingCount += 1
      pathMap.set(finding.attackChainId, path)
    }
  }
  const tools = [...toolMap.values()]
    .map((tool) => ({ ...tool, capabilities: sortedCapabilities(tool.capabilities) }))
    .sort((a, b) => a.name.localeCompare(b.name))
  const attackPaths = [...pathMap.values()]
    .map((path) => ({ ...path, capabilities: sortedCapabilities(path.capabilities) }))
    .sort((a, b) => a.id.localeCompare(b.id))
  return {
    complete: true,
    tools,
    capabilities: sortedCapabilities(tools.flatMap((tool) => tool.capabilities)),
    attackPaths,
    failures: [],
  }
}

/** Compare observed capabilities against a declaration keyed by tool name. */
export function evaluateCapabilityPolicy(graph, declarations = {}) {
  const findings = []
  for (const tool of graph?.tools ?? []) {
    const declared = new Set(Array.isArray(declarations[tool.name]) ? declarations[tool.name] : [])
    const undeclared = tool.capabilities.filter((capability) => !declared.has(capability))
    if (undeclared.length === 0 || tool.name === '(unbound)') continue
    findings.push({
      ruleId: 'SEN-AGENT-006',
      severity: 'medium',
      category: 'agent',
      confidence: 'medium',
      message: `工具 ${tool.name} 使用了未声明能力(${undeclared.join(', ')})`,
      file: 'capability-policy',
      line: 1,
      snippet: tool.name,
      recommendation: '补充最小能力声明，或移除未授权的运行期副作用。',
      toolName: tool.name,
      capabilities: undeclared,
    })
  }
  return findings
}
