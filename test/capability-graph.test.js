import assert from 'node:assert/strict'
import { test } from 'node:test'
import { buildCapabilityGraph, evaluateCapabilityPolicy } from '../engine/semantic/capability-graph.js'

test('capability graph normalizes observed tool capabilities and attack paths', () => {
  const graph = buildCapabilityGraph([
    { ruleId: 'SEN-AGENT-001', file: 'index.js', line: 4, toolName: 'run', attackChainId: 'chain-1' },
    { ruleId: 'SEN-TAINT-001', file: 'index.js', line: 5, toolName: 'run', attackChainId: 'chain-1' },
    { ruleId: 'SEN-AGENT-004', file: 'net.js', line: 2, toolName: 'send' },
  ])
  assert.equal(graph.complete, true)
  assert.deepEqual(graph.capabilities, ['credential-access', 'network', 'shell'])
  assert.equal(graph.tools.length, 2)
  assert.equal(graph.tools[0].name, 'run')
  assert.deepEqual(graph.attackPaths, [{ id: 'chain-1', capabilities: ['credential-access', 'shell'], findingCount: 2 }])
})

test('capability policy reports undeclared observed powers', () => {
  const graph = buildCapabilityGraph([{ ruleId: 'SEN-AGENT-001', file: 'index.js', line: 4, toolName: 'run' }])
  const findings = evaluateCapabilityPolicy(graph, { run: ['network'] })
  assert.equal(findings.length, 1)
  assert.equal(findings[0].ruleId, 'SEN-AGENT-006')
  assert.deepEqual(findings[0].capabilities, ['shell'])
})
