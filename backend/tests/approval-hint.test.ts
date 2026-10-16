/**
 * Approval-hint tests: the one sentence the phone shows instead of a button that
 * cannot work.
 *
 * The example reasons are copied from real `approval/asked` events in this
 * machine's session logs, so the parser is exercised against the shapes DSH
 * actually writes.
 *
 * @module dsh-pocket-monitor/tests/approval-hint.test
 */

import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { describeApproval, approvalHintFields } from '../src/adapters/dsh/approval-hint.ts'
import { createFoldState, foldEvent, projectSession } from '../src/adapters/dsh/session/session-model.ts'

test('a real sandbox-escalation reason becomes an actionable sentence', () => {
  // Verbatim reason from a real approval/asked event on this machine.
  const reason =
    'escalate sandbox to danger-full-access: Vite/esbuild 构建需要以管道方式启动子进程，在受限沙箱下会被系统拒绝（spawn EPERM）；重建前端产物是必需步骤。'
  const described = describeApproval({ toolName: 'pwsh', reason, policy: 'ask' })
  assert.equal(described.kind, 'sandbox-escalation')
  assert.equal(described.label, '沙箱提权')
  assert.equal(described.target, 'danger-full-access')
  assert.match(described.hint, /把沙箱提升到 danger-full-access/)
  assert.match(described.hint, /执行命令行/)
  assert.match(described.hint, /请在运行 DSH 的电脑上批准/)
  assert.ok(described.hint.length < 400, '提示要短到能在手机上一眼看完')
})

test('a workspace-write escalation is reported with its own target', () => {
  const described = describeApproval({ toolName: 'pwsh', reason: 'escalate sandbox to workspace-write', policy: 'ask' })
  assert.equal(described.kind, 'sandbox-escalation')
  assert.equal(described.target, 'workspace-write')
  assert.match(described.hint, /workspace-write/)
})

test('permission, network, file and retry reasons each map to their own kind', () => {
  const permission = describeApproval({ toolName: 'read', reason: 'needs permission fs:read outside workspace' })
  assert.equal(permission.kind, 'permission')
  assert.match(permission.hint, /权限/)

  const network = describeApproval({ toolName: 'web_fetch', reason: ' requires network access to api.example.com' })
  assert.equal(network.kind, 'network-access')
  assert.match(network.hint, /联网/)

  const file = describeApproval({ toolName: 'write', reason: 'write outside workspace: C:\\Windows\\System32\\drivers\\etc\\hosts' })
  assert.equal(file.kind, 'file-access')
  assert.match(file.hint, /C:\\Windows\\System32\\drivers\\etc\\hosts/)

  const retry = describeApproval({
    toolName: 'pwsh',
    reason: 'The tool call was recorded but its outcome is unknown; retry only if the operation is idempotent.',
  })
  assert.equal(retry.kind, 'read-only-retry')
  assert.match(retry.hint, /重试/)
})

test('a never policy is explained as auto-rejection instead of a prompt', () => {
  const described = describeApproval({ toolName: 'pwsh', reason: 'requires approval', policy: 'never' })
  assert.equal(described.kind, 'approval-policy')
  assert.match(described.hint, /never/)
  assert.match(described.hint, /自动拒绝/)
})

test('an unknown reason still yields a usable sentence naming the tool', () => {
  const described = describeApproval({ toolName: 'custom-tool', reason: '', policy: 'ask' })
  assert.equal(described.kind, 'tool-permission')
  assert.match(described.hint, /custom-tool/)
  assert.match(described.hint, /请在运行 DSH 的电脑上/)

  const noReason = describeApproval({ toolName: 'pwsh' })
  assert.match(noReason.hint, /执行命令行/)
})

test('hint fields ride along on the session view pending approvals', () => {
  const state = createFoldState({ type: 'session', version: 4, id: 's-hint', createdAt: 1, cwd: 'C:\\w' })
  foldEvent(state, { type: 'approval/policy', seq: 0, time: 1_000, data: { policy: 'ask' } })
  foldEvent(state, { type: 'turn/start', seq: 1, time: 1_100, data: { turn: 1 } })
  foldEvent(state, {
    type: 'approval/asked',
    seq: 2,
    time: 1_200,
    data: { id: 'ap-hint', toolName: 'pwsh', callId: 'c1', reason: 'escalate sandbox to danger-full-access: needs to build' },
  })

  const { view } = projectSession(state, 2_000)
  assert.equal(view.pendingApprovals.length, 1)
  const request = view.pendingApprovals[0]
  assert.ok(request !== undefined)
  assert.equal(request.requiredAction, 'sandbox-escalation')
  assert.match(request.hint ?? '', /把沙箱提升到 danger-full-access/)
  assert.equal(view.state, 'waiting-approval')
})

test('an approval asked long before the display window is still reported', () => {
  // Regression guard: pending approvals used to be derived from the bounded
  // 400-event display window, so an older approval silently disappeared.
  const state = createFoldState({ type: 'session', version: 4, id: 's-old', createdAt: 1, cwd: 'C:\\w' })
  foldEvent(state, { type: 'approval/policy', seq: 0, time: 1, data: { policy: 'ask' } })
  foldEvent(state, { type: 'turn/start', seq: 1, time: 2, data: { turn: 1 } })
  foldEvent(state, { type: 'approval/asked', seq: 2, time: 3, data: { id: 'ap-old', toolName: 'pwsh', reason: 'escalate sandbox to danger-full-access: old request' } })
  for (let seq = 3; seq < 900; seq += 1) {
    foldEvent(state, { type: 'step/start', seq, time: 100 + seq, data: { turn: 1, step: seq } })
  }

  const { view } = projectSession(state, 10_000)
  assert.equal(view.eventCount, 900)
  assert.equal(view.pendingApprovals.length, 1, '窗口外的待审批不能被丢掉')
  assert.equal(view.pendingApprovals[0]?.id, 'ap-old')
  assert.equal(view.state, 'waiting-approval')
})

test('a decided approval stops being pending and is listed as decided', () => {
  const state = createFoldState({ type: 'session', version: 4, id: 's-done', createdAt: 1, cwd: 'C:\\w' })
  foldEvent(state, { type: 'turn/start', seq: 0, time: 1, data: { turn: 1 } })
  foldEvent(state, { type: 'approval/asked', seq: 1, time: 2, data: { id: 'ap-1', toolName: 'pwsh', reason: 'escalate sandbox to danger-full-access: x' } })
  foldEvent(state, { type: 'approval/decided', seq: 2, time: 3, data: { id: 'ap-1', outcome: 'allowed-once' } })

  const { view } = projectSession(state, 10)
  assert.equal(view.pendingApprovals.length, 0)
  assert.equal(view.state, 'running')
  assert.equal(state.decidedApprovals.length, 1)
  assert.equal(state.decidedApprovals[0]?.outcome, 'allowed-once')
})

test('approvalHintFields always returns both fields', () => {
  const fields = approvalHintFields({ toolName: 'read', reason: 'needs permission fs:read' })
  assert.equal(fields.requiredAction, 'permission')
  assert.ok(fields.hint.length > 0)
})
