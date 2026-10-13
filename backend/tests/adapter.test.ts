/**
 * Adapter tests: real DSH event mapping, frame decoding, and the log tailer.
 *
 * @module dsh-pocket-monitor/tests/adapter.test
 */

import { strict as assert } from 'node:assert'
import { rm, stat, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { zstdCompressSync, constants } from 'node:zlib'
import { DshSessionSource, normalisePath, projectKey, resolveDshHome } from '../src/adapters/dsh/sessions.ts'
import { SessionLogTailer } from '../src/adapters/dsh/session/log-tailer.ts'
import { decodeFrameLines, scanZstdFrames } from '../src/adapters/dsh/session/zstd-frames.ts'
import type { DshSessionHeader, SessionFoldState } from '../src/adapters/dsh/session/session-model.ts'
import {
  createFoldState,
  foldEvent,
  oneLine,
  parseSessionRow,
  projectSession,
  readAssistantContent,
  summariseArguments,
  summariseToolResult,
} from '../src/adapters/dsh/session/session-model.ts'
import { buildSessionLog, event, frame, tempDir, writeSessionLog } from './helpers.ts'

test('projectKey matches the DSH project-directory encoding', () => {
  assert.equal(projectKey('C:\\Users\\18500\\Desktop\\program\\personal\\3_dsh_remote'), '--C-Users-18500-Desktop-program-personal-3_dsh_remote--')
  assert.equal(projectKey('C:\\Users\\18500'), '--C-Users-18500--')
  assert.equal(projectKey('/home/user/proj'), '--home-user-proj--')
  // Separator runs collapse, other characters escape as ~XXXX.
  assert.equal(projectKey('C:\\\\double\\\\sep'), '--C-double-sep--')
  assert.equal(projectKey('C:\\a b'), '--C-a~0020b--')
  assert.throws(() => projectKey(''))
})

test('resolveDshHome honours DSH_HOME and falls back to ~/.dsh', () => {
  assert.equal(resolveDshHome({ DSH_HOME: 'D:\\custom\\dsh' }), 'D:\\custom\\dsh')
  assert.ok(resolveDshHome({}).endsWith('.dsh'))
})

test('scanZstdFrames finds every complete frame and reports a torn tail', () => {
  const a = frame(['{"type":"session","version":4,"id":"x","createdAt":1}'])
  const b = frame(['{"type":"turn/start","seq":0,"time":2,"data":{"turn":1}}'])
  const whole = Buffer.concat([a, b])
  const scan = scanZstdFrames(whole)
  assert.equal(scan.frames.length, 2)
  assert.equal(scan.tornStart, undefined)

  const torn = scanZstdFrames(Buffer.concat([a, b.subarray(0, b.length - 3)]))
  assert.equal(torn.frames.length, 1)
  assert.equal(torn.tornStart, a.length)

  assert.throws(() => scanZstdFrames(Buffer.from('not zstd at all, definitely longer than four bytes')))
})

test('a torn final frame is decoded only after the rest of the batch lands', () => {
  const a = frame(['{"type":"session","version":4,"id":"x","createdAt":1}'])
  const b = frame(['{"type":"turn/start","seq":0,"time":2,"data":{"turn":1}}'])
  const torn = Buffer.concat([a, b.subarray(0, Math.floor(b.length / 2))])
  const scan = scanZstdFrames(torn)
  assert.equal(scan.frames.length, 1, 'half a frame must not be treated as complete')
  assert.equal(scan.tornStart, a.length)
})

test('decodeFrameLines splits one frame into its JSONL rows', () => {
  const lines = ['{"a":1}', '{"b":2}']
  const bytes = frame(lines)
  const scan = scanZstdFrames(bytes)
  assert.deepEqual(decodeFrameLines(bytes, scan.frames[0]), lines)
})

test('parseSessionRow accepts headers and events, rejects junk', () => {
  const header = parseSessionRow('{"type":"session","version":4,"id":"s","createdAt":5,"cwd":"C:\\\\w"}')
  assert.ok(header !== undefined && 'version' in header)
  assert.equal((header as DshSessionHeader).cwd, 'C:\\w')

  const parsed = parseSessionRow('{"type":"tool/call","seq":3,"time":9,"data":{"name":"pwsh"}}')
  assert.ok(parsed !== undefined && !('version' in parsed))
  assert.equal(parsed.type, 'tool/call')
  assert.deepEqual(parsed.data, { name: 'pwsh' })

  assert.equal(parseSessionRow('not json'), undefined)
  assert.equal(parseSessionRow('{"nope":true}'), undefined)
  assert.equal(parseSessionRow('{"type":"turn/start"}'), undefined, 'a missing envelope seq/time is not an event')
})

test('readAssistantContent and argument summaries keep phone payloads small', () => {
  const content = readAssistantContent({
    content: [
      { type: 'reasoning', text: 'think' },
      { type: 'text', text: 'hello' },
      { type: 'tool-call', id: 'c1', name: 'pwsh', arguments: '{"command":"ls"}' },
      { type: 'tool-call', name: 'no-id' },
    ],
  })
  assert.equal(content.reasoning, 'think')
  assert.equal(content.text, 'hello')
  assert.equal(content.toolCalls.length, 1)
  assert.equal(content.toolCalls[0]?.name, 'pwsh')

  assert.equal(summariseArguments('{"description":"List files","command":"Get-ChildItem"}'), 'description=List files · command=Get-ChildItem')
  assert.equal(summariseArguments('{"a":1,"b":2}'), 'keys: a, b')
  assert.equal(summariseArguments(undefined), '(no arguments)')
  assert.equal(summariseArguments('raw text'), 'raw text')

  assert.deepEqual(summariseToolResult({ content: [{ type: 'text', text: 'ok' }] }), { detail: 'ok', isError: false })
  assert.deepEqual(summariseToolResult({ isError: true }), { detail: 'failed (no output)', isError: true })
  assert.ok(oneLine('a'.repeat(500)).length <= 220)
})

/** Fold real events through the production fold so projection sees real state. */
function foldOf(events: ReadonlyArray<{ type: string; seq: number; time: number; data: unknown }>): SessionFoldState {
  const state = createFoldState({ type: 'session', version: 4, id: 's-test', createdAt: 1_000, cwd: 'C:\\w' })
  for (const entry of events) {
    foldEvent(state, { type: entry.type, seq: entry.seq, time: entry.time, data: (entry.data ?? {}) as Record<string, unknown> })
  }
  return state
}

test('projectSession derives running state and open tool calls from real event shapes', () => {
  const events = [
    event('turn/start', 0, 1_000, { turn: 1 }),
    event('step/start', 1, 1_050, { turn: 1, step: 1 }),
    event('tool/call', 2, 1_100, { turn: 1, step: 1, callId: 'c1', name: 'pwsh', arguments: '{"description":"run tests"}' }),
  ]
  const { view, timeline } = projectSession(foldOf(events), 2_000)
  assert.equal(view.state, 'running')
  assert.equal(view.turn, 1)
  assert.equal(view.step, 1)
  assert.equal(view.runDurationMs, 1_000)
  assert.equal(view.currentTools.length, 1)
  assert.equal(view.currentTools[0]?.name, 'pwsh')
  assert.equal(view.currentTools[0]?.durationMs, 900)
  assert.equal(view.currentTools[0]?.status, 'running')
  assert.equal(view.pendingApprovals.length, 0)
  assert.ok(timeline.some((entry) => entry.title === '工具调用：pwsh'))
})

test('projectSession maps tool results, failures, and turn-end reasons', () => {
  const events = [
    event('turn/start', 0, 1_000, { turn: 1 }),
    event('tool/call', 1, 1_100, { turn: 1, step: 1, callId: 'c1', name: 'pwsh', arguments: '{}' }),
    event('tool/result', 2, 1_900, {
      turn: 1,
      step: 1,
      toolCallId: 'c1',
      message: { role: 'tool', isError: true, content: [{ type: 'text', text: 'boom' }] },
    }),
    event('turn/end', 3, 2_000, { turn: 1, reason: { kind: 'error', error: { message: 'provider exploded' } } }),
  ]
  const { view, timeline } = projectSession(foldOf(events), 3_000)
  assert.equal(view.state, 'failed')
  assert.equal(view.currentTools.length, 0)
  assert.equal(view.recentTools.length, 1)
  assert.equal(view.recentTools[0]?.status, 'failed')
  assert.equal(view.recentTools[0]?.durationMs, 800)
  const end = timeline.find((entry) => entry.kind === 'turn' && entry.level === 'error')
  assert.ok(end !== undefined)
  assert.match(end.title, /出错/)
  assert.equal(end.detail, 'provider exploded')
})

test('projectSession tracks pending approvals until the matching decision arrives', () => {
  const asked = event('approval/asked', 2, 1_500, { id: 'a1', toolName: 'pwsh', callId: 'c1', reason: '需要执行命令' })
  const pendingFold = foldOf([event('turn/start', 0, 1_000, { turn: 1 }), event('step/start', 1, 1_200, { turn: 1, step: 1 }), asked])
  const pendingView = projectSession(pendingFold, 2_000).view
  assert.equal(pendingView.state, 'waiting-approval')
  assert.equal(pendingView.pendingApprovals.length, 1)
  assert.equal(pendingView.pendingApprovals[0]?.toolName, 'pwsh')
  assert.equal(pendingView.pendingApprovals[0]?.reason, '需要执行命令')

  const decidedFold = foldOf([
    event('turn/start', 0, 1_000, { turn: 1 }),
    event('step/start', 1, 1_200, { turn: 1, step: 1 }),
    asked,
    event('approval/decided', 3, 1_800, { id: 'a1', outcome: 'allowed-once' }),
  ])
  const decidedView = projectSession(decidedFold, 2_000).view
  assert.equal(decidedView.pendingApprovals.length, 0)
  assert.equal(decidedView.state, 'running')
})

test('projectSession labels permission posture and reports idle reasons honestly', () => {
  const events = [
    event('permission/preset', 0, 1_000, { preset: 'workspace-write' }),
    event('sandbox/mode', 1, 1_000, { mode: 'workspace-write' }),
    event('approval/policy', 2, 1_000, { policy: 'ask' }),
    event('turn/start', 3, 1_100, { turn: 1 }),
    event('turn/end', 4, 1_600, { turn: 1, reason: { kind: 'completed' } }),
  ]
  const { view } = projectSession(foldOf(events), 2_000)
  assert.equal(view.approvalPolicy, 'ask')
  assert.equal(view.permissionPreset, 'workspace-write')
  assert.equal(view.sandboxMode, 'workspace-write')
  assert.equal(view.state, 'idle')
  assert.match(view.stateReason, /已完成/)

  const empty = projectSession(foldOf([]), 2_000).view
  assert.equal(empty.state, 'idle')
  assert.match(empty.stateReason, /还没有事件/)
})

test('SessionLogTailer reads only new frames and reports a torn batch', async () => {
  const root = await tempDir('dpm-tailer-')
  try {
    const specEvents = [
      event('turn/start', 0, 1_000, { turn: 1 }),
      event('tool/call', 1, 1_100, { turn: 1, step: 1, callId: 'c1', name: 'pwsh', arguments: '{}' }),
    ]
    const path = join(root, 'session.v4.jsonl.zstd')
    await writeFile(path, buildSessionLog({ id: 'tailer', cwd: 'C:\\w', events: specEvents }))
    const tailer = new SessionLogTailer(path)

    const first = await tailer.update()
    assert.equal(first.newEvents.length, 2)
    assert.equal(tailer.state?.totalEvents, 2)
    const second = await tailer.update()
    assert.equal(second.changed, false)
    assert.equal(second.newEvents.length, 0)

    // Append one more frame (a new durable batch).
    const extra = frame([JSON.stringify(event('turn/end', 2, 1_500, { turn: 1, reason: { kind: 'completed' } }))])
    const before = (await stat(path)).size
    const { appendFile } = await import('node:fs/promises')
    await appendFile(path, extra)
    const third = await tailer.update()
    assert.equal(third.newEvents.length, 1)
    assert.equal(third.newEvents[0]?.type, 'turn/end')
    assert.ok((await stat(path)).size > before)

    // Grow the file with a half-written frame: nothing new may be decoded.
    const half = extra.subarray(0, Math.floor(extra.length / 2))
    await appendFile(path, half)
    const fourth = await tailer.update()
    assert.equal(fourth.newEvents.length, 0)
    assert.equal(tailer.state?.totalEvents, 3)

    // Complete it: exactly the missing event appears.
    await appendFile(path, extra.subarray(Math.floor(extra.length / 2)))
    const fifth = await tailer.update()
    assert.equal(fifth.newEvents.length, 1)
    assert.equal(tailer.state?.totalEvents, 4)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('a damaged middle section is reported without blocking the frames after it', async () => {
  const root = await tempDir('dpm-tailer-damaged-')
  try {
    const first = buildSessionLog({ id: 'damaged', cwd: 'C:\\w', events: [event('turn/start', 0, 1_000, { turn: 1 })] })
    const second = frame([JSON.stringify(event('turn/end', 1, 1_100, { turn: 1, reason: { kind: 'completed' } }))])
    const third = frame([JSON.stringify(event('turn/start', 2, 1_200, { turn: 2 }))])
    // Corrupt one whole frame in the middle: its magic still reads as Zstandard,
    // so the structural scan rejects it instead of silently skipping.
    const corrupted = Buffer.from(second)
    corrupted.writeUInt8(0x08, 4)
    const path = join(root, 'session.v4.jsonl.zstd')
    await writeFile(path, Buffer.concat([first, corrupted, third]))

    const tailer = new SessionLogTailer(path)
    const result = await tailer.update()
    assert.ok((result.error ?? '') !== '', 'a damaged frame must surface as an error, not as silence')
    assert.match(result.error ?? '', /reserved frame-header bit/)
    // The frames decoded before the damage are still delivered.
    assert.equal(tailer.state?.totalEvents, 1)

    // A later pass must not loop forever on the same damage.
    const again = await tailer.update()
    assert.ok((again.error ?? '') !== '')
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('a torn tail never hides the complete frames that follow it', async () => {
  // Regression: the reader used to stop at the first torn frame, so a partially
  // written batch in the middle of a multi-chunk read hid every later event.
  const root = await tempDir('dpm-tailer-chunk-')
  try {
    const events = Array.from({ length: 12 }, (_, index) => event('turn/start', index, 1_000 + index, { turn: index + 1 }))
    const bytes = buildSessionLog({ id: 'chunked', cwd: 'C:\\w', events })
    const path = join(root, 'session.v4.jsonl.zstd')
    // Append the whole log plus half of a 13th frame: many tiny reads are needed.
    const torn = frame([JSON.stringify(event('turn/start', 12, 2_000, { turn: 13 }))])
    await writeFile(path, Buffer.concat([bytes, torn.subarray(0, Math.floor(torn.length / 2))]))

    const tailer = new SessionLogTailer(path, 64)
    const first = await tailer.update()
    assert.equal(first.newEvents.length, 12, 'every complete frame must be decoded')
    assert.equal(tailer.state?.totalEvents, 12)
    assert.equal(tailer.state?.openTurn, 12)

    // Finish the torn frame: the last event arrives, nothing is duplicated.
    const { appendFile } = await import('node:fs/promises')
    await appendFile(path, torn.subarray(Math.floor(torn.length / 2)))
    const second = await tailer.update()
    assert.equal(second.newEvents.length, 1)
    assert.equal(second.newEvents[0]?.seq, 12)
    assert.equal(tailer.state?.totalEvents, 13)
    assert.equal(tailer.state?.openTurn, 13)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('SessionLogTailer survives a truncated (replaced) artifact', async () => {  const root = await tempDir('dpm-tailer-reset-')
  try {
    const path = join(root, 'session.v4.jsonl.zstd')
    await writeFile(
      path,
      buildSessionLog({
        id: 'reset',
        cwd: 'C:\\w',
        events: [event('turn/start', 0, 1_000, { turn: 1 }), event('turn/end', 1, 1_100, { turn: 1, reason: { kind: 'completed' } })],
      }),
    )
    const tailer = new SessionLogTailer(path)
    await tailer.update()
    assert.equal(tailer.state?.totalEvents, 2)

    await writeFile(path, buildSessionLog({ id: 'reset', cwd: 'C:\\w', events: [event('turn/start', 0, 2_000, { turn: 9 })] }))
    const after = await tailer.update()
    assert.equal(after.restarted, true)
    assert.equal(tailer.state?.totalEvents, 1)
    assert.equal(tailer.state?.openTurn, 9)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('SessionLogTailer reports an unreadable artifact instead of throwing', async () => {
  const tailer = new SessionLogTailer(join(await tempDir('dpm-missing-'), 'nope.jsonl.zstd'))
  const result = await tailer.update()
  assert.equal(result.changed, false)
  assert.ok((result.error ?? '') !== '')
})

test('DshSessionSource discovers this workspace and projects real DSH logs', async () => {
  const root = await tempDir('dpm-home-')
  const workspace = 'C:\\Users\\18500\\Desktop\\program\\personal\\3_dsh_remote'
  try {
    // A session in a different project must not be picked up.
    await writeSessionLog(join(root, 'sessions'), { id: 'other', cwd: 'C:\\elsewhere', events: [event('turn/start', 0, 1, { turn: 1 })] })
    const mine = [
      event('permission/preset', 0, 1_000, { preset: 'workspace-write' }),
      event('approval/policy', 1, 1_000, { policy: 'ask' }),
      event('turn/start', 2, 1_100, { turn: 1 }),
      event('session/title', 3, 1_200, { title: '跑一下测试', messageSeqs: [2], source: { kind: 'fallback' } }),
      event('tool/call', 4, 1_300, { turn: 1, step: 1, callId: 'c1', name: 'pwsh', arguments: '{"description":"run tests"}' }),
      event('tool/result', 5, 1_800, { turn: 1, step: 1, toolCallId: 'c1', message: { role: 'tool', content: [{ type: 'text', text: 'all good' }] } }),
      event('approval/asked', 6, 1_900, { id: 'ap1', toolName: 'pwsh', callId: 'c9', reason: '需要提权' }),
    ]
    await writeSessionLog(join(root, 'sessions'), { id: 'session-mine', cwd: workspace, events: mine })

    const source = new DshSessionSource({ dshHome: root, workspace, pollIntervalMs: 1_000 })
    const snapshot = await source.snapshot()
    assert.equal(snapshot.payload.currentSessionId, 'session-mine')
    assert.equal(snapshot.payload.sessions.length, 1)
    const view = snapshot.payload.sessions[0]
    assert.ok(view !== undefined)
    assert.equal(view.title, '跑一下测试')
    assert.equal(view.approvalPolicy, 'ask')
    assert.equal(view.permissionPreset, 'workspace-write')
    assert.equal(view.state, 'waiting-approval')
    assert.equal(view.pendingApprovals.length, 1)
    assert.equal(view.recentTools.length, 1)
    assert.equal(view.eventCount, 7)
    assert.equal(source.timelineFor('session-mine').length, 7)
    assert.equal(snapshot.payload.capabilities.approvalDeciding, false)
    assert.equal(normalisePath(workspace), normalisePath(view.cwd))
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('DshSessionSource reports a missing project without inventing data', async () => {
  const root = await tempDir('dpm-home-empty-')
  try {
    const source = new DshSessionSource({ dshHome: root, workspace: 'C:\\nowhere\\at\\all', pollIntervalMs: 1_000 })
    const snapshot = await source.snapshot()
    assert.equal(snapshot.payload.sessions.length, 0)
    assert.equal(snapshot.payload.source.status, 'source-missing')
    assert.equal(snapshot.payload.currentSessionId, undefined)
    assert.match(snapshot.payload.source.message, /还没找到|没有会话日志/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('an unknown event type still reaches the timeline instead of being dropped', () => {
  const { timeline } = projectSession(foldOf([event('brand/new-event', 0, 1_000, { whatever: true })]), 1_500)
  assert.equal(timeline.length, 1)
  assert.equal(timeline[0]?.kind, 'other')
  assert.equal(timeline[0]?.title, 'brand/new-event')
})

test('corrupt frame structure is reported, not silently skipped', () => {
  // Reserved frame-header bit 3 set: a structurally invalid frame.
  const bad = Buffer.concat([Buffer.from([0x28, 0xb5, 0x2f, 0xfd, 0x08]), zstdCompressSync(Buffer.from('{}'))])
  assert.throws(() => scanZstdFrames(bad), /reserved frame-header bit/)
})
