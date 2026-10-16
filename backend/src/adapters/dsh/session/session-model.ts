/**
 * Reading and folding DSH session logs into the monitor's own data model.
 *
 * Everything here is derived from verified DSH facts (see docs/dsh-integration.md):
 * the log is a concatenation of checksummed Zstandard frames, each holding JSONL
 * rows; the first row is the session header, every other row is one event with
 * the envelope `{ type, seq, time, data }`.
 *
 * @module dsh-pocket-monitor/adapters/dsh/session
 */

import type {
  DecidedApproval,
  MonitorEvent,
  PendingApproval,
  SessionState,
  SessionView,
  ToolActivity,
} from '../../../../../shared/types/index.ts'
import { approvalHintFields } from '../approval-hint.ts'

/** Physical session header as DSH writes it. */
export interface DshSessionHeader {
  readonly type: 'session'
  readonly version: number
  readonly id: string
  readonly createdAt: number
  readonly cwd?: string
  readonly isSeeded?: boolean
  readonly delegationDepth?: number
  readonly agentPreset?: string
}

/** One decoded logical session event. */
export interface DshSessionEvent {
  readonly type: string
  readonly seq: number
  readonly time: number
  readonly data: Record<string, unknown>
}

/** Header plus decoded events of one session artifact. */
export interface DshSessionArtifact {
  readonly header: DshSessionHeader
  readonly events: readonly DshSessionEvent[]
}

/** Maximum characters kept for any single-line phone-facing detail. */
const DETAIL_LIMIT = 220
/** Events kept per session in memory (newest win). */
export const EVENT_WINDOW = 400
/** Decided approvals kept per session for display. */
export const DECIDED_WINDOW = 20
/** A session whose log changed within this window counts as live. */
export const LIVE_WINDOW_MS = 8_000

/** Narrow an unknown value to a plain object record. */
function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

/** Coerce an unknown value to a finite number, when it is one. */
function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

/** Coerce an unknown value to a string, when it is one. */
function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined
}

/** Collapse whitespace and truncate a single-line summary. */
export function oneLine(text: string, limit = DETAIL_LIMIT): string {
  const flat = text.replace(/\s+/g, ' ').trim()
  return flat.length > limit ? `${flat.slice(0, limit - 1)}…` : flat
}

/** Parse one JSONL row into a header, an event, or nothing. */
export function parseSessionRow(row: string): DshSessionHeader | DshSessionEvent | undefined {
  let value: unknown
  try {
    value = JSON.parse(row)
  } catch {
    return undefined
  }
  const record = asRecord(value)
  if (record === undefined) return undefined
  const type = asString(record.type)
  if (type === undefined) return undefined
  if (type === 'session') {
    const id = asString(record.id)
    if (id === undefined) return undefined
    const version = asNumber(record.version)
    const createdAt = asNumber(record.createdAt)
    if (version === undefined || createdAt === undefined) return undefined
    return {
      type: 'session',
      version,
      id,
      createdAt,
      cwd: asString(record.cwd),
      isSeeded: record.isSeeded === true,
      delegationDepth: asNumber(record.delegationDepth),
      agentPreset: asString(record.agentPreset),
    }
  }
  const seq = asNumber(record.seq)
  const time = asNumber(record.time)
  if (seq === undefined || time === undefined) return undefined
  return { type, seq, time, data: asRecord(record.data) ?? {} }
}

/** Type guard: is this decoded row a header? */
export function isSessionHeader(row: DshSessionHeader | DshSessionEvent): row is DshSessionHeader {
  return row.type === 'session'
}

/** Tool call info extracted from an assistant message content block. */
export interface AssistantToolCall {
  readonly id: string
  readonly name: string
  readonly arguments: string
}

/** Extract text/reasoning/tool-call content from an assistant message payload. */
export function readAssistantContent(message: unknown): {
  text: string
  reasoning: string
  toolCalls: readonly AssistantToolCall[]
} {
  const content = asRecord(message)?.content
  let text = ''
  let reasoning = ''
  const toolCalls: AssistantToolCall[] = []
  if (!Array.isArray(content)) return { text, reasoning, toolCalls }
  for (const block of content) {
    const record = asRecord(block)
    if (record === undefined) continue
    const kind = asString(record.type)
    if (kind === 'text') text += asString(record.text) ?? ''
    else if (kind === 'reasoning') reasoning += asString(record.text) ?? ''
    else if (kind === 'tool-call') {
      const id = asString(record.id)
      const name = asString(record.name)
      if (id !== undefined && name !== undefined) {
        toolCalls.push({ id, name, arguments: asString(record.arguments) ?? '' })
      }
    }
  }
  return { text, reasoning, toolCalls }
}

/** Read the pipeline entry point the approval request would block on. */
export function readToolCallName(data: Record<string, unknown>): string {
  return asString(data.name) ?? 'unknown'
}

/** Summarise a tool call's raw argument JSON without leaking whole commands. */
export function summariseArguments(raw: string | undefined): string {
  if (raw === undefined || raw.trim() === '') return '(no arguments)'
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return oneLine(raw, 120)
  }
  const record = asRecord(parsed)
  if (record === undefined) return oneLine(raw, 120)
  const preferred = ['description', 'command', 'file_path', 'path', 'pattern', 'query', 'title', 'prompt']
  const parts: string[] = []
  for (const key of preferred) {
    const value = record[key]
    if (typeof value === 'string' && value.trim() !== '') parts.push(`${key}=${oneLine(value, 90)}`)
    if (parts.length >= 2) break
  }
  if (parts.length === 0) {
    const keys = Object.keys(record)
    return keys.length === 0 ? '(empty arguments)' : `keys: ${keys.slice(0, 6).join(', ')}`
  }
  return parts.join(' · ')
}

/** Summarise a tool result message into one line, marking failures. */
export function summariseToolResult(message: unknown): { detail: string; isError: boolean } {
  const record = asRecord(message)
  const isError = record?.isError === true
  const content = record?.content
  let text = ''
  if (Array.isArray(content)) {
    for (const block of content) {
      const b = asRecord(block)
      if (b === undefined) continue
      if (asString(b.type) === 'text') text += asString(b.text) ?? ''
    }
  }
  return { detail: text === '' ? (isError ? 'failed (no output)' : 'completed (no output)') : oneLine(text), isError }
}

/** Mutable fold state for one session log. */
export interface SessionFoldState {
  header: DshSessionHeader
  events: DshSessionEvent[]
  totalEvents: number
  lastEventAt: number
  openTurn?: number
  openTurnStartedAt?: number
  lastTurnEndReason?: string
  step?: number
  title?: string
  approvalPolicy?: string
  permissionPreset?: string
  sandboxMode?: string
  agentPreset?: string
  /**
   * Approvals asked but not yet decided.
   *
   * Maintained incrementally while folding, NOT derived from {@link events}:
   * that array is a bounded display window, so scanning it would silently drop
   * an approval asked more than {@link EVENT_WINDOW} events ago.
   */
  pendingApprovals: Map<string, PendingApproval>
  /** Decided approvals in log order, capped by {@link DECIDED_WINDOW}. */
  decidedApprovals: DecidedApproval[]
}

/** Create empty fold state for one decoded header. */
export function createFoldState(header: DshSessionHeader): SessionFoldState {
  return {
    header,
    events: [],
    totalEvents: 0,
    lastEventAt: header.createdAt,
    agentPreset: header.agentPreset,
    pendingApprovals: new Map(),
    decidedApprovals: [],
  }
}

/**
 * Fold one decoded event into the running state.
 *
 * @param state - mutable fold state for this session.
 * @param event - one decoded DSH event.
 */
export function foldEvent(state: SessionFoldState, event: DshSessionEvent): void {
  state.events.push(event)
  state.totalEvents += 1
  if (state.events.length > EVENT_WINDOW) state.events.splice(0, state.events.length - EVENT_WINDOW)
  state.lastEventAt = event.time
  const data = event.data
  switch (event.type) {
    case 'turn/start': {
      state.openTurn = asNumber(data.turn)
      state.openTurnStartedAt = event.time
      state.step = undefined
      break
    }
    case 'turn/end': {
      const reason = asRecord(data.reason)
      state.lastTurnEndReason = asString(reason?.kind) ?? 'unknown'
      state.openTurn = undefined
      state.openTurnStartedAt = undefined
      state.step = undefined
      break
    }
    case 'step/start':
    case 'step/end': {
      state.step = asNumber(data.step)
      break
    }
    case 'session/title': {
      state.title = asString(data.title) ?? state.title
      break
    }
    case 'approval/policy': {
      state.approvalPolicy = asString(data.policy) ?? state.approvalPolicy
      break
    }
    case 'permission/preset': {
      state.permissionPreset = asString(data.preset) ?? state.permissionPreset
      break
    }
    case 'sandbox/mode': {
      state.sandboxMode = asString(data.mode) ?? state.sandboxMode
      break
    }
    case 'agent-preset/selected': {
      state.agentPreset = asString(data.preset) ?? state.agentPreset
      break
    }
    case 'approval/asked': {
      const id = asString(data.id) ?? `seq-${event.seq}`
      const toolName = asString(data.toolName) ?? 'unknown'
      const reason = asString(data.reason)
      const request: PendingApproval = {
        id,
        toolName,
        callId: asString(data.callId),
        reason,
        sessionId: state.header.id,
        askedAt: event.time,
        policy: state.approvalPolicy,
        ...approvalHintFields({ toolName, reason, policy: state.approvalPolicy, sessionId: state.header.id }),
      }
      state.pendingApprovals.set(id, request)
      break
    }
    case 'approval/decided': {
      const id = asString(data.id) ?? `seq-${event.seq}`
      state.pendingApprovals.delete(id)
      state.decidedApprovals.push({
        id,
        sessionId: state.header.id,
        outcome: asString(data.outcome) ?? 'unknown',
        decidedAt: event.time,
      })
      if (state.decidedApprovals.length > DECIDED_WINDOW) {
        state.decidedApprovals.splice(0, state.decidedApprovals.length - DECIDED_WINDOW)
      }
      break
    }
    default:
      break
  }
}

/** Tool call collected from the log for the tool view. */
interface ToolCallRecord {
  readonly callId: string
  readonly name: string
  readonly arguments: string
  readonly time: number
  readonly turn: number
  readonly step: number
  result?: { readonly time: number; readonly isError: boolean; readonly detail: string }
}

/**
 * Build the phone-facing session view + timeline entries from folded events.
 *
 * @param state - folded state for one session.
 * @param now - current epoch milliseconds (injected for deterministic tests).
 * @returns the session view and the mapped timeline events.
 */
export function projectSession(
  state: SessionFoldState,
  now: number,
): { view: SessionView; timeline: MonitorEvent[] } {
  const sessionId = state.header.id
  const calls = new Map<string, ToolCallRecord>()
  const callOrder: string[] = []
  const timeline: MonitorEvent[] = []

  const push = (event: MonitorEvent): void => {
    timeline.push(event)
  }

  for (const event of state.events) {
    const data = event.data
    const base = { sessionId, seq: event.seq, time: event.time }
    switch (event.type) {
      case 'turn/start': {
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'turn',
          level: 'info',
          title: `第 ${asNumber(data.turn) ?? '?'} 轮开始`,
        })
        break
      }
      case 'turn/end': {
        const reason = asRecord(data.reason)
        const kind = asString(reason?.kind) ?? 'unknown'
        const level = kind === 'completed' ? 'success' : kind === 'error' ? 'error' : 'warn'
        const errorRecord = asRecord(reason?.error)
        const detail = kind === 'error' ? oneLine(asString(errorRecord?.message) ?? '未知错误') : undefined
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'turn',
          level,
          title: `第 ${asNumber(data.turn) ?? '?'} 轮结束：${turnEndLabel(kind)}`,
          detail,
        })
        break
      }
      case 'step/start':
      case 'step/end': {
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'step',
          level: 'info',
          title: `第 ${asNumber(data.turn) ?? '?'} 轮第 ${asNumber(data.step) ?? '?'} 步${event.type === 'step/start' ? '开始' : '结束'}`,
        })
        break
      }
      case 'tool/call': {
        const callId = asString(data.callId) ?? `seq-${event.seq}`
        const record: ToolCallRecord = {
          callId,
          name: readToolCallName(data),
          arguments: asString(data.arguments) ?? '',
          time: event.time,
          turn: asNumber(data.turn) ?? 0,
          step: asNumber(data.step) ?? 0,
        }
        calls.set(callId, record)
        callOrder.push(callId)
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'tool',
          level: 'info',
          title: `工具调用：${record.name}`,
          detail: summariseArguments(record.arguments),
        })
        break
      }
      case 'tool/result': {
        const callId = asString(data.toolCallId) ?? asString(asRecord(data.message)?.toolCallId) ?? ''
        const record = calls.get(callId)
        const summary = summariseToolResult(data.message)
        if (record !== undefined) {
          record.result = { time: event.time, isError: summary.isError, detail: summary.detail }
        }
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'tool',
          level: summary.isError ? 'error' : 'success',
          title: `工具结果：${record?.name ?? '工具'}`,
          detail: summary.detail,
        })
        break
      }
      case 'assistant/message': {
        const { text, reasoning, toolCalls } = readAssistantContent(data.message)
        for (const call of toolCalls) {
          if (!calls.has(call.id)) {
            calls.set(call.id, {
              callId: call.id,
              name: call.name,
              arguments: call.arguments,
              time: event.time,
              turn: asNumber(data.turn) ?? 0,
              step: asNumber(data.step) ?? 0,
            })
            callOrder.push(call.id)
          }
        }
        const body = text !== '' ? text : reasoning !== '' ? reasoning : toolCalls.length > 0 ? `（请求 ${toolCalls.length} 个工具调用）` : '（空消息）'
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'assistant',
          level: 'info',
          title: '助手回复',
          detail: oneLine(body),
        })
        break
      }
      case 'user/message': {
        const content = data.content
        let text = ''
        if (Array.isArray(content)) {
          for (const block of content) {
            const b = asRecord(block)
            if (b !== undefined && asString(b.type) === 'text') text += asString(b.text) ?? ''
          }
        }
        const source = asRecord(data.source)
        const sourceKind = asString(source?.kind) ?? 'unknown'
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'user',
          level: 'info',
          title: `用户输入（来源：${sourceLabel(sourceKind)}）`,
          detail: text === '' ? undefined : oneLine(text),
        })
        break
      }
      case 'command/run': {
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'command',
          level: 'info',
          title: `斜杠命令：/${asString(data.name) ?? '?'}`,
          detail: asString(data.args) === '' ? undefined : oneLine(asString(data.args) ?? ''),
        })
        break
      }
      case 'command/done': {
        const kind = asString(data.kind) ?? 'unknown'
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'command',
          level: kind === 'success' ? 'success' : 'error',
          title: `命令结束：${kind}`,
          detail: asString(data.text) === undefined ? undefined : oneLine(asString(data.text) ?? ''),
        })
        break
      }
      case 'approval/asked': {
        const toolName = asString(data.toolName) ?? 'unknown'
        const request = state.pendingApprovals.get(asString(data.id) ?? '')
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'approval',
          level: 'warn',
          title: `等待审批：${toolName}`,
          detail: request?.hint ?? (asString(data.reason) === undefined ? undefined : oneLine(asString(data.reason) ?? '')),
        })
        break
      }
      case 'approval/decided': {
        const outcome = asString(data.outcome) ?? 'unknown'
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'approval',
          level: outcome === 'allowed-once' ? 'success' : 'warn',
          title: `审批已决定：${outcomeLabel(outcome)}`,
        })
        break
      }
      case 'approval/policy':
      case 'permission/preset':
      case 'sandbox/mode': {
        const label =
          event.type === 'approval/policy'
            ? `审批策略：${asString(data.policy) ?? '?'}`
            : event.type === 'permission/preset'
              ? `权限预设：${asString(data.preset) ?? '?'}`
              : `沙箱模式：${asString(data.mode) ?? '?'}`
        push({ ...base, id: `${sessionId}:${event.seq}`, kind: 'policy', level: 'info', title: label })
        break
      }
      case 'session/title': {
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'title',
          level: 'info',
          title: '会话标题',
          detail: oneLine(asString(data.title) ?? ''),
        })
        break
      }
      default: {
        push({
          ...base,
          id: `${sessionId}:${event.seq}`,
          kind: 'other',
          level: 'info',
          title: event.type,
        })
        break
      }
    }
  }

  const currentTools: ToolActivity[] = []
  const recentTools: ToolActivity[] = []
  for (const callId of callOrder) {
    const record = calls.get(callId)
    if (record === undefined) continue
    const end = record.result?.time ?? now
    const activity: ToolActivity = {
      callId: record.callId,
      name: record.name,
      argumentsSummary: summariseArguments(record.arguments),
      startedAt: record.time,
      turn: record.turn,
      step: record.step,
      durationMs: Math.max(0, end - record.time),
      status: record.result === undefined ? 'running' : record.result.isError ? 'failed' : 'succeeded',
    }
    if (record.result === undefined) currentTools.push(activity)
    else recentTools.push(activity)
  }
  recentTools.reverse()

  const pendingApprovals = [...state.pendingApprovals.values()].sort((a, b) => a.askedAt - b.askedAt)
  const { state: sessionState, reason } = deriveState(state, pendingApprovals.length > 0, now)
  const live = now - state.lastEventAt <= LIVE_WINDOW_MS

  const view: SessionView = {
    sessionId,
    title: state.title,
    cwd: state.header.cwd ?? '',
    createdAt: state.header.createdAt,
    lastEventAt: state.lastEventAt,
    lastEventAgeMs: Math.max(0, now - state.lastEventAt),
    state: sessionState,
    stateReason: reason,
    turn: state.openTurn,
    step: state.step,
    runDurationMs: state.openTurnStartedAt === undefined ? undefined : Math.max(0, now - state.openTurnStartedAt),
    eventCount: state.totalEvents,
    approvalPolicy: state.approvalPolicy,
    permissionPreset: state.permissionPreset,
    sandboxMode: state.sandboxMode,
    currentTools,
    recentTools: recentTools.slice(0, 12),
    pendingApprovals,
    live,
    formatVersion: state.header.version,
  }

  return { view, timeline }
}

/** Map a turn-end reason kind to a Chinese label. */
export function turnEndLabel(kind: string): string {
  switch (kind) {
    case 'completed':
      return '已完成'
    case 'aborted':
      return '已取消'
    case 'blocked':
      return '被阻塞'
    case 'error':
      return '出错'
    case 'max-tokens':
      return '达到输出上限'
    case 'interrupted':
      return '被中断（崩溃后收尾）'
    case 'forked':
      return '分叉收尾'
    default:
      return kind
  }
}

/** Map an approval outcome to a Chinese label. */
export function outcomeLabel(outcome: string): string {
  switch (outcome) {
    case 'allowed-once':
      return '已批准（仅此一次）'
    case 'rejected':
      return '已拒绝'
    case 'cancelled':
      return '已取消'
    case 'unavailable':
      return '无人应答（按拒绝处理）'
    default:
      return outcome
  }
}

/** Map a user-message source kind to a Chinese label. */
function sourceLabel(kind: string): string {
  switch (kind) {
    case 'user':
      return '本机用户'
    case 'user-approval':
      return '策略变更通知'
    case 'agent':
      return '智能体注入'
    case 'todo-board':
      return '待办板'
    default:
      return kind
  }
}

/** Derive the session state from confirmed log facts only. */
function deriveState(
  state: SessionFoldState,
  hasPendingApproval: boolean,
  now: number,
): { state: SessionState; reason: string } {
  if (state.openTurn !== undefined) {
    if (hasPendingApproval) return { state: 'waiting-approval', reason: '当前轮次里有未决定的审批请求' }
    return { state: 'running', reason: `第 ${state.openTurn} 轮进行中，日志仍在追加` }
  }
  if (state.totalEvents === 0) return { state: 'idle', reason: '日志里还没有事件' }
  switch (state.lastTurnEndReason) {
    case 'error':
      return { state: 'failed', reason: '最近一轮以错误结束' }
    case 'aborted':
      return { state: 'aborted', reason: '最近一轮被取消' }
    case 'blocked':
      return { state: 'blocked', reason: '最近一轮被阻塞' }
    case 'interrupted':
      return { state: 'interrupted', reason: '最近一轮因进程中断被收尾' }
    case 'interval':
      return { state: 'idle', reason: '最近一轮已结束' }
    default:
      return {
        state: state.lastTurnEndReason === undefined ? 'unknown' : 'idle',
        reason:
          state.lastTurnEndReason === undefined
            ? '日志里没有轮次边界事件'
            : `最近一轮：${turnEndLabel(state.lastTurnEndReason)}（${Math.round((now - state.lastEventAt) / 1000)} 秒前有活动）`,
      }
  }
}
