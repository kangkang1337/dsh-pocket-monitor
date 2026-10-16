/**
 * Display helpers shared by the phone components.
 *
 * @module dsh-pocket-monitor/frontend/utils/format
 */

import type { ConnectionStatus, SessionState } from '../../../shared/types/index.ts'

/** Format a duration in milliseconds as a compact human string. */
export function formatDuration(ms: number | undefined): string {
  if (ms === undefined || !Number.isFinite(ms) || ms < 0) return '—'
  const seconds = Math.floor(ms / 1_000)
  if (seconds < 60) return `${seconds} 秒`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes} 分 ${seconds % 60} 秒`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 小时 ${minutes % 60} 分`
  const days = Math.floor(hours / 24)
  return `${days} 天 ${hours % 24} 小时`
}

/** Format a "time ago" string for event ages. */
export function formatAgo(timestamp: number, now = Date.now()): string {
  const delta = Math.max(0, now - timestamp)
  if (delta < 5_000) return '刚刚'
  if (delta < 60_000) return `${Math.floor(delta / 1_000)} 秒前`
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)} 分钟前`
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)} 小时前`
  return `${Math.floor(delta / 86_400_000)} 天前`
}

/** Format a clock time (HH:MM:SS) in the phone's locale. */
export function formatClock(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString('zh-CN', { hour12: false })
}

/** Format a full local timestamp. */
export function formatDateTime(timestamp: number | undefined): string {
  if (timestamp === undefined) return '—'
  return new Date(timestamp).toLocaleString('zh-CN', { hour12: false })
}

/** Label for the DSH data-source status. */
export function sourceStatusLabel(status: ConnectionStatus): string {
  switch (status) {
    case 'connected':
      return '正在接收新事件'
    case 'watching':
      return '已连接（暂无新事件）'
    case 'idle':
      return '空闲'
    case 'disconnected':
      return '已断开'
    case 'source-missing':
      return '等待 DSH 会话日志'
    case 'unreadable':
      return '会话日志不可读'
    default:
      return status
  }
}

/** One-line connection diagnosis for the settings panel. */
export function diagnoseHint(status: ConnectionStatus, workspace: string): string {
  switch (status) {
    case 'source-missing':
      return `还没找到 ${workspace} 的 DSH 会话日志：请确认 DSH 正在这个目录里运行（或在服务启动参数里指定 --workspace 与 --dsh-home）。`
    case 'unreadable':
      return '会话日志文件当前读不了：可能是权限问题，或者文件正在被其他程序独占。本服务只读，不会修改它。'
    case 'connected':
    case 'watching':
      return '读取正常。事件只在 DSH 落盘后出现，通常延迟在毫秒到秒级。'
    default:
      return '等待下一次扫描。'
  }
}

/** Label for the session state. */
export function sessionStateLabel(state: SessionState | string): string {
  switch (state) {
    case 'running':
      return '运行中'
    case 'waiting-approval':
      return '等待审批'
    case 'idle':
      return '空闲'
    case 'failed':
      return '执行失败'
    case 'aborted':
      return '已取消'
    case 'blocked':
      return '被阻塞'
    case 'interrupted':
      return '被中断'
    default:
      return '状态未知'
  }
}

/** Tone token used for styling a session state. */
export function sessionStateTone(state: SessionState): 'ok' | 'warn' | 'bad' | 'idle' {
  switch (state) {
    case 'running':
      return 'ok'
    case 'waiting-approval':
      return 'warn'
    case 'failed':
      return 'bad'
    case 'blocked':
    case 'aborted':
    case 'interrupted':
      return 'warn'
    default:
      return 'idle'
  }
}

/** Tone token for the link/source banner. */
export function statusTone(status: ConnectionStatus): 'ok' | 'warn' | 'bad' | 'idle' {
  switch (status) {
    case 'connected':
    case 'watching':
      return 'ok'
    case 'idle':
      return 'idle'
    case 'source-missing':
      return 'warn'
    default:
      return 'bad'
  }
}

/** Icon glyph per timeline kind (text, not colour, carries the meaning). */
export function eventIcon(kind: string, level: string): string {
  if (level === 'error') return '✕'
  switch (kind) {
    case 'turn':
      return '◆'
    case 'step':
      return '·'
    case 'tool':
      return '⚙'
    case 'assistant':
      return '✎'
    case 'user':
      return '›'
    case 'command':
      return '/'
    case 'approval':
      return '⚠'
    case 'policy':
      return '⛨'
    case 'title':
      return '★'
    default:
      return '•'
  }
}

/** Short label for an approval outcome. */
export function outcomeText(outcome: string): string {
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

/** Chinese badge label for what a pending approval is asking for. */
export function requiredActionLabel(action: string): string {
  switch (action) {
    case 'sandbox-escalation':
      return '沙箱提权'
    case 'permission':
      return '权限申请'
    case 'network-access':
      return '联网访问'
    case 'file-access':
      return '文件访问'
    case 'read-only-retry':
      return '需重试确认'
    case 'tool-permission':
      return '工具授权'
    case 'approval-policy':
      return '审批策略'
    default:
      return action
  }
}

/** Truncate a title for the session switcher. */
export function shortTitle(title: string | undefined, fallback: string): string {
  if (title === undefined || title.trim() === '') return fallback
  const flat = title.replace(/\s+/g, ' ').trim()
  return flat.length > 28 ? `${flat.slice(0, 27)}…` : flat
}
