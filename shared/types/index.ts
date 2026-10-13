/**
 * Shared types for the DSH Pocket Monitor.
 *
 * These are the project's own vocabulary: raw DSH session events are mapped
 * into {@link MonitorEvent} / {@link SessionView} by the adapter layer, and the
 * backend hands exactly these shapes to the phone.
 *
 * @module dsh-pocket-monitor/shared/types
 */

/** Connection health of the DSH data source, as the backend can actually confirm it. */
export type ConnectionStatus = 'connected' | 'watching' | 'idle' | 'disconnected' | 'source-missing' | 'unreadable'

/** Human-facing state of a session, derived only from facts the log confirms. */
export type SessionState =
  | 'running'
  | 'waiting-approval'
  | 'idle'
  | 'failed'
  | 'aborted'
  | 'blocked'
  | 'interrupted'
  | 'unknown'

/** One pending tool execution (a call without its result yet). */
export interface ToolActivity {
  readonly callId: string
  readonly name: string
  /** Short, redaction-safe summary of the raw argument JSON. */
  readonly argumentsSummary: string
  /** Epoch milliseconds when the call was recorded. */
  readonly startedAt: number
  /** Step/turn the call belongs to. */
  readonly turn: number
  readonly step: number
  /** How long the call has been open, or its recorded duration once settled. */
  readonly durationMs: number
  readonly status: 'running' | 'succeeded' | 'failed'
}

/** One real pending approval, read from the session audit log. */
export interface PendingApproval {
  readonly id: string
  readonly toolName: string
  readonly callId?: string
  readonly reason?: string
  /** Session the request belongs to. */
  readonly sessionId: string
  /** Epoch milliseconds of the `approval/asked` event. */
  readonly askedAt: number
  /** The effective approval policy at the time of reading, when the log states it. */
  readonly policy?: string
}

/** An approval whose decision has been recorded in the log. */
export interface DecidedApproval {
  readonly id: string
  readonly sessionId: string
  readonly outcome: string
  readonly decidedAt: number
}

/** One entry of the activity timeline. */
export interface MonitorEvent {
  /** Globally unique within the backend process: `${sessionId}:${seq}`. */
  readonly id: string
  readonly sessionId: string
  readonly seq: number
  /** Epoch milliseconds from the DSH event envelope. */
  readonly time: number
  readonly kind:
    | 'turn'
    | 'step'
    | 'tool'
    | 'assistant'
    | 'user'
    | 'command'
    | 'approval'
    | 'policy'
    | 'title'
    | 'other'
  /** Single-line headline for the phone timeline. */
  readonly title: string
  /** Optional one-line detail, already truncated for phone display. */
  readonly detail?: string
  /** Severity used by the UI for icon + text (never colour alone). */
  readonly level: 'info' | 'warn' | 'error' | 'success'
}

/** A session as the monitor understands it. */
export interface SessionView {
  readonly sessionId: string
  readonly title?: string
  readonly cwd: string
  readonly createdAt: number
  readonly lastEventAt: number
  readonly lastEventAgeMs: number
  readonly state: SessionState
  /** Why the state is what it is, in one line. */
  readonly stateReason: string
  readonly turn?: number
  readonly step?: number
  /** Milliseconds since the current turn opened; absent when no turn is open. */
  readonly runDurationMs?: number
  readonly eventCount: number
  readonly approvalPolicy?: string
  readonly permissionPreset?: string
  readonly sandboxMode?: string
  readonly currentTools: readonly ToolActivity[]
  readonly recentTools: readonly ToolActivity[]
  readonly pendingApprovals: readonly PendingApproval[]
  /** Whether the session log is currently being appended to (within the live window). */
  readonly live: boolean
  /** Highest format version this reader understood, e.g. 4. */
  readonly formatVersion?: number
}

/** A Windows process the adapter could verify as DSH-related. */
export interface ProcessInfo {
  readonly pid: number
  readonly name: string
  readonly startedAt?: number
  /** Which DSH surface this process serves, e.g. `dsh web (127.0.0.1:3080)`. */
  readonly role: string
  /** Command line with secrets redacted and truncated. */
  readonly commandLine: string
  /** Whether the port this process listens on is loopback-only. */
  readonly listen?: ReadonlyArray<{ readonly host: string; readonly port: number }>
}

/** Which data source the backend is actually using, and how well it works. */
export interface SourceHealth {
  readonly kind: 'dsh-session-log'
  readonly status: ConnectionStatus
  /** One-line human explanation of the status. */
  readonly message: string
  readonly sessionsRoot: string
  readonly workspace: string
  /** Resolved project directory under the sessions root, when it exists. */
  readonly projectDir?: string
  readonly lastScanAt: number
  readonly lastError?: string
  /** Non-fatal note about the process view (e.g. WMI blocked in a sandbox). */
  readonly processNote?: string
  /** How many `node.exe` processes were visible during the last probe. */
  readonly nodeProcessCount?: number
  /** True when this reader can only observe (no external approval channel). */
  readonly approvalWritable: boolean
}

/** Whole-dashboard payload for `GET /api/status`. */
export interface StatusPayload {
  readonly generatedAt: number
  readonly source: SourceHealth
  readonly currentSessionId?: string
  readonly sessions: readonly SessionView[]
  readonly processes: readonly ProcessInfo[]
  readonly pendingApprovals: readonly PendingApproval[]
  readonly recentlyDecided: readonly DecidedApproval[]
  /** Capability report: what is implemented vs. limited by the DSH build. */
  readonly capabilities: Capabilities
}

/** Honest capability report shown in the phone UI. */
export interface Capabilities {
  readonly monitoring: true
  readonly processView: true
  readonly pairing: true
  readonly approvalViewing: true
  /** False while DSH offers no external approval channel for this build. */
  readonly approvalDeciding: boolean
  readonly approvalDecidingReason: string
  readonly publicAccess: 'disabled'
  readonly publicAccessReason: string
  readonly chat: false
  readonly commandExecution: false
}

/** Public-access (mode B) status: reserved interface, never implemented in v1. */
export interface PublicAccessStatus {
  readonly mode: 'disabled' | 'starting' | 'active' | 'stopping' | 'error'
  readonly configured: false
  readonly active: false
  readonly url: null
  readonly reason: string
}

/** Real-time transport frames pushed to paired phones. */
export type ServerFrame =
  | { readonly type: 'hello'; readonly payload: { readonly deviceId: string; readonly status: ConnectionStatus } }
  | { readonly type: 'status'; readonly payload: StatusPayload }
  | { readonly type: 'events'; readonly payload: { readonly sessionId: string; readonly events: readonly MonitorEvent[] } }
  | { readonly type: 'approval'; readonly payload: { readonly pending: readonly PendingApproval[]; readonly decided: readonly DecidedApproval[] } }
  | { readonly type: 'heartbeat'; readonly payload: { readonly at: number } }

/** Error envelope used by every failing API response. */
export interface ApiError {
  readonly error: {
    readonly code: string
    readonly message: string
  }
}

/** Result of a client `GET /api/health` probe (unauthenticated by design). */
export interface HealthPayload {
  readonly ok: boolean
  readonly version: string
  readonly pairingOpen: boolean
  readonly requiresPairing: boolean
}
