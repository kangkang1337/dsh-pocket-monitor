/**
 * Reactive store for the phone UI.
 *
 * One store instance owns: the pairing state, the device identity, the latest
 * status payload, the merged timeline per session, and the phone-to-server link
 * state. Every value shown in the UI comes from the backend; nothing is
 * simulated and no demo data is generated.
 *
 * @module dsh-pocket-monitor/frontend/stores/monitor
 */

import { computed, readonly, reactive, type ComputedRef } from 'vue'
import { api, ApiFailure, rememberPin, type ApprovalListing, type PairingProbe } from '../services/api'
import { linkLabel, openStream, type LinkState } from '../services/stream'
import type { MonitorEvent, PendingApproval, PublicAccessStatus, SessionView, StatusPayload } from '../../../shared/types/index.ts'

/** Persisted pairing attempt, so a refresh does not lose an approved pairing. */
const PAIRING_STORAGE_KEY = 'dpm.pairing.v1'

/** Bounded timeline kept in memory per session. */
const TIMELINE_LIMIT = 300

/** Pairing attempt as the phone remembers it. */
interface StoredPairing {
  readonly pairingId: string
  readonly pairSecret: string
  readonly deviceName: string
}

/** UI phases. */
export type Phase = 'loading' | 'pairing' | 'ready' | 'error'

/** Store state. */
interface State {
  phase: Phase
  /** Set when the phone is not paired yet and needs a code. */
  needsPairing: boolean
  pairing: PairingProbe | undefined
  pairingStatus: 'idle' | 'claiming' | 'waiting-approval' | 'approved' | 'rejected' | 'failed'
  pairingMessage: string
  deviceName: string
  device: { id: string; name: string; scopes: readonly string[]; createdAt: number; lastSeenAt: number } | undefined
  status: StatusPayload | undefined
  timelines: Record<string, MonitorEvent[]>
  selectedSessionId: string | undefined
  approvals: ApprovalListing | undefined
  publicAccess: PublicAccessStatus | undefined
  link: LinkState
  lastFrameAt: number
  error: string
  /** Transient banner message; the UI clears it after showing. */
  notice: string
  busy: boolean
  /**
   * Set when the server demands the public-access PIN: the phone moved onto the
   * public URL and needs the second factor before anything else works.
   */
  pinRequired: boolean
  /** Message shown alongside the PIN prompt. */
  pinMessage: string
}

const state = reactive<State>({
  phase: 'loading',
  needsPairing: true,
  pairing: undefined,
  pairingStatus: 'idle',
  pairingMessage: '',
  deviceName: guessDeviceName(),
  device: undefined,
  status: undefined,
  timelines: {},
  selectedSessionId: undefined,
  approvals: undefined,
  publicAccess: undefined,
  link: 'connecting',
  lastFrameAt: 0,
  error: '',
  notice: '',
  busy: false,
  pinRequired: false,
  pinMessage: '',
})

let disposeStream: (() => void) | undefined
let pollTimer: number | undefined

/** Read a stored pairing attempt, if any. */
function loadStoredPairing(): StoredPairing | undefined {
  try {
    const raw = window.localStorage.getItem(PAIRING_STORAGE_KEY)
    if (raw === null) return undefined
    const parsed = JSON.parse(raw) as Partial<StoredPairing>
    if (typeof parsed.pairingId !== 'string' || typeof parsed.pairSecret !== 'string') return undefined
    return { pairingId: parsed.pairingId, pairSecret: parsed.pairSecret, deviceName: parsed.deviceName ?? guessDeviceName() }
  } catch {
    return undefined
  }
}

/** Persist one pairing attempt. */
function storePairing(pairing: StoredPairing | undefined): void {
  try {
    if (pairing === undefined) window.localStorage.removeItem(PAIRING_STORAGE_KEY)
    else window.localStorage.setItem(PAIRING_STORAGE_KEY, JSON.stringify(pairing))
  } catch {
    /* private mode: pairing just won't survive a refresh */
  }
}

/** Best-effort device label for the desktop confirmation prompt. */
function guessDeviceName(): string {
  const ua = navigator.userAgent
  if (/iPhone/.test(ua)) return 'iPhone'
  if (/iPad/.test(ua)) return 'iPad'
  if (/Android/.test(ua)) return 'Android 设备'
  return '手机浏览器'
}

/** Generate a phone-side pairing secret (never sent anywhere but this server). */
function freshPairSecret(): string {
  const bytes = new Uint8Array(24)
  crypto.getRandomValues(bytes)
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('')
}

/** Merge incoming timeline entries into the per-session cache (dedup by id). */
function mergeEvents(sessionId: string, incoming: readonly MonitorEvent[]): void {
  const existing = state.timelines[sessionId] ?? []
  const seen = new Set(existing.map((event) => event.id))
  const merged = [...existing]
  for (const event of incoming) {
    if (seen.has(event.id)) continue
    merged.push(event)
    seen.add(event.id)
  }
  merged.sort((left, right) => left.seq - right.seq)
  state.timelines[sessionId] = merged.slice(-TIMELINE_LIMIT)
}

/** Store actions and derived values. */
export interface MonitorStore {
  readonly state: Readonly<State>
  readonly currentSession: ComputedRef<SessionView | undefined>
  readonly timeline: ComputedRef<readonly MonitorEvent[]>
  readonly pendingApprovals: ComputedRef<readonly PendingApproval[]>
  readonly linkText: ComputedRef<string>
  readonly connected: ComputedRef<boolean>
  initialise: () => Promise<void>
  refreshPairingProbe: () => Promise<void>
  afterPaired: () => Promise<void>
  refreshStatus: (seedTimelines: boolean) => Promise<void>
  loadTimeline: (sessionId: string) => Promise<void>
  refreshApprovals: () => Promise<void>
  refreshPublicAccess: () => Promise<void>
  selectSession: (sessionId: string) => void
  claimPairing: (code: string) => Promise<void>
  resumePairing: (stored: StoredPairing) => Promise<void>
  pollPairing: (stored: StoredPairing) => Promise<void>
  decide: (approvalId: string, action: 'approve' | 'reject') => Promise<void>
  clearNotice: () => void
  unbind: () => Promise<void>
  handleLostSession: () => Promise<void>
  /** Submit the public-access PIN, then retry whatever needed it. */
  submitPin: (pin: string) => Promise<void>
  /** Forget the stored PIN (e.g. before re-entering a rotated one). */
  forgetPin: () => void
  dispose: () => void
}

const currentSession = computed<SessionView | undefined>(() => {
  const payload = state.status
  if (payload === undefined) return undefined
  if (state.selectedSessionId !== undefined) {
    return payload.sessions.find((session) => session.sessionId === state.selectedSessionId) ?? payload.sessions[0]
  }
  return payload.sessions[0]
})

const timeline = computed<readonly MonitorEvent[]>(() => {
  const session = currentSession.value
  if (session === undefined) return []
  // Newest first for display; the store keeps them in log order.
  return [...(state.timelines[session.sessionId] ?? [])].reverse()
})

const pendingApprovals = computed<readonly PendingApproval[]>(() => state.status?.pendingApprovals ?? [])

/** Store actions and computed values consumed by the templates. */
export const monitor: MonitorStore = {
  state: readonly(state) as Readonly<State>,
  currentSession,
  timeline,
  pendingApprovals,
  linkText: computed(() => linkLabel(state.link)),
  connected: computed(() => state.link === 'open'),

  /** Load everything for a phone that may or may not be paired. */
  async initialise(): Promise<void> {
    state.phase = 'loading'
    state.error = ''
    try {
      const health = await api.health()
      if (health.ok !== true) throw new Error('本地服务没有就绪')
    } catch (error) {
      // A PIN refusal is not a service failure — it means this phone reached the
      // server from another network and needs the second factor.
      if (error instanceof ApiFailure && error.pinRequired) {
        state.phase = 'ready'
        state.pinRequired = true
        state.pinMessage = error.message
        return
      }
      state.phase = 'error'
      state.error = describe(error)
      return
    }
    try {
      state.device = await api.device()
      state.needsPairing = false
      await monitor.afterPaired()
      return
    } catch (error) {
      if (error instanceof ApiFailure && error.pinRequired) {
        state.phase = 'ready'
        state.pinRequired = true
        state.pinMessage = error.message
        return
      }
      if (!(error instanceof ApiFailure) || error.status !== 401) {
        state.phase = 'error'
        state.error = describe(error)
        return
      }
    }
    state.needsPairing = true
    await monitor.refreshPairingProbe()
    const stored = loadStoredPairing()
    if (stored !== undefined) {
      state.phase = 'pairing'
      state.pairingStatus = 'waiting-approval'
      state.pairingMessage = '已找回上次未完成的配对，正在等待电脑端确认…'
      void monitor.resumePairing(stored)
      return
    }
    state.phase = 'pairing'
  },

  /** Refresh the public pairing probe (expiry, whether the code is still live). */
  async refreshPairingProbe(): Promise<void> {
    try {
      state.pairing = await api.pairingProbe()
    } catch {
      state.pairing = undefined
    }
  },

  /** Everything that must run once a device session exists. */
  async afterPaired(): Promise<void> {
    state.phase = 'ready'
    state.needsPairing = false
    await Promise.all([monitor.refreshStatus(true), monitor.refreshPublicAccess()])
    disposeStream?.()
    disposeStream = openStream({
      onState: (link) => {
        state.link = link
      },
      onFrame: (frame) => {
        state.lastFrameAt = Date.now()
        if (frame.type === 'status') {
          applyStatus(frame.payload)
        } else if (frame.type === 'events') {
          mergeEvents(frame.payload.sessionId, frame.payload.events)
        } else if (frame.type === 'approval') {
          if (state.status !== undefined) {
            state.status = {
              ...state.status,
              pendingApprovals: frame.payload.pending,
              recentlyDecided: frame.payload.decided,
            }
          }
          void monitor.refreshApprovals()
        }
      },
    })
    // A slow fallback poll covers environments where SSE is buffered by a proxy.
    if (pollTimer !== undefined) window.clearInterval(pollTimer)
    pollTimer = window.setInterval(() => {
      if (state.link === 'open' && Date.now() - state.lastFrameAt < 20_000) return
      void monitor.refreshStatus(false)
    }, 5_000)
  },

  /** Fetch the dashboard payload and seed timelines on first load. */
  async refreshStatus(seedTimelines: boolean): Promise<void> {
    try {
      const payload = await api.status()
      applyStatus(payload)
      state.error = ''
      if (seedTimelines) {
        const session = payload.sessions[0]
        if (session !== undefined) await monitor.loadTimeline(session.sessionId)
      }
    } catch (error) {
      if (error instanceof ApiFailure && error.pinRequired) {
        state.pinRequired = true
        state.pinMessage = error.message
        return
      }
      if (error instanceof ApiFailure && error.status === 401) {
        await monitor.handleLostSession()
        return
      }
      state.error = describe(error)
      if (state.phase === 'loading') state.phase = 'error'
    }
  },

  /**
   * Submit the public-access PIN and re-run whatever needed it.
   *
   * The PIN is remembered on this phone for the next time it roams; the server
   * still re-checks it on every public request.
   */
  async submitPin(pin: string): Promise<void> {
    state.busy = true
    rememberPin(pin.trim())
    try {
      await api.health()
      state.pinRequired = false
      state.pinMessage = ''
      state.phase = 'loading'
      await monitor.initialise()
    } catch (error) {
      if (error instanceof ApiFailure && error.pinRequired) {
        rememberPin(undefined)
        state.pinRequired = true
        state.pinMessage = error.message
      } else {
        rememberPin(undefined)
        state.pinRequired = false
        state.error = describe(error)
      }
    } finally {
      state.busy = false
    }
  },

  /** Forget the remembered PIN. */
  forgetPin(): void {
    rememberPin(undefined)
  },

  /** Load a session's timeline from the HTTP API (used on tap and first load). */
  async loadTimeline(sessionId: string): Promise<void> {
    try {
      const response = await api.events(sessionId, TIMELINE_LIMIT)
      mergeEvents(sessionId, response.events)
    } catch {
      /* the stream will fill this in */
    }
  },

  /** Refresh the approvals list and the capability report. */
  async refreshApprovals(): Promise<void> {
    try {
      state.approvals = await api.approvals()
    } catch {
      /* keep the last known list */
    }
  },

  /** Refresh the reserved mode-B status (always disabled in this build). */
  async refreshPublicAccess(): Promise<void> {
    try {
      state.publicAccess = await api.publicAccess()
    } catch {
      state.publicAccess = undefined
    }
  },

  /** Select a session to display. */
  selectSession(sessionId: string): void {
    state.selectedSessionId = sessionId
    if (state.timelines[sessionId] === undefined) void monitor.loadTimeline(sessionId)
  },

  /** Submit a pairing code; the phone then waits for desktop confirmation. */
  async claimPairing(code: string): Promise<void> {
    state.busy = true
    state.pairingStatus = 'claiming'
    state.pairingMessage = ''
    try {
      const stored = loadStoredPairing()
      const pairSecret = stored?.pairSecret ?? freshPairSecret()
      const response = await api.claimPairing({ code: code.trim(), pairSecret, deviceName: state.deviceName })
      const record: StoredPairing = { pairingId: response.pairingId, pairSecret, deviceName: state.deviceName }
      storePairing(record)
      state.pairingStatus = 'waiting-approval'
      state.pairingMessage = '配对请求已提交。请在电脑端确认（终端里按 a，或运行 npm run approve）。'
      void monitor.pollPairing(record)
    } catch (error) {
      state.pairingStatus = 'failed'
      state.pairingMessage = describe(error)
      await monitor.refreshPairingProbe()
    } finally {
      state.busy = false
    }
  },

  /** Resume polling an already-claimed pairing (after a refresh). */
  async resumePairing(stored: StoredPairing): Promise<void> {
    await monitor.pollPairing(stored)
  },

  /** Poll until the desktop decides, then finish pairing. */
  async pollPairing(stored: StoredPairing): Promise<void> {
    for (let attempt = 0; attempt < 150; attempt += 1) {
      try {
        const result = await api.pollPairing({ pairingId: stored.pairingId, pairSecret: stored.pairSecret })
        if (result.state === 'approved') {
          storePairing(undefined)
          state.pairingStatus = 'approved'
          state.pairingMessage = '配对成功，正在加载监控数据…'
          state.device = await api.device()
          await monitor.afterPaired()
          return
        }
      } catch (error) {
        if (error instanceof ApiFailure && ['unknown-pairing', 'expired', 'rejected', 'denied'].includes(error.code)) {
          storePairing(undefined)
          state.pairingStatus = 'failed'
          state.pairingMessage = error.message
          await monitor.refreshPairingProbe()
          return
        }
        // Network hiccups: keep waiting.
      }
      await delay(2_000)
    }
    storePairing(undefined)
    state.pairingStatus = 'failed'
    state.pairingMessage = '等待电脑端确认超时，请重新扫码配对。'
  },

  /** Submit an approval decision and surface the backend's honest answer. */
  async decide(approvalId: string, action: 'approve' | 'reject'): Promise<void> {
    state.busy = true
    try {
      const result = await api.decide(approvalId, action, crypto.randomUUID())
      state.notice = result.nextStep ?? '已提交。'
    } catch (error) {
      if (error instanceof ApiFailure && error.code === 'approval_channel_unavailable') {
        state.notice = error.message
      } else if (error instanceof ApiFailure && error.status === 409) {
        state.notice = error.message
      } else {
        state.notice = describe(error)
      }
      await monitor.refreshStatus(true)
    } finally {
      state.busy = false
    }
  },

  /** Clear the transient notice banner. */
  clearNotice(): void {
    state.notice = ''
  },

  /** Unbind this phone and return to the pairing screen. */
  async unbind(): Promise<void> {
    state.busy = true
    try {
      await api.unbind()
      state.notice = '已解除绑定。'
    } catch (error) {
      state.notice = describe(error)
    } finally {
      await monitor.handleLostSession()
      state.busy = false
    }
  },

  /** The device session is gone (unbound, revoked, or expired). */
  async handleLostSession(): Promise<void> {
    disposeStream?.()
    disposeStream = undefined
    if (pollTimer !== undefined) window.clearInterval(pollTimer)
    pollTimer = undefined
    state.device = undefined
    state.status = undefined
    state.timelines = {}
    state.approvals = undefined
    state.needsPairing = true
    state.link = 'closed'
    state.phase = 'pairing'
    state.pairingStatus = 'idle'
    state.pairingMessage = '这台设备已经解绑或会话失效，请重新扫码配对。'
    await monitor.refreshPairingProbe()
  },

  /** Stop timers and streams (called on unmount). */
  dispose(): void {
    disposeStream?.()
    disposeStream = undefined
    if (pollTimer !== undefined) window.clearInterval(pollTimer)
    pollTimer = undefined
  },
}

/** Apply a status payload, keeping the selected session in sync. */
function applyStatus(payload: StatusPayload): void {
  state.status = payload
  const ids = new Set(payload.sessions.map((session) => session.sessionId))
  if (state.selectedSessionId !== undefined && !ids.has(state.selectedSessionId)) state.selectedSessionId = undefined
  if (state.selectedSessionId === undefined && payload.sessions.length > 0) {
    state.selectedSessionId = payload.sessions[0]?.sessionId
  }
  state.link = state.link === 'closed' ? 'closed' : state.link
}

/** Turn an unknown error into a phone-friendly message. */
function describe(error: unknown): string {
  if (error instanceof ApiFailure) return error.message
  if (error instanceof Error) {
    if (error.message.includes('Failed to fetch')) return '无法连接本地服务：请确认服务仍在运行、手机还在同一 Wi-Fi。'
    return error.message
  }
  return String(error)
}

/** Promise-based delay. */
function delay(ms: number): Promise<void> {
  return new Promise((resolvePromise) => window.setTimeout(resolvePromise, ms))
}
