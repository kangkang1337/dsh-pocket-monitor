/**
 * Typed client for the monitor's own API.
 *
 * The phone only ever talks to this project's backend: there is no DSH endpoint
 * here, no chat, and no command surface. Cookies carry the device session, so
 * every call uses `credentials: 'same-origin'`.
 *
 * @module dsh-pocket-monitor/frontend/services/api
 */

import type {
  HealthPayload,
  MonitorEvent,
  PendingApproval,
  PublicAccessStatus,
  StatusPayload,
} from '../../../shared/types/index.ts'

/** Error carrying the backend's machine-readable code. */
export class ApiFailure extends Error {
  readonly code: string
  readonly status: number
  /** True when the server needs the public-access PIN before anything else. */
  readonly pinRequired: boolean

  constructor(status: number, code: string, message: string, pinRequired = false) {
    super(message)
    this.name = 'ApiFailure'
    this.status = status
    this.code = code
    this.pinRequired = pinRequired
  }
}

/** Header carrying the public-access PIN (the roaming second factor). */
const PIN_HEADER = 'x-dsh-pocket-pin'

/** Storage key for the PIN this phone was accepted with. */
const PIN_STORAGE_KEY = 'dpm.pin.v1'

/** The PIN remembered on this phone, if any. */
export function rememberedPin(): string | undefined {
  try {
    return window.localStorage.getItem(PIN_STORAGE_KEY) ?? undefined
  } catch {
    return undefined
  }
}

/** Remember (or forget) the PIN on this phone. */
export function rememberPin(pin: string | undefined): void {
  try {
    if (pin === undefined || pin === '') window.localStorage.removeItem(PIN_STORAGE_KEY)
    else window.localStorage.setItem(PIN_STORAGE_KEY, pin)
  } catch {
    /* private mode: the PIN just will not persist */
  }
}

/** Send a JSON request and normalise errors. */
async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const pin = rememberedPin()
  const headers: Record<string, string> = { ...((init.headers as Record<string, string> | undefined) ?? {}) }
  if (init.body !== undefined) headers['content-type'] = 'application/json'
  // Always send the remembered PIN: on the LAN it is ignored, and when the phone
  // roams onto the public URL it is what lets the request through.
  if (pin !== undefined) headers[PIN_HEADER] = pin
  const response = await fetch(path, { credentials: 'same-origin', ...init, headers })
  const text = await response.text()
  let parsed: unknown
  try {
    parsed = text === '' ? {} : JSON.parse(text)
  } catch {
    parsed = { raw: text }
  }
  if (!response.ok) {
    const envelope = parsed as { error?: { code?: string; message?: string; pinRequired?: boolean } }
    const error = envelope.error
    throw new ApiFailure(
      response.status,
      error?.code ?? 'unknown',
      error?.message ?? `HTTP ${response.status}`,
      error?.pinRequired === true || error?.code === 'pin-required' || error?.code === 'pin-not-configured',
    )
  }
  return parsed as T
}

/** Pairing status reported by the desktop through the QR payload. */
export interface PairingProbe {
  readonly serverName: string
  readonly lanUrls: readonly string[]
  readonly pairingOpen: boolean
  readonly expiresAt: number | null
  readonly hasClaim: boolean
}

/** Approval listing plus the honest capability report. */
export interface ApprovalListing {
  readonly pending: readonly PendingApproval[]
  readonly decided: readonly { id: string; sessionId: string; outcome: string; decidedAt: number }[]
  readonly capability: boolean
  readonly capabilityReason: string
  readonly attempts: readonly {
    at: number
    approvalId: string
    deviceId: string
    action: string
    result: string
    reason: string
  }[]
}

/** The monitor API surface available to a paired phone. */
export const api = {
  /** Liveness probe; needs no session. */
  health: (): Promise<HealthPayload> => call('/api/health'),

  /** Public pairing probe; needs no session and exposes no secret. */
  pairingProbe: (): Promise<PairingProbe> => call('/api/pair/session'),

  /** Submit a pairing code with a phone-generated secret. */
  claimPairing: (input: { code: string; pairSecret: string; deviceName: string }): Promise<{ pairingId: string; state: string }> =>
    call('/api/pair/claim', { method: 'POST', body: JSON.stringify(input) }),

  /** Poll for the pairing decision. */
  pollPairing: (input: {
    pairingId: string
    pairSecret: string
  }): Promise<{ state: 'pending' } | { state: 'approved'; deviceId: string; deviceName: string }> =>
    call('/api/pair/poll', { method: 'POST', body: JSON.stringify(input) }),

  /** Full dashboard payload. */
  status: (): Promise<StatusPayload> => call('/api/status'),

  /** Timeline for one session. */
  events: (sessionId: string, limit = 200): Promise<{ sessionId: string | null; events: readonly MonitorEvent[] }> =>
    call(`/api/events?sessionId=${encodeURIComponent(sessionId)}&limit=${limit}`),

  /** Approvals plus capability report. */
  approvals: (): Promise<ApprovalListing> => call('/api/approvals'),

  /**
   * Submit an approval decision.
   *
   * The backend answers with an explicit capability error while DSH offers no
   * external approval channel; the UI shows that verbatim rather than pretending
   * a decision was delivered.
   */
  decide: (
    approvalId: string,
    action: 'approve' | 'reject',
    clientRequestId: string,
  ): Promise<{ nextStep?: string; deliveredToDsh?: boolean }> =>
    call(`/api/approvals/${encodeURIComponent(approvalId)}/decision`, {
      method: 'POST',
      body: JSON.stringify({ action, clientRequestId }),
    }),

  /** Unbind this phone. */
  unbind: (): Promise<{ revoked: boolean }> => call('/api/device', { method: 'DELETE' }),

  /** Who am I (device identity and scopes). */
  device: (): Promise<{ id: string; name: string; scopes: readonly string[]; createdAt: number; lastSeenAt: number }> =>
    call('/api/device'),

  /** Reserved mode-B status; always disabled in this build. */
  publicAccess: (): Promise<PublicAccessStatus> => call('/api/public-access'),
}
