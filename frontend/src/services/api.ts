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
  ApiError,
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

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiFailure'
    this.status = status
    this.code = code
  }
}

/** Send a JSON request and normalise errors. */
async function call<T>(path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    credentials: 'same-origin',
    headers: init.body === undefined ? undefined : { 'content-type': 'application/json' },
    ...init,
  })
  const text = await response.text()
  let parsed: unknown
  try {
    parsed = text === '' ? {} : JSON.parse(text)
  } catch {
    parsed = { raw: text }
  }
  if (!response.ok) {
    const error = (parsed as Partial<ApiError>).error
    throw new ApiFailure(response.status, error?.code ?? 'unknown', error?.message ?? `HTTP ${response.status}`)
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
