/**
 * One-shot LAN pairing: short-lived code, one-time claim, desktop confirmation.
 *
 * Flow (all steps are rate-limited and audited):
 *  1. the desktop prints a QR containing only the LAN URL, the pairing id and
 *     the current 6-digit code — never a DSH credential and never a long token;
 *  2. the phone posts the code to `/api/pair/claim` with a secret it generated
 *     itself, and waits;
 *  3. the desktop confirms that pending claim (loopback-only admin API, or the
 *     terminal prompt on the machine), because a LAN address alone must not be
 *     enough to bind a device;
 *  4. the phone's poll then receives the device token exactly once.
 *
 * Codes expire, are single-use, and are destroyed when a device is bound.
 *
 * @module dsh-pocket-monitor/auth/pairing
 */

import { createHash, randomBytes, randomInt, randomUUID, timingSafeEqual } from 'node:crypto'

/** Seconds a confirmed pairing stays collectable after its code expires. */
const CLAIM_GRACE_MS = 120_000

/** Pairing code lifetime marker. */
export interface PairingCodeView {
  readonly id: string
  readonly code: string
  /** Desktop confirmation secret. The dashboard and the loopback admin API hold it. */
  readonly nonce: string
  readonly issuedAt: number
  readonly expiresAt: number
  readonly claim?: PairingClaimView
}

/** A phone's pending claim on the current code. */
export interface PairingClaimView {
  readonly secretHash: string
  readonly deviceName: string
  readonly claimedAt: number
  readonly claimedFrom: string
  readonly status: 'pending' | 'approved' | 'rejected'
  readonly rejectedReason?: string
}

/** Internal pairing state for one code. */
interface PairingCode {
  readonly id: string
  readonly code: string
  readonly issuedAt: number
  readonly expiresAt: number
  /** Secret the desktop must hold to confirm this code. */
  readonly nonce: string
  claim?: ClaimRecord
  /** Token issued to the phone at most once, once approved. */
  issuedToken?: string
  issuedDeviceId?: string
}

/** Internal claim record. */
interface ClaimRecord {
  readonly secretHash: string
  readonly deviceName: string
  readonly claimedAt: number
  readonly claimedFrom: string
  status: 'pending' | 'approved' | 'rejected'
  readonly rejectedReason?: string
}

/** Outcome of a claim attempt. */
export type ClaimResult =
  | { readonly ok: true; readonly pairingId: string }
  | { readonly ok: false; readonly reason: 'no-active-code' | 'expired' | 'already-claimed' | 'already-bound' | 'rate-limited' }

/** Outcome of a poll attempt. */
export type PollResult =
  | { readonly ok: true; readonly state: 'pending' }
  | { readonly ok: true; readonly state: 'approved'; readonly token: string; readonly deviceId: string; readonly deviceName: string }
  | { readonly ok: false; readonly reason: 'unknown-pairing' | 'expired' | 'rejected' | 'denied'; readonly message?: string }

/** Options for the pairing service. */
export interface PairingServiceOptions {
  /** Code lifetime in seconds. */
  readonly ttlSeconds: number
  /** Failed claims allowed per IP inside the window. */
  readonly maxAttemptsPerIp: number
  /** Window for the attempt counter, in seconds. */
  readonly attemptWindowSeconds: number
}

/** Hash helper kept local so the auth module has one hashing path. */
function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

/** Constant-time comparison of two equal-length hex digests. */
function safeEqualHex(left: string, right: string): boolean {
  const a = Buffer.from(left, 'hex')
  const b = Buffer.from(right, 'hex')
  if (a.length !== b.length || a.length === 0) return false
  return timingSafeEqual(a, b)
}

/**
 * The pairing authority: mints codes, records claims, and issues device tokens
 * exactly once per approved claim.
 */
export class PairingService {
  private readonly options: PairingServiceOptions
  private current: PairingCode | undefined
  private readonly attempts = new Map<string, number[]>()
  private lastIssueAt = 0
  /** Prevent hammering the dashboard with new codes. */
  private readonly issueCooldownMs = 2_000

  constructor(options: PairingServiceOptions) {
    this.options = options
  }

  /** Whether an unexpired code exists right now. */
  hasActiveCode(now = Date.now()): boolean {
    return this.currentView(now) !== undefined
  }

  /**
   * Mint a fresh one-time code, replacing any previous one.
   *
   * @param now - current time.
   * @param force - rotate even if a usable code already exists.
   * @returns the code view shown on the desktop (includes the confirm nonce).
   */
  issue(now = Date.now(), force = false): PairingCodeView & { nonce: string } {
    if (!force && this.current !== undefined && this.current.expiresAt > now && now - this.lastIssueAt < this.issueCooldownMs) {
      return { ...this.view(this.current), nonce: this.current.nonce }
    }
    const code = randomInt(0, 1_000_000).toString().padStart(6, '0')
    const pairing: PairingCode = {
      id: randomUUID(),
      code,
      issuedAt: now,
      expiresAt: now + this.options.ttlSeconds * 1_000,
      nonce: randomBytes(18).toString('base64url'),
    }
    this.current = pairing
    this.lastIssueAt = now
    return { ...this.view(pairing), nonce: pairing.nonce }
  }

  /** The current code view, or undefined when there is none or it expired. */
  currentView(now = Date.now()): PairingCodeView | undefined {
    if (this.current === undefined) return undefined
    if (this.current.expiresAt <= now) return undefined
    return this.view(this.current)
  }

  /** Render the internal state into its public view. */
  private view(pairing: PairingCode): PairingCodeView {
    return {
      id: pairing.id,
      code: pairing.code,
      nonce: pairing.nonce,
      issuedAt: pairing.issuedAt,
      expiresAt: pairing.expiresAt,
      ...(pairing.claim === undefined ? {} : { claim: { ...pairing.claim } }),
    }
  }

  /**
   * Record a phone's claim against the current code.
   *
   * @param input - pairing code, phone-generated secret, device name, source IP.
   * @param now - current time.
   * @returns whether the claim was accepted; the phone must then poll.
   */
  claim(
    input: { code: string; pairSecret: string; deviceName: string; from: string },
    now = Date.now(),
  ): ClaimResult {
    if (this.isRateLimited(input.from, now)) return { ok: false, reason: 'rate-limited' }
    this.recordAttempt(input.from, now)

    const pairing = this.current
    if (pairing === undefined) return { ok: false, reason: 'no-active-code' }
    if (pairing.expiresAt <= now) return { ok: false, reason: 'expired' }
    if (pairing.code !== input.code.trim()) return { ok: false, reason: 'no-active-code' }
    if (pairing.issuedToken !== undefined) return { ok: false, reason: 'already-bound' }
    if (pairing.claim !== undefined && pairing.claim.status === 'approved') return { ok: false, reason: 'already-claimed' }
    if (pairing.claim !== undefined && pairing.claim.status === 'pending') {
      // A claim already waiting: only the same secret may refresh it.
      if (!safeEqualHex(pairing.claim.secretHash, sha256Hex(input.pairSecret))) {
        // Anonymous takeover attempt from the LAN: never let it replace the real claim.
        this.recordAttempt(input.from, now)
        return { ok: false, reason: 'already-claimed' }
      }
      pairing.claim = { ...pairing.claim, deviceName: input.deviceName, claimedAt: now, claimedFrom: input.from }
      return { ok: true, pairingId: pairing.id }
    }
    pairing.claim = {
      secretHash: sha256Hex(input.pairSecret),
      deviceName: input.deviceName,
      claimedAt: now,
      claimedFrom: input.from,
      status: 'pending',
    }
    return { ok: true, pairingId: pairing.id }
  }

  /**
   * Approve the pending claim on one pairing id *without* the desktop nonce.
   *
   * This exists for the two cases where no LAN attacker can be in the way: the
   * claim arrived over loopback (the operator's own machine), or the desktop
   * dashboard itself is answering. Any other path must go through
   * {@link decide} with the nonce.
   *
   * @param pairingId - the pairing being approved.
   * @param source - audit label for why approval was automatic.
   * @returns the token to hand to the phone, or a refusal.
   */
  approveClaim(
    pairingId: string,
    source: string,
  ):
    | { ok: true; token: string; deviceId: string; deviceName: string; claimedFrom: string; source: string }
    | { ok: false; reason: string } {
    const pairing = this.current
    if (pairing === undefined || pairing.id !== pairingId) return { ok: false, reason: '配对码不存在或已轮换' }
    if (pairing.claim === undefined) return { ok: false, reason: '还没有手机提交配对请求' }
    if (pairing.claim.status === 'rejected') return { ok: false, reason: '这次配对已被拒绝' }
    if (pairing.claim.status === 'approved') {
      const token = pairing.issuedToken
      const deviceId = pairing.issuedDeviceId
      if (token === undefined || deviceId === undefined) return { ok: false, reason: '这次配对已经发放过令牌' }
      return {
        ok: true,
        token,
        deviceId,
        deviceName: pairing.claim.deviceName,
        claimedFrom: pairing.claim.claimedFrom,
        source,
      }
    }
    const token = randomBytes(32).toString('base64url')
    const deviceId = randomUUID()
    pairing.claim = { ...pairing.claim, status: 'approved' }
    pairing.issuedToken = token
    pairing.issuedDeviceId = deviceId
    return { ok: true, token, deviceId, deviceName: pairing.claim.deviceName, claimedFrom: pairing.claim.claimedFrom, source }
  }

  /**
   * Approve or reject the pending claim.
   *
   * A positive decision mints the device token here and holds it in memory until
   * the phone's next poll hands it over exactly once — the token never travels in
   * the QR, in a URL, or over any channel the desktop prints.
   *
   * @param input - pairing id, the desktop nonce, and the decision.
   * @param now - current time.
   * @returns the decision result, including the pending device token on approval.
   */
  decide(
    input: { pairingId: string; nonce: string; approve: boolean; reason?: string },
    now = Date.now(),
  ): { ok: true; status: 'approved'; token: string; deviceId: string } | { ok: true; status: 'rejected' } | { ok: false; reason: string } {
    const pairing = this.current
    if (pairing === undefined || pairing.id !== input.pairingId) return { ok: false, reason: 'pairing code 不存在或已轮换' }
    if (pairing.expiresAt <= now) return { ok: false, reason: 'pairing code 已过期' }
    if (pairing.nonce !== input.nonce) return { ok: false, reason: '确认凭证不正确' }
    if (pairing.claim === undefined) return { ok: false, reason: '还没有手机提交配对请求' }
    if (!input.approve) {
      if (pairing.claim.status === 'rejected') return { ok: true, status: 'rejected' }
      pairing.claim = { ...pairing.claim, status: 'rejected', rejectedReason: input.reason ?? 'desktop 拒绝了这次配对' }
      return { ok: true, status: 'rejected' }
    }
    const approved = this.approveClaim(input.pairingId, 'desktop-confirmed')
    if (!approved.ok) return { ok: false, reason: approved.reason }
    return { ok: true, status: 'approved', token: approved.token, deviceId: approved.deviceId }
  }

  /**
   * Poll for the pairing result. The device token is handed over at most once.
   *
   * @param input - pairing id and the phone's secret.
   * @param now - current time.
   * @returns the current state, or the token when approved.
   */
  poll(input: { pairingId: string; pairSecret: string }, now = Date.now()): PollResult {
    const pairing = this.current
    if (pairing === undefined || pairing.id !== input.pairingId) return { ok: false, reason: 'unknown-pairing' }
    if (pairing.claim === undefined || !safeEqualHex(pairing.claim.secretHash, sha256Hex(input.pairSecret))) {
      return { ok: false, reason: 'unknown-pairing' }
    }
    if (pairing.claim.status === 'rejected') return { ok: false, reason: 'rejected', message: pairing.claim.rejectedReason }
    if (pairing.claim.status === 'pending') {
      // An unconfirmed pairing expires with its code; a confirmed one gets a short
      // grace period so a slow phone can still collect its token.
      if (pairing.expiresAt <= now) return { ok: false, reason: 'expired' }
      return { ok: true, state: 'pending' }
    }
    const token = pairing.issuedToken
    const deviceId = pairing.issuedDeviceId
    if (token === undefined || deviceId === undefined) return { ok: false, reason: 'denied', message: '配对已被确认，但令牌已经发放过，请重新配对。' }
    if (pairing.expiresAt + CLAIM_GRACE_MS <= now) return { ok: false, reason: 'expired' }
    // Single hand-over: destroy the pairing so neither code nor claim can be reused.
    pairing.issuedToken = undefined
    pairing.issuedDeviceId = undefined
    this.current = undefined
    return { ok: true, state: 'approved', token, deviceId, deviceName: pairing.claim.deviceName }
  }

  /** Invalidate the current code (used by "重新配对" and shutdown). */
  invalidate(): void {
    this.current = undefined
  }

  /** Drop every pending claim and code; used on shutdown so nothing survives exit. */
  revokeAll(): void {
    this.current = undefined
    this.attempts.clear()
  }

  /** Whether this IP has exhausted its claim attempts. */
  private isRateLimited(from: string, now: number): boolean {
    const window = this.attempts.get(from)
    if (window === undefined) return false
    const cutoff = now - this.options.attemptWindowSeconds * 1_000
    return window.filter((at) => at >= cutoff).length >= this.options.maxAttemptsPerIp
  }

  /** Record one claim attempt for an IP. */
  private recordAttempt(from: string, now: number): void {
    const cutoff = now - this.options.attemptWindowSeconds * 1_000
    const window = (this.attempts.get(from) ?? []).filter((at) => at >= cutoff)
    window.push(now)
    this.attempts.set(from, window)
  }
}

/** Export the hash helper for the wiring layer (device token hashing). */
export { sha256Hex }
