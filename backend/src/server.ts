/**
 * The monitor's HTTP service: LAN host/origin fence, phone pairing, read-only
 * status API, SSE stream, and the restricted approval surface.
 *
 * Security properties enforced here (and covered by tests):
 *  - `Host` must be loopback, one of this host's own addresses, or an explicitly
 *    trusted authority; a mismatched `Origin` or a cross-site fetch is refused;
 *  - every non-public route needs a paired device cookie, so hiding a button in
 *    the UI never has to be the only defence;
 *  - mutation routes are POST/DELETE only and are rate limited;
 *  - the monitor serves no chat, no command execution, and no DSH proxy route.
 *
 * @module dsh-pocket-monitor/server
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { createServer as createHttpsServer, type Server as HttpsServer } from 'node:https'
import { readFileSync } from 'node:fs'
import { appendFile, mkdir, readFile, stat } from 'node:fs/promises'
import { extname, join, normalize, resolve, sep } from 'node:path'
import { DshSessionSource } from './adapters/dsh/sessions.ts'
import { hashToken, sanitiseDeviceName, type DeviceRecord, type DeviceStore } from './auth/devices.ts'
import { PairingService } from './auth/pairing.ts'
import { listLanAddresses, type LanAddress } from './services/lan.ts'
import { PublicGate, generatePin } from './services/public-access.ts'
import { readVersion } from './version.ts'
import { SseHub } from './transport/sse.ts'
import type { MonitorConfig } from './config.ts'
import type { ApiError, HealthPayload, ServerFrame, StatusPayload } from '../../shared/types/index.ts'

/** Name of the HttpOnly cookie that carries the device token. */
export const DEVICE_COOKIE = 'dpm_device'

/** Header a public client uses to present the access PIN (second factor). */
export const PIN_HEADER = 'x-dsh-pocket-pin'

/** How many decision attempts are kept in memory. */
const DECISION_MEMORY = 200
/** Poll interval safety floor so a typo cannot spin the CPU. */
const MIN_POLL_MS = 200

/** Bounded sliding-window rate limiter. */
class RateLimiter {
  private readonly hits = new Map<string, number[]>()
  private readonly limit: number
  private readonly windowMs: number

  constructor(limit: number, windowMs: number) {
    this.limit = limit
    this.windowMs = windowMs
  }

  /** Record an attempt and report whether it is allowed. */
  allow(key: string, now = Date.now()): boolean {
    const cutoff = now - this.windowMs
    const entries = (this.hits.get(key) ?? []).filter((at) => at >= cutoff)
    entries.push(now)
    this.hits.set(key, entries)
    return entries.length <= this.limit
  }

  /** Forget one key (used when a client proves itself). */
  reset(key: string): void {
    this.hits.delete(key)
  }
}

/** One recorded approval attempt, kept for the operator's audit list. */
export interface ApprovalAttempt {
  readonly at: number
  readonly approvalId: string
  readonly sessionId: string
  readonly deviceId: string
  readonly action: 'approve' | 'reject'
  readonly result: 'rejected-not-supported' | 'validation-failed' | 'delivered'
  readonly reason: string
}

/** Runtime info published once the socket is bound. */
export interface RuntimeInfo {
  readonly port: number
  readonly host: string
  readonly urls: readonly string[]
  readonly lanAddresses: readonly LanAddress[]
}

/** Constructor inputs for the monitor service. */
export interface MonitorServiceDeps {
  readonly config: MonitorConfig
  readonly source: DshSessionSource
  readonly devices: DeviceStore
  readonly frontendDir: string
  /** Public-mode gate; omitted in tests that only exercise LAN behaviour. */
  readonly gate?: PublicGate
}

/**
 * The monitor service. `start()` binds the socket; `stop()` closes it, revokes
 * the live pairing code, and drops every realtime stream.
 */
export class MonitorService {
  readonly config: MonitorConfig
  readonly source: DshSessionSource
  readonly devices: DeviceStore
  readonly pairing: PairingService
  readonly gate: PublicGate
  readonly sse = new SseHub()
  readonly startedAt = Date.now()

  private readonly frontendDir: string
  private server: Server | HttpsServer | undefined
  private pollTimer: NodeJS.Timeout | undefined
  private sweepTimer: NodeJS.Timeout | undefined
  private sweepTimerNote = ''
  private snapshot: { payload: StatusPayload; at: number } | undefined
  private busy = false
  private stopped = false
  private readonly approvedPairingIds = new Set<string>()
  private readonly attempts: ApprovalAttempt[] = []
  private readonly seenClientRequestIds = new Map<string, { status: number; body: unknown }>()
  private shutdownHandlers: Array<() => void> = []

  private readonly claimLimiter = new RateLimiter(20, 60_000)
  private readonly decideLimiter = new RateLimiter(30, 60_000)
  private readonly streamLimiter = new RateLimiter(40, 60_000)
  private readonly approvalLimiter = new RateLimiter(30, 60_000)

  constructor(deps: MonitorServiceDeps) {
    this.config = deps.config
    this.source = deps.source
    this.devices = deps.devices
    this.frontendDir = deps.frontendDir
    this.gate =
      deps.gate ??
      new PublicGate({
        enabled: false,
        tls: false,
        behindTlsTerminator: false,
        dataDir: deps.config.dataDir,
        requirePin: false,
        localAuthorities: [],
      })
    this.pairing = new PairingService({
      ttlSeconds: deps.config.pairTtlSeconds,
      maxAttemptsPerIp: deps.config.pairMaxAttempts,
      attemptWindowSeconds: 300,
    })
  }

  /** Port actually bound (resolves `--port 0`). */
  get port(): number {
    const address = this.server?.address()
    if (address !== null && typeof address === 'object') return address.port
    return this.config.port
  }

  /** Whether the socket is listening. */
  get listening(): boolean {
    return this.server?.listening === true
  }

  /** Current access URLs (loopback first, then LAN candidates). */
  runtimeInfo(): RuntimeInfo {
    const port = this.port
    const lan = listLanAddresses().filter((entry) => this.hostAccepts(entry.address))
    const urls = [`http://127.0.0.1:${port}/`, ...lan.map((entry) => `http://${entry.address}:${port}/`)]
    return { port, host: this.config.host, urls, lanAddresses: lan }
  }

  /** Recently recorded (and refused) approval attempts. */
  get approvalAttempts(): readonly ApprovalAttempt[] {
    return [...this.attempts].reverse()
  }

  /**
   * Run the device retention sweep once.
   *
   * Called at startup and on an interval; also reachable through the loopback
   * admin API so the operator can clean up on demand.
   *
   * @param now - current time (injected for tests).
   * @returns how many records were expired and how many were removed.
   */
  async sweepDevices(now = Date.now()): Promise<{ expired: number; removed: number }> {
    const result = await this.devices.sweep(now)
    if (result.expired > 0 || result.removed > 0) {
      this.sweepTimerNote = `上次清理：标记过期 ${result.expired} 台、移除 ${result.removed} 条（${new Date(now).toLocaleString()}）`
    }
    return result
  }

  /**
   * Device listing with live status and expiry, for the terminal dashboard and
   * the loopback admin API.
   *
   * @param now - current time (injected for tests).
   * @returns the listing plus per-status counts.
   */
  private async deviceListing(now = Date.now()): Promise<{
    devices: readonly Record<string, unknown>[]
    counts: { active: number; expired: number; revoked: number }
  }> {
    await this.devices.load()
    const devices = this.devices.list().map((device) => {
      const status = this.devices.classify(device, now)
      return {
        ...publicDevice(device),
        status,
        expiresAt: this.devices.expiryOf(device, now) ?? null,
      }
    })
    return {
      devices,
      counts: {
        active: devices.filter((entry) => entry['status'] === 'active').length,
        expired: devices.filter((entry) => entry['status'] === 'expired').length,
        revoked: devices.filter((entry) => entry['status'] === 'revoked').length,
      },
    }
  }

  /** Human note about the last retention sweep. */
  get lastSweepNote(): string {
    return this.sweepTimerNote
  }

  /** Start the periodic retention sweep. */
  private startSweepTimer(): void {
    const interval = 6 * 60 * 60 * 1000
    this.sweepTimer = setInterval(() => {
      void this.sweepDevices()
    }, interval)
    this.sweepTimer.unref()
  }

  /** The latest status payload, refreshing it when it is older than the poll interval. */
  async currentStatus(force = false): Promise<StatusPayload> {
    const now = Date.now()
    const interval = Math.max(MIN_POLL_MS, this.config.pollIntervalMs)
    if (!force && this.snapshot !== undefined && now - this.snapshot.at < interval) return withPublicAccess(this.snapshot.payload, this.gate)
    return await this.refresh(force)
  }

  /** Force a refresh; concurrent callers share one in-flight pass. */
  private async refresh(_force: boolean): Promise<StatusPayload> {
    if (this.busy && this.snapshot !== undefined) return withPublicAccess(this.snapshot.payload, this.gate)
    this.busy = true
    try {
      const { payload } = await this.source.snapshot()
      const merged = withPublicAccess(payload, this.gate)
      this.snapshot = { payload: merged, at: Date.now() }
      return merged
    } finally {
      this.busy = false
    }
  }

  /** Bind the socket and start the poll loop. */
  async start(): Promise<RuntimeInfo> {
    await this.devices.load()
    // Retention first: a stale record must not look usable even for one request.
    await this.sweepDevices()
    await this.refresh(true)
    // Mint the first pairing code immediately, so a code exists whether or not an
    // interactive dashboard is attached and the operator never sees an empty QR.
    this.pairing.issue(Date.now(), true)
    this.server = this.createHttpServer()
    this.server.on('clientError', (_error, socket) => {
      socket.destroy()
    })
    await new Promise<void>((resolvePromise, rejectPromise) => {
      const onError = (error: Error): void => {
        rejectPromise(error)
      }
      this.server?.once('error', onError)
      this.server?.listen(this.config.port, this.config.host, () => {
        this.server?.off('error', onError)
        resolvePromise()
      })
    })
    const interval = Math.max(MIN_POLL_MS, this.config.pollIntervalMs)
    this.pollTimer = setInterval(() => {
      void this.tick()
    }, interval)
    this.pollTimer.unref()
    this.startSweepTimer()
    return this.runtimeInfo()
  }

  /** Create the HTTP or HTTPS server, depending on the configured TLS material. */
  private createHttpServer(): Server | HttpsServer {
    const handler = (req: IncomingMessage, res: ServerResponse): void => {
      void this.handle(req, res)
    }
    const cert = this.config.tlsCertPath
    const key = this.config.tlsKeyPath
    if (cert === undefined || key === undefined) return createServer(handler)
    return createHttpsServer({ cert: readFileSync(cert), key: readFileSync(key) }, handler)
  }

  /** Whether this process terminates TLS itself. */
  private get tlsEnabled(): boolean {
    return this.config.tlsCertPath !== undefined && this.config.tlsKeyPath !== undefined
  }

  /** One poll pass: refresh the source and push changes to connected phones. */
  private async tick(): Promise<void> {
    if (this.stopped) return
    try {
      const previous = this.snapshot?.payload
      const payload = await this.refresh(true)
      if (this.sse.size === 0) return
      const changed = previous === undefined || JSON.stringify(previous.source) !== JSON.stringify(payload.source)
      if (changed) this.sse.broadcast({ type: 'status', payload })
      const sessionId = payload.currentSessionId
      if (sessionId === undefined) return
      const previousSession = previous?.sessions.find((s) => s.sessionId === sessionId)
      const currentSession = payload.sessions.find((s) => s.sessionId === sessionId)
      if (currentSession === undefined) return
      if (previousSession?.eventCount !== currentSession.eventCount) {
        const timeline = this.source.timelineFor(sessionId, 60)
        const fresh = timeline.filter((event) => previousSession === undefined || event.seq >= (previousSession.eventCount ?? 0))
        if (fresh.length > 0) this.sse.broadcast({ type: 'events', payload: { sessionId, events: fresh } })
      }
      if (previousSession?.pendingApprovals.length !== currentSession.pendingApprovals.length) {
        this.sse.broadcast({
          type: 'approval',
          payload: { pending: payload.pendingApprovals, decided: payload.recentlyDecided },
        })
      }
    } catch {
      /* a failing pass must never kill the loop; the source reports its own error */
    }
  }

  /** Close every socket and invalidate this process's pairing state. */
  async stop(): Promise<void> {
    if (this.stopped) return
    this.stopped = true
    if (this.pollTimer !== undefined) clearInterval(this.pollTimer)
    this.pollTimer = undefined
    if (this.sweepTimer !== undefined) clearInterval(this.sweepTimer)
    this.sweepTimer = undefined
    // Opportunistically persist the batched lastSeenAt values before exiting.
    await this.devices.flushTouches().catch(() => undefined)
    this.pairing.revokeAll()
    this.sse.close()
    for (const handler of this.shutdownHandlers) handler()
    this.shutdownHandlers = []
    await new Promise<void>((resolvePromise) => {
      if (this.server === undefined || !this.server.listening) {
        resolvePromise()
        return
      }
      this.server.close(() => resolvePromise())
      // Give in-flight responses a beat, then destroy lingering sockets.
      setTimeout(() => this.server?.closeAllConnections?.(), 500).unref()
    })
    this.server = undefined
  }

  /** Register a callback fired during `stop()`. */
  onShutdown(handler: () => void): void {
    this.shutdownHandlers.push(handler)
  }

  // ───────────────────────────── request handling ─────────────────────────────

  /** Route one request. */
  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const trust = this.checkTrust(req)
    if (!trust.ok) {
      this.sendJson(res, 403, { error: { code: 'forbidden-origin', message: trust.reason } })
      return
    }
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    const path = url.pathname
    const method = (req.method ?? 'GET').toUpperCase()
    const purpose = this.requestPurpose(req)

    if (path.startsWith('/api/admin/')) {
      // Admin (pairing confirmation, device revocation) is never reachable from
      // the public internet, whatever the gate says.
      if (!this.isLoopback(req)) {
        this.sendJson(res, 403, { error: { code: 'loopback-only', message: '管理接口只允许从本机访问。' } })
        return
      }
      await this.handleAdmin(req, res, method, path)
      return
    }

    if (purpose === 'public') {
      // `EventSource` cannot attach custom headers, so the SSE stream carries the
      // PIN in a query parameter; every other request uses the header.
      const pin = headerValue(req, PIN_HEADER) ?? url.searchParams.get('pin') ?? undefined
      const decision = this.gate.checkPublicRequest({ from: this.clientIp(req), pin })
      if (!decision.ok) {
        this.sendJson(res, decision.status, {
          error: {
            code: decision.code,
            message: decision.message,
            ...(decision.pinRequired === true ? { pinRequired: true } : {}),
          },
        })
        return
      }
    }

    if (path.startsWith('/api/')) {
      await this.handleApi(req, res, method, path, url)
      return
    }
    await this.serveStatic(req, res, method, path)
  }

  /**
   * Which fence applies to this request: loopback, local network, or public.
   *
   * A request is public when its authority is not one this machine owns and not
   * a private/loopback address. `localhost` and private LAN addresses stay on the
   * LAN path even when public mode is on, so pairing at home keeps working.
   */
  private requestPurpose(req: IncomingMessage): 'loopback' | 'lan' | 'public' {
    return classifyRequest({
      remoteAddress: req.socket.remoteAddress ?? '',
      host: req.headers.host ?? '',
      gate: this.gate,
      hostAccepts: (hostname) => this.hostAccepts(hostname),
    })
  }

  /** Public pairing + health routes (no device session required). */
  private async handlePublic(req: IncomingMessage, res: ServerResponse, method: string, path: string, url: URL): Promise<boolean> {
    if (path === '/api/health' && method === 'GET') {
      const payload: HealthPayload = {
        ok: true,
        version: await readVersion(),
        pairingOpen: this.pairing.hasActiveCode(),
        requiresPairing: true,
      }
      this.sendJson(res, 200, payload)
      return true
    }
    if (path === '/api/pair/session' && method === 'GET') {
      const view = this.pairing.currentView()
      this.sendJson(res, 200, {
        serverName: 'DSH Pocket Monitor',
        lanUrls: this.runtimeInfo().urls,
        pairingOpen: view !== undefined,
        expiresAt: view?.expiresAt ?? null,
        hasClaim: view?.claim !== undefined,
      })
      return true
    }
    if (path === '/api/pair/claim' && method === 'POST') {
      const body = await this.readJsonBody(req, res)
      if (body === undefined) return true
      const ip = this.clientIp(req)
      if (!this.claimLimiter.allow(`claim:${ip}`)) {
        this.sendJson(res, 429, { error: { code: 'rate-limited', message: '配对尝试过于频繁，请稍后再试。' } })
        return true
      }
      const code = stringField(body, 'code')
      const pairSecret = stringField(body, 'pairSecret')
      const deviceName = sanitiseDeviceName(stringField(body, 'deviceName') ?? 'iPhone')
      if (code === undefined || pairSecret === undefined || pairSecret.length < 16) {
        this.sendJson(res, 400, { error: { code: 'invalid-request', message: '需要 code 与至少 16 字符的 pairSecret。' } })
        return true
      }
      const result = this.pairing.claim({ code, pairSecret, deviceName, from: ip })
      if (!result.ok) {
        const status = result.reason === 'rate-limited' ? 429 : 400
        this.sendJson(res, status, { error: { code: result.reason, message: claimMessage(result.reason) } })
        return true
      }
      // A claim from this machine itself is the operator sitting at the console:
      // approve it immediately, unless terminal approval was turned off.
      if (this.isLoopback(req) && this.config.terminalApproval) await this.approveThroughLoopback(result.pairingId)
      this.sendJson(res, 202, { pairingId: result.pairingId, state: 'pending' })
      return true
    }
    if (path === '/api/pair/poll' && method === 'POST') {
      const body = await this.readJsonBody(req, res)
      if (body === undefined) return true
      const pairingId = stringField(body, 'pairingId')
      const pairSecret = stringField(body, 'pairSecret')
      if (pairingId === undefined || pairSecret === undefined) {
        this.sendJson(res, 400, { error: { code: 'invalid-request', message: '需要 pairingId 与 pairSecret。' } })
        return true
      }
      const result = this.pairing.poll({ pairingId, pairSecret })
      if (!result.ok) {
        const status = result.reason === 'unknown-pairing' ? 404 : 409
        this.sendJson(res, status, { error: { code: result.reason, message: result.message ?? pairMessage(result.reason) } })
        return true
      }
      if (result.state === 'pending') {
        this.sendJson(res, 202, { state: 'pending' })
        return true
      }
      this.setDeviceCookie(res, req, result.token)
      this.sendJson(res, 200, { state: 'approved', deviceId: result.deviceId, deviceName: result.deviceName })
      return true
    }
    void url
    return false
  }

  /** Authenticated phone routes. */
  private async handleApi(req: IncomingMessage, res: ServerResponse, method: string, path: string, url: URL): Promise<void> {
    if (await this.handlePublic(req, res, method, path, url)) return

    const device = await this.authenticate(req)
    if (device === undefined) {
      this.sendJson(res, 401, {
        error: { code: 'unauthorized', message: '这台设备还没有绑定，请在电脑上生成配对码后扫码配对。' },
      })
      return
    }

    if (path === '/api/status' && method === 'GET') {
      this.sendJson(res, 200, await this.currentStatus())
      return
    }
    if (path === '/api/events' && method === 'GET') {
      const sessionId = url.searchParams.get('sessionId') ?? (await this.currentStatus()).currentSessionId
      if (sessionId === undefined) {
        this.sendJson(res, 200, { sessionId: null, events: [] })
        return
      }
      const limit = clampNumber(url.searchParams.get('limit'), 1, 400, 120)
      this.sendJson(res, 200, { sessionId, events: this.source.timelineFor(sessionId, limit) })
      return
    }
    if (path === '/api/stream' && method === 'GET') {
      if (!this.streamLimiter.allow(`stream:${this.clientIp(req)}`)) {
        this.sendJson(res, 429, { error: { code: 'rate-limited', message: '连接过于频繁，请稍后再试。' } })
        return
      }
      this.openStream(req, res, device)
      return
    }
    if (path === '/api/device' && method === 'GET') {
      this.sendJson(res, 200, {
        id: device.id,
        name: device.name,
        scopes: device.scopes,
        createdAt: device.createdAt,
        lastSeenAt: device.lastSeenAt,
      })
      return
    }
    if (path === '/api/device' && method === 'DELETE') {
      if (!this.requireSameOrigin(req, res)) return
      await this.devices.revoke(device.id)
      this.sse.disconnectDevice(device.id)
      this.clearDeviceCookie(res, req)
      this.sendJson(res, 200, { revoked: true, deviceId: device.id })
      return
    }
    if (path === '/api/approvals' && method === 'GET') {
      const status = await this.currentStatus(true)
      this.sendJson(res, 200, {
        pending: status.pendingApprovals,
        decided: status.recentlyDecided,
        capability: status.capabilities.approvalDeciding,
        capabilityReason: status.capabilities.approvalDecidingReason,
        attempts: this.approvalAttempts.slice(0, 20),
      })
      return
    }
    const decideMatch = /^\/api\/approvals\/([^/]+)\/decision$/.exec(path)
    if (decideMatch !== null && method === 'POST') {
      if (!this.requireSameOrigin(req, res)) return
      await this.handleDecision(req, res, device, decodeURIComponent(decideMatch[1]))
      return
    }
    if (path.startsWith('/api/public-access') && method === 'GET') {
      this.sendJson(res, 200, this.gate.status())
      return
    }
    this.sendJson(res, 404, { error: { code: 'not-found', message: '没有这个接口。本服务不提供聊天、命令执行或 DSH 代理接口。' } })
  }

  /** Loopback-only admin routes used by the terminal dashboard and tests. */
  private async handleAdmin(req: IncomingMessage, res: ServerResponse, method: string, path: string): Promise<void> {
    if (path === '/api/admin/session' && method === 'GET') {
      const view = this.pairing.currentView()
      this.sendJson(res, 200, {
        serverName: 'DSH Pocket Monitor',
        pid: process.pid,
        startedAt: this.startedAt,
        urls: this.runtimeInfo().urls,
        pairingId: view?.id ?? null,
        pairingCode: view?.code ?? null,
        pairingNonce: view?.nonce ?? null,
        pairingExpiresAt: view?.expiresAt ?? null,
        claim: view?.claim ?? null,
        devices: (await this.deviceListing()).devices,
        deviceRetention: {
          inactivityDays: this.devices.retention.inactivityDays,
          revokedRetentionDays: this.devices.retention.revokedRetentionDays,
          note: this.sweepTimerNote,
        },
        sseClients: this.sse.size,
        source: (await this.currentStatus()).source,
        publicAccess: this.gate.status(),
        publicAccessEnabled: this.gate.enabled,
        publicPinConfigured: this.gate.hasPin,
        publicPinGenerated: this.gate.pinWasGenerated,
        tls: this.tlsEnabled,
      })
      return
    }
    if (path === '/api/admin/pairing/code' && method === 'POST') {
      const view = this.pairing.issue(Date.now(), true)
      this.sendJson(res, 200, { id: view.id, code: view.code, issuedAt: view.issuedAt, expiresAt: view.expiresAt })
      return
    }
    if (path === '/api/admin/pairing/claim' && method === 'POST') {
      const body = await this.readJsonBody(req, res)
      if (body === undefined) return
      const view = this.pairing.currentView()
      if (view === undefined) {
        this.sendJson(res, 409, { error: { code: 'no-active-code', message: '当前没有有效的配对码，请先生成新码。' } })
        return
      }
      const nonce = stringField(body, 'nonce')
      if (nonce === undefined) {
        this.sendJson(res, 400, { error: { code: 'invalid-request', message: '需要 nonce（终端里显示的确认凭证）。' } })
        return
      }
      const approve = body['approve'] !== false
      if (!approve) {
        const decision = this.pairing.decide({ pairingId: view.id, nonce, approve: false, reason: stringField(body, 'reason') })
        if (!decision.ok) {
          this.sendJson(res, 409, { error: { code: 'decision-refused', message: decision.reason } })
          return
        }
        this.sendJson(res, 200, { status: 'rejected' })
        return
      }
      const decision = this.pairing.decide({ pairingId: view.id, nonce, approve: true })
      if (!decision.ok) {
        this.sendJson(res, 409, { error: { code: 'decision-refused', message: decision.reason } })
        return
      }
      if (decision.status === 'rejected') {
        this.sendJson(res, 409, { error: { code: 'decision-refused', message: '这次配对已被拒绝，请重新生成配对码。' } })
        return
      }
      if (!this.approvedPairingIds.has(decision.deviceId)) {
        this.approvedPairingIds.add(decision.deviceId)
        await this.devices.create({
          id: decision.deviceId,
          name: view.claim?.deviceName ?? '手机',
          token: decision.token,
          pairedFrom: view.claim?.claimedFrom,
        })
      }
      const stored = this.devices.get(decision.deviceId)
      this.sendJson(res, 200, { status: 'approved', device: stored === undefined ? null : publicDevice(stored) })
      return
    }
    if (path === '/api/admin/approvals/attempts' && method === 'GET') {
      this.sendJson(res, 200, { attempts: this.approvalAttempts })
      return
    }
    if (path === '/api/admin/devices/sweep' && method === 'POST') {
      const result = await this.sweepDevices()
      this.sendJson(res, 200, { ...result, devices: (await this.deviceListing()).devices })
      return
    }
    const revokeMatch = /^\/api\/admin\/devices\/([^/]+)$/.exec(path)
    if (revokeMatch !== null && method === 'DELETE') {
      const id = decodeURIComponent(revokeMatch[1])
      const revoked = await this.devices.revoke(id)
      if (revoked === undefined) {
        this.sendJson(res, 404, { error: { code: 'not-found', message: '没有这台设备。' } })
        return
      }
      this.sse.disconnectDevice(id)
      this.sendJson(res, 200, { revoked: true, device: publicDevice(revoked) })
      return
    }
    if (path === '/api/admin/public-access/start' && method === 'POST') {
      // Kept as a permanently-not-implemented endpoint on purpose: this service
      // must never download, install or start a tunnel client by itself.
      this.sendJson(res, 501, {
        error: {
          code: 'public_access_not_implemented',
          message:
            '本服务不会自动启动公网隧道（不下载、不安装、不改防火墙）。' +
            '请自行准备隧道或反向代理，然后用 --public 与 --public-url 接入。',
        },
        publicAccess: this.gate.status(),
      })
      return
    }
    if (path === '/api/admin/public-access/pin' && method === 'POST') {
      const body = await this.readJsonBody(req, res)
      if (body === undefined) return
      const requested = stringField(body, 'pin')
      const pin = requested ?? generatePin()
      try {
        await this.gate.setPin(pin, requested === undefined)
      } catch (error) {
        this.sendJson(res, 400, { error: { code: 'invalid-pin', message: error instanceof Error ? error.message : 'PIN 不合法。' } })
        return
      }
      // The PIN is printed, never returned over the wire unless loopback asked for
      // it explicitly — and this whole endpoint is loopback-only anyway.
      process.stdout.write(`\n新的公网访问 PIN：${pin}（${requested === undefined ? '自动生成' : '由你指定'}）\n`)
      this.sendJson(res, 200, {
        pin,
        generated: requested === undefined,
        hint: '在手机页面输入这个 PIN 即可继续访问（每台设备、每个新网络只需输一次）。',
      })
      return
    }
    this.sendJson(res, 404, { error: { code: 'not-found', message: '没有这个管理接口。' } })
  }

  // ───────────────────────────── approvals ─────────────────────────────

  /**
   * The restricted approval endpoint.
   *
   * Every guard is real and tested: device capability, request id, live pending
   * state (re-read from the log, not from a cache), idempotency per
   * `clientRequestId`, and rate limiting. The final delivery step is where this
   * DSH build fails honestly: `approval/request` decisions only exist inside the
   * DSH process, so this endpoint records the attempt and returns an explicit
   * "no external approval channel" error instead of pretending a decision was
   * delivered. It never uses a generic RPC or writes to the session log.
   */
  private async handleDecision(req: IncomingMessage, res: ServerResponse, device: DeviceRecord, approvalId: string): Promise<void> {
    const body = await this.readJsonBody(req, res)
    if (body === undefined) return
    const clientRequestId = stringField(body, 'clientRequestId')
    if (clientRequestId === undefined || clientRequestId.length < 8) {
      this.sendJson(res, 400, {
        error: { code: 'invalid-request', message: '需要 clientRequestId（至少 8 字符），用于保证重复点击不会重复审批。' },
      })
      return
    }
    const cached = this.seenClientRequestIds.get(clientRequestId)
    if (cached !== undefined) {
      this.sendJson(res, cached.status, cached.body)
      return
    }
    if (!this.approvalLimiter.allow(`approval:${device.id}`)) {
      const payload: ApiError = { error: { code: 'rate-limited', message: '操作过于频繁，请稍后再试。' } }
      this.seenClientRequestIds.set(clientRequestId, { status: 429, body: payload })
      this.sendJson(res, 429, payload)
      return
    }

    const action = stringField(body, 'action')
    if (action !== 'approve' && action !== 'reject') {
      const payload: ApiError = { error: { code: 'invalid-request', message: 'action 只能是 approve 或 reject。' } }
      this.seenClientRequestIds.set(clientRequestId, { status: 400, body: payload })
      this.sendJson(res, 400, payload)
      return
    }

    const status = await this.currentStatus(true)
    const pending = status.pendingApprovals.find((entry) => entry.id === approvalId)
    if (pending === undefined) {
      const decided = status.recentlyDecided.find((entry) => entry.id === approvalId)
      const payload: ApiError = decided === undefined
        ? { error: { code: 'approval-not-found', message: '这个审批请求不存在，可能已经不是本次会话的待审批项。' } }
        : { error: { code: 'approval-already-decided', message: `这个审批请求已经有结果了（${decided.outcome}），不能重复审批。` } }
      this.seenClientRequestIds.set(clientRequestId, { status: decided === undefined ? 404 : 409, body: payload })
      this.recordAttempt({
        approvalId,
        sessionId: decided?.sessionId ?? 'unknown',
        deviceId: device.id,
        action,
        result: 'validation-failed',
        reason: payload.error.code,
      })
      this.sendJson(res, decided === undefined ? 404 : 409, payload)
      return
    }

    if (!device.scopes.includes('approval:view')) {
      const payload: ApiError = { error: { code: 'forbidden-scope', message: '这台设备没有查看审批的权限。' } }
      this.seenClientRequestIds.set(clientRequestId, { status: 403, body: payload })
      this.sendJson(res, 403, payload)
      return
    }

    const reason = status.capabilities.approvalDecidingReason
    const payload = {
      error: {
        code: 'approval_channel_unavailable',
        message: `已经收到你对「${pending.toolName}」的${action === 'approve' ? '批准' : '拒绝'}意图，但无法下发给 DSH：${reason}`,
      },
      approval: {
        id: pending.id,
        toolName: pending.toolName,
        sessionId: pending.sessionId,
        action,
        requiredAction: pending.requiredAction ?? null,
        hint: pending.hint ?? null,
      },
      nextStep: `请在运行 DSH 的那台电脑上操作：${pending.hint ?? 'Web GUI 的审批面板或终端里的审批提示'} 手机端会在日志里看到结果变化。`,
      recordedLocally: true,
      deliveredToDsh: false,
    }
    this.recordAttempt({ approvalId, sessionId: pending.sessionId, deviceId: device.id, action, result: 'rejected-not-supported', reason: 'approval_channel_unavailable' })
    this.seenClientRequestIds.set(clientRequestId, { status: 501, body: payload })
    this.trimDecisionCache()
    this.sse.broadcast({
      type: 'approval',
      payload: { pending: status.pendingApprovals, decided: status.recentlyDecided },
    })
    this.sendJson(res, 501, payload)
  }

  /** Append one approval attempt to the in-memory audit list and the on-disk log. */
  private recordAttempt(input: Omit<ApprovalAttempt, 'at'>): void {
    const attempt: ApprovalAttempt = { at: Date.now(), ...input }
    this.attempts.push(attempt)
    if (this.attempts.length > DECISION_MEMORY) this.attempts.splice(0, this.attempts.length - DECISION_MEMORY)
    const line = `${JSON.stringify(attempt)}\n`
    const path = join(this.config.dataDir, 'approval-attempts.jsonl')
    void mkdir(this.config.dataDir, { recursive: true })
      .then(() => appendFile(path, line, 'utf8'))
      .catch(() => {
        /* audit logging must never break a request */
      })
  }

  /** Keep the idempotency cache bounded. */
  private trimDecisionCache(): void {
    if (this.seenClientRequestIds.size <= 500) return
    const excess = this.seenClientRequestIds.size - 500
    let removed = 0
    for (const key of this.seenClientRequestIds.keys()) {
      this.seenClientRequestIds.delete(key)
      removed += 1
      if (removed >= excess) break
    }
  }

  /** Approve a loopback-originated claim and bind the device before the phone polls. */
  private async approveThroughLoopback(pairingId: string): Promise<boolean> {
    const decision = this.pairing.approveClaim(pairingId, 'loopback')
    if (!decision.ok) return false
    if (!this.approvedPairingIds.has(decision.deviceId)) {
      this.approvedPairingIds.add(decision.deviceId)
      await this.devices.create({
        id: decision.deviceId,
        name: decision.deviceName,
        token: decision.token,
        pairedFrom: decision.claimedFrom,
      })
    }
    return true
  }

  // ───────────────────────────── streaming ─────────────────────────────

  /** Open one SSE stream for a paired device. */
  private openStream(req: IncomingMessage, res: ServerResponse, device: DeviceRecord): void {
    res.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-store, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    })
    res.write(': connected\n\n')
    const remove = this.sse.add(device.id, res)
    void this.currentStatus().then((payload) => {
      const frame: ServerFrame = { type: 'hello', payload: { deviceId: device.id, status: payload.source.status } }
      res.write(`data: ${JSON.stringify(frame)}\n\n`)
      const statusFrame: ServerFrame = { type: 'status', payload }
      res.write(`data: ${JSON.stringify(statusFrame)}\n\n`)
    })
    req.on('close', () => {
      remove()
    })
  }

  // ───────────────────────────── helpers ─────────────────────────────

  /**
   * Resolve the device session from the cookie or a bearer token.
   *
   * The token is what makes a phone recognised from *any* network: nothing here
   * depends on the source address, so a paired phone keeps working after moving
   * between Wi-Fi and cellular. Public requests additionally need the access PIN,
   * which the router already checked before this runs.
   */
  private async authenticate(req: IncomingMessage): Promise<DeviceRecord | undefined> {
    const device = await this.resolveDevice(req)
    const ip = this.clientIp(req)
    if (device !== undefined) {
      this.gate.noteAuthSuccess(ip)
      return device
    }
    if (this.requestPurpose(req) === 'public') {
      const failure = this.gate.noteAuthFailure(ip)
      if (failure.limited) return undefined
    }
    return undefined
  }

  /** Look up the device from the bearer token or the device cookie. */
  private async resolveDevice(req: IncomingMessage): Promise<DeviceRecord | undefined> {
    const header = req.headers.authorization
    if (typeof header === 'string' && header.toLowerCase().startsWith('bearer ')) {
      return await this.devices.authenticate(header.slice(7).trim())
    }
    const cookies = parseCookies(req.headers.cookie)
    const token = cookies[DEVICE_COOKIE]
    if (token === undefined) return undefined
    return await this.devices.authenticate(token)
  }

  /** Whether a request came from this machine. */
  private isLoopback(req: IncomingMessage): boolean {
    return isLoopbackAddress(req.socket.remoteAddress ?? '')
  }

  /** Best-effort client identity for rate limiting and audit. */
  private clientIp(req: IncomingMessage): string {
    return req.socket.remoteAddress ?? 'unknown'
  }

  /** Host/Origin fence: DNS-rebinding and cross-site protection. */
  private checkTrust(req: IncomingMessage): { ok: true } | { ok: false; reason: string } {
    const host = req.headers.host
    if (host === undefined || host.trim() === '') return { ok: false, reason: '缺少 Host 头。' }
    const hostname = stripPort(host)
    if (!this.hostAccepts(hostname)) return { ok: false, reason: `Host ${hostname} 不在本服务的可信地址列表里。` }
    const origin = req.headers.origin
    if (typeof origin === 'string' && origin !== '') {
      let originHost: string
      try {
        originHost = new URL(origin).host
      } catch {
        return { ok: false, reason: 'Origin 头无法解析。' }
      }
      if (originHost.toLowerCase() !== host.toLowerCase()) return { ok: false, reason: 'Origin 与 Host 不一致，已拒绝跨站请求。' }
    }
    if (req.headers['sec-fetch-site'] === 'cross-site') return { ok: false, reason: '拒绝跨站浏览器请求（sec-fetch-site: cross-site）。' }
    return { ok: true }
  }

  /** Whether this service answers to a hostname. */
  private hostAccepts(hostname: string): boolean {
    const normalised = hostname.toLowerCase().replace(/^\[|\]$/g, '')
    if (normalised === '127.0.0.1' || normalised === 'localhost' || normalised === '::1') return true
    if (normalised === this.config.host.toLowerCase()) return true
    for (const entry of this.config.trustedOrigins) {
      if (entry.toLowerCase() === normalised || stripPort(entry).toLowerCase() === normalised) return true
    }
    for (const candidate of listLanAddresses()) if (candidate.address === normalised) return true
    // A requested bind host of 0.0.0.0 means "whatever address a phone types";
    // the device cookie and Origin check remain the actual authorisation.
    if (this.config.host === '0.0.0.0' && isPrivateIpv4(normalised)) return true
    // Public mode makes the declared authority reachable; `requestPurpose` then
    // routes it onto the public path, where the PIN and device token decide.
    if (this.gate.isPublicAuthority(hostname)) return true
    return false
  }

  /** Require a same-origin mutation request (CSRF defence beyond SameSite). */
  private requireSameOrigin(req: IncomingMessage, res: ServerResponse): boolean {
    const origin = req.headers.origin
    if (origin === undefined || origin === '') return true
    const host = req.headers.host
    if (host === undefined) return false
    try {
      if (new URL(origin).host.toLowerCase() === host.toLowerCase()) return true
    } catch {
      /* fall through to refusal */
    }
    this.sendJson(res, 403, { error: { code: 'forbidden-origin', message: 'Origin 与 Host 不一致。' } })
    return false
  }

  /** Read and validate a JSON request body. */
  private async readJsonBody(req: IncomingMessage, res: ServerResponse): Promise<Record<string, unknown> | undefined> {
    const limit = 64 * 1024
    const chunks: Buffer[] = []
    let total = 0
    try {
      for await (const chunk of req) {
        const buffer = typeof chunk === 'string' ? Buffer.from(chunk) : chunk
        total += buffer.length
        if (total > limit) {
          this.sendJson(res, 413, { error: { code: 'payload-too-large', message: '请求体过大。' } })
          return undefined
        }
        chunks.push(buffer)
      }
    } catch {
      this.sendJson(res, 400, { error: { code: 'invalid-request', message: '读取请求体失败。' } })
      return undefined
    }
    if (total === 0) return {}
    try {
      const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString('utf8'))
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not an object')
      return parsed as Record<string, unknown>
    } catch {
      this.sendJson(res, 400, { error: { code: 'invalid-json', message: '请求体不是 JSON 对象。' } })
      return undefined
    }
  }

  /** Set the device cookie bound to the request's authority. */
  private setDeviceCookie(res: ServerResponse, req: IncomingMessage, token: string): void {
    // `Secure` only when the request actually arrived over TLS; marking it Secure
    // on the LAN's plain HTTP would make the cookie unusable.
    const secure = this.tlsEnabled || isHttpsRequest(req) ? '; Secure' : ''
    res.setHeader('set-cookie', `${DEVICE_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/${secure}; Max-Age=${30 * 24 * 3600}`)
  }

  /** Clear the device cookie. */
  private clearDeviceCookie(res: ServerResponse, req: IncomingMessage): void {
    void req
    res.setHeader('set-cookie', `${DEVICE_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`)
  }

  /** Send a JSON response with no-store caching. */
  private sendJson(res: ServerResponse, status: number, body: unknown): void {
    if (res.headersSent) return
    const payload = JSON.stringify(body)
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'content-length': Buffer.byteLength(payload),
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    })
    res.end(payload)
  }

  /** Serve the built frontend, with an SPA fallback to index.html. */
  private async serveStatic(req: IncomingMessage, res: ServerResponse, method: string, path: string): Promise<void> {
    if (method !== 'GET' && method !== 'HEAD') {
      this.sendJson(res, 405, { error: { code: 'method-not-allowed', message: '只支持 GET/HEAD。' } })
      return
    }
    const relative = path === '/' ? 'index.html' : path.replace(/^\/+/, '')
    const target = resolve(join(this.frontendDir, normalize(relative)))
    const root = resolve(this.frontendDir)
    if (!target.startsWith(root + sep) && target !== root) {
      this.sendJson(res, 403, { error: { code: 'forbidden-path', message: '路径不合法。' } })
      return
    }
    const file = (await stat(target).catch(() => undefined))?.isFile() === true ? target : join(root, 'index.html')
    const exists = (await stat(file).catch(() => undefined))?.isFile() === true
    if (!exists) {
      res.writeHead(503, { 'content-type': 'text/plain; charset=utf-8' })
      res.end('前端资源还没有构建。请先运行 npm run build（或 npm run dev:frontend 用 Vite 开发服务器）。')
      return
    }
    const content = await readFile(file)
    res.writeHead(200, {
      'content-type': mimeType(file),
      'cache-control': file.endsWith('index.html') ? 'no-store' : 'public, max-age=600',
      'content-length': content.length,
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    })
    if (method === 'HEAD') res.end()
    else res.end(content)
  }
}

/**
 * Decide which fence a request belongs to.
 *
 * Kept pure and exported so the decision matrix can be tested directly: whether
 * a request counts as "public" decides whether the access PIN is demanded, and
 * that must not depend on being able to fake a foreign socket in a test.
 *
 * @param input - observed remote address, `Host` header, gate, and the local
 *   authority test used for the LAN fence.
 * @returns `loopback`, `lan`, or `public`.
 */
export function classifyRequest(input: {
  remoteAddress: string
  host: string
  gate: PublicGate
  hostAccepts: (hostname: string) => boolean
}): 'loopback' | 'lan' | 'public' {
  if (isLoopbackAddress(input.remoteAddress)) return 'loopback'
  if (input.host === '') return 'lan'
  // Public is checked first: a declared public authority must take the public
  // path (and therefore the PIN requirement) even though the fence also accepts
  // it as a reachable authority.
  if (input.gate.isPublicAuthority(input.host)) return 'public'
  if (input.hostAccepts(stripPort(input.host))) return 'lan'
  // Anything else already failed the fence; treat it as LAN so the failure mode
  // stays "401 unpaired" rather than leaking the public-mode machinery.
  return 'lan'
}

/** Whether a socket address is this machine's own loopback interface. */
export function isLoopbackAddress(address: string): boolean {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
}

/**
 * Project the live public-access state into a status payload's capabilities.
 *
 * The adapter owns the DSH-facing capabilities; the service owns this one,
 * because only it knows whether public mode was switched on.
 *
 * @param payload - the adapter's payload.
 * @param gate - the public-access gate.
 * @returns the same payload with `capabilities.publicAccess*` refreshed.
 */
export function withPublicAccess(payload: StatusPayload, gate: PublicGate): StatusPayload {
  const status = gate.status()
  return {
    ...payload,
    capabilities: {
      ...payload.capabilities,
      publicAccess: status.mode === 'active' ? 'active' : 'disabled',
      publicAccessReason: status.reason,
    },
  }
}

/** Public projection of a device record (never includes the token hash). */
export function publicDevice(device: DeviceRecord): Record<string, unknown> {  return {
    id: device.id,
    name: device.name,
    scopes: device.scopes,
    createdAt: device.createdAt,
    lastSeenAt: device.lastSeenAt,
    revokedAt: device.revokedAt ?? null,
    pairedFrom: device.pairedFrom ?? null,
  }
}

/** Parse a Cookie header into a map. */
export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  if (header === undefined) return out
  for (const part of header.split(';')) {
    const index = part.indexOf('=')
    if (index === -1) continue
    const key = part.slice(0, index).trim()
    const value = part.slice(index + 1).trim()
    if (key !== '') out[key] = value
  }
  return out
}

/** Strip a port from an authority. */
function stripPort(authority: string): string {
  const trimmed = authority.trim()
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']')
    return end === -1 ? trimmed : trimmed.slice(1, end)
  }
  const colon = trimmed.lastIndexOf(':')
  return colon === -1 ? trimmed : trimmed.slice(0, colon)
}

/** Read one request header as a trimmed string. */
function headerValue(req: IncomingMessage, name: string): string | undefined {
  const raw = req.headers[name]
  const value = Array.isArray(raw) ? raw[0] : raw
  if (value === undefined) return undefined
  const trimmed = value.trim()
  return trimmed === '' ? undefined : trimmed
}

/** Whether the request reached this process over HTTPS (directly or via a proxy). */
function isHttpsRequest(req: IncomingMessage): boolean {
  if ((req.socket as { encrypted?: boolean }).encrypted === true) return true
  const forwarded = headerValue(req, 'x-forwarded-proto')
  return forwarded !== undefined && forwarded.split(',')[0]?.trim().toLowerCase() === 'https'
}

/** Whether an IPv4 literal is private/CGNAT (used only for the 0.0.0.0 bind case). */
function isPrivateIpv4(hostname: string): boolean {
  const parts = hostname.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false
  const [a, b] = parts
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  return false
}

/** Read a string field defensively. */
function stringField(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key]
  return typeof value === 'string' && value !== '' ? value : undefined
}

/** Clamp a query parameter to an integer range. */
function clampNumber(raw: string | null, min: number, max: number, fallback: number): number {
  if (raw === null) return fallback
  const parsed = Number(raw)
  if (!Number.isFinite(parsed)) return fallback
  return Math.min(max, Math.max(min, Math.trunc(parsed)))
}

/** Human message for a refused claim. */
function claimMessage(reason: string): string {
  switch (reason) {
    case 'no-active-code':
      return '配对码不正确或已失效，请在电脑上重新生成。'
    case 'expired':
      return '配对码已过期，请在电脑上重新生成。'
    case 'already-claimed':
      return '这个配对码已经被另一台设备占用，请在电脑上重新生成。'
    case 'already-bound':
      return '这个配对码已经用过并绑定成功了。'
    case 'rate-limited':
      return '尝试次数过多，请稍后再试。'
    default:
      return '配对失败。'
  }
}

/** Human message for a refused poll. */
function pairMessage(reason: string): string {
  switch (reason) {
    case 'unknown-pairing':
      return '这次配对不存在或已被取消，请重新扫码。'
    case 'expired':
      return '配对请求已超时，请重新扫码。'
    case 'rejected':
      return '电脑端拒绝或未确认这次配对。'
    case 'denied':
      return '令牌已经发放过了，请重新配对。'
    default:
      return '配对未完成。'
  }
}

/** Content type for a served file. */
function mimeType(path: string): string {
  switch (extname(path).toLowerCase()) {
    case '.html':
      return 'text/html; charset=utf-8'
    case '.js':
      return 'text/javascript; charset=utf-8'
    case '.css':
      return 'text/css; charset=utf-8'
    case '.json':
    case '.webmanifest':
      return 'application/json; charset=utf-8'
    case '.svg':
      return 'image/svg+xml'
    case '.png':
      return 'image/png'
    case '.ico':
      return 'image/x-icon'
    case '.woff2':
      return 'font/woff2'
    case '.txt':
      return 'text/plain; charset=utf-8'
    default:
      return 'application/octet-stream'
  }
}

/** Hash helper re-exported for the wiring layer's tests. */
export { hashToken }
