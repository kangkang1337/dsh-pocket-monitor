/**
 * Public-access mode: the opt-in gateway that lets a **paired** phone reach the
 * monitor from another network.
 *
 * Two invariants shape everything here:
 *
 *  1. **Reachability is not identity.** Accepting a public `Host` only makes the
 *     monitor *reachable*; every read still requires a device token issued
 *     through the desktop-confirmed pairing flow. An unpaired device that finds
 *     the URL gets a 401 and nothing else.
 *  2. **A public token needs a second factor.** A device token is a bearer
 *     credential: if it leaks (browser sync, a shared phone, a proxy log) it is
 *     enough on its own. Public mode therefore asks for an access PIN from any
 *     non-loopback client and rate-limits both the PIN and the token so neither
 *     can be brute-forced.
 *
 * The monitor never installs, downloads, starts or configures a tunnel: the
 * operator brings their own (Cloudflare Tunnel, ngrok, Tailscale, a reverse
 * proxy, …) and passes its hostname via `--public-url`.
 *
 * @module dsh-pocket-monitor/services/public-access
 */

import { createHash, randomInt, timingSafeEqual } from 'node:crypto'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import type { PublicAccessStatus } from '../../../shared/types/index.ts'

/** Sliding-window counter used by every public-mode limiter. */
class Window {
  private readonly hits = new Map<string, number[]>()
  private readonly limit: number
  private readonly windowMs: number

  constructor(limit: number, windowMs: number) {
    this.limit = limit
    this.windowMs = windowMs
  }

  /** Record one attempt and report whether it is still allowed. */
  allow(key: string, now = Date.now()): boolean {
    const cutoff = now - this.windowMs
    const entries = (this.hits.get(key) ?? []).filter((at) => at >= cutoff)
    entries.push(now)
    this.hits.set(key, entries)
    return entries.length <= this.limit
  }

  /** How many attempts this key has left inside the window. */
  remaining(key: string, now = Date.now()): number {
    const cutoff = now - this.windowMs
    const used = (this.hits.get(key) ?? []).filter((at) => at >= cutoff).length
    return Math.max(0, this.limit - used)
  }

  /** Clear one key, e.g. after the client proved itself. */
  reset(key: string): void {
    this.hits.delete(key)
  }
}

/** Result of asking the gate whether a public request may proceed. */
export type GateDecision =
  | { readonly ok: true }
  | {
      readonly ok: false
      readonly status: 401 | 429
      readonly code: string
      readonly message: string
      readonly pinRequired?: boolean
    }

/** Options for {@link PublicGate}. */
export interface PublicGateOptions {
  /** Whether public mode is on. */
  readonly enabled: boolean
  /** Operator-declared public authority, e.g. `mon.example.com` or `host:port`. */
  readonly publicUrl?: string
  /** True when this process terminates TLS itself. */
  readonly tls: boolean
  /** True when a tunnel/reverse proxy terminates TLS in front of this process. */
  readonly behindTlsTerminator: boolean
  /** Directory holding this project's own state (the PIN hash lives here). */
  readonly dataDir: string
  /** Require the access PIN for public requests (defaults to on). */
  readonly requirePin: boolean
  /** Local authorities that must never be treated as public. */
  readonly localAuthorities: readonly string[]
}

/** Persisted PIN record. */
interface PinFile {
  readonly version: 1
  readonly algorithm: 'sha256'
  /** `sha256(pepper + pin)`; the PIN itself is never stored. */
  readonly hash: string
  readonly createdAt: number
  /** True when the monitor generated it rather than the operator. */
  readonly generated: boolean
}

/** Hash a PIN with a fixed pepper. */
function hashPin(pin: string): string {
  return createHash('sha256').update(`dsh-pocket-monitor/pin:${pin}`, 'utf8').digest('hex')
}

/** Constant-time comparison of two hex digests. */
function safeEqualHex(left: string, right: string): boolean {
  const a = Buffer.from(left, 'hex')
  const b = Buffer.from(right, 'hex')
  if (a.length === 0 || a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

/** Whether an authority is loopback or private-LAN rather than the public internet. */
export function isLocalAuthority(host: string): boolean {
  const name = host.trim().toLowerCase().replace(/^\[|\]$/g, '')
  if (name === 'localhost' || name === '127.0.0.1' || name === '::1') return true
  const bare = name.split(':')[0] ?? ''
  const parts = bare.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false
  const [a, b] = parts
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  return false
}

/** Normalise an authority for comparison: lowercase, brackets and port removed. */
export function normaliseAuthority(host: string): string {
  const trimmed = host.trim().toLowerCase()
  const withoutBrackets = trimmed.startsWith('[') ? (trimmed.slice(1).split(']')[0] ?? '') : trimmed
  return withoutBrackets.split(':')[0] ?? ''
}

/** Generate a 6-digit access PIN. */
export function generatePin(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, '0')
}

/**
 * The public-mode gate: owns the PIN, the public-host decision, and every rate
 * limit that exists because the monitor may now be reachable from the internet.
 */
export class PublicGate {
  readonly enabled: boolean
  readonly publicUrl?: string
  readonly tls: boolean
  readonly behindTlsTerminator: boolean
  readonly requirePin: boolean
  private readonly dataDir: string
  private readonly localAuthorities: readonly string[]
  private pinHash: string | undefined
  private pinGenerated = false
  private pinCreatedAt = 0
  private loaded = false

  /** PIN attempts: few tries per source address. */
  private readonly pinLimiter = new Window(10, 10 * 60_000)
  /** Token failures per source address. */
  private readonly authLimiter = new Window(30, 10 * 60_000)
  /** Global token-failure budget, so one botnet cannot grind a single token. */
  private readonly globalAuthLimiter = new Window(300, 10 * 60_000)
  /** Overall public request budget per address. */
  private readonly requestLimiter = new Window(1_200, 60_000)

  constructor(options: PublicGateOptions) {
    this.enabled = options.enabled
    this.publicUrl = options.publicUrl
    this.tls = options.tls
    this.behindTlsTerminator = options.behindTlsTerminator
    this.dataDir = options.dataDir
    this.requirePin = options.requirePin
    this.localAuthorities = options.localAuthorities
  }

  /** File holding the PIN hash. */
  get pinFilePath(): string {
    return join(this.dataDir, 'access-pin.json')
  }

  /** Whether a PIN is configured. */
  get hasPin(): boolean {
    return this.pinHash !== undefined
  }

  /** Whether the current PIN was generated by the monitor. */
  get pinWasGenerated(): boolean {
    return this.pinGenerated
  }

  /** When the current PIN was created. */
  get pinCreatedAtValue(): number {
    return this.pinCreatedAt
  }

  /**
   * Load the stored PIN, generating one when public mode needs a PIN and none
   * exists yet.
   *
   * @returns the PIN when this call generated a new one, so the caller can print
   *   it exactly once.
   */
  async load(): Promise<string | undefined> {
    if (this.loaded) return undefined
    this.loaded = true
    try {
      const raw = await readFile(this.pinFilePath, 'utf8')
      const parsed = JSON.parse(raw) as Partial<PinFile>
      if (typeof parsed.hash === 'string' && parsed.hash.length === 64) {
        this.pinHash = parsed.hash
        this.pinGenerated = parsed.generated === true
        this.pinCreatedAt = typeof parsed.createdAt === 'number' ? parsed.createdAt : 0
        return undefined
      }
    } catch {
      /* no PIN yet */
    }
    if (!this.enabled || !this.requirePin) return undefined
    const pin = generatePin()
    await this.setPin(pin, true)
    return pin
  }

  /**
   * Set (or rotate) the PIN.
   *
   * @param pin - 4-12 digits.
   * @param generated - whether the monitor produced it.
   */
  async setPin(pin: string, generated: boolean): Promise<void> {
    if (!/^\d{4,12}$/.test(pin)) throw new Error('访问 PIN 必须是 4-12 位数字')
    this.pinHash = hashPin(pin)
    this.pinGenerated = generated
    this.pinCreatedAt = Date.now()
    const payload: PinFile = {
      version: 1,
      algorithm: 'sha256',
      hash: this.pinHash,
      createdAt: this.pinCreatedAt,
      generated,
    }
    await mkdir(dirname(this.pinFilePath), { recursive: true })
    const temp = `${this.pinFilePath}.tmp-${Date.now()}`
    await writeFile(temp, `${JSON.stringify(payload, null, 2)}\n`, 'utf8')
    await rename(temp, this.pinFilePath)
  }

  /** Verify a candidate PIN in constant time. */
  verifyPin(candidate: string): boolean {
    if (this.pinHash === undefined) return false
    return safeEqualHex(this.pinHash, hashPin(candidate))
  }

  /**
   * Whether an authority is "the public internet entry point" for this service.
   *
   * @param host - the request's `Host` header (port allowed).
   * @returns true when the host is not a trusted/local authority and public mode
   *   is on.
   */
  isPublicAuthority(host: string): boolean {
    if (!this.enabled) return false
    const name = normaliseAuthority(host)
    if (name === '') return false
    // Authorities this machine owns (its LAN literals, an explicit trusted host)
    // stay on the local path: reaching them does not mean "arrived from the
    // internet", so they must not trigger the public PIN flow.
    for (const local of this.localAuthorities) {
      if (normaliseAuthority(local) === name) return false
    }
    if (isLocalAuthority(host)) return false
    if (this.publicUrl === undefined) return true
    return normaliseAuthority(this.publicUrl) === name
  }

  /**
   * Gate one request that arrived on a public authority.
   *
   * @param input - source address, presented PIN (if any), current time.
   * @returns a decision; a refusal carries the HTTP status to answer with.
   */
  checkPublicRequest(input: { from: string; pin?: string; now?: number }): GateDecision {
    const now = input.now ?? Date.now()
    if (!this.requestLimiter.allow(`req:${input.from}`, now)) {
      return { ok: false, status: 429, code: 'rate-limited', message: '请求过于频繁，请稍后再试。' }
    }
    if (!this.requirePin) return { ok: true }
    if (this.pinHash === undefined) {
      return {
        ok: false,
        status: 401,
        code: 'pin-not-configured',
        message: '公网访问已开启但没有设置访问 PIN，请在电脑端设置后再试。',
        pinRequired: true,
      }
    }
    const key = `pin:${input.from}`
    if (!this.pinLimiter.allow(key, now)) {
      return { ok: false, status: 429, code: 'rate-limited', message: 'PIN 尝试过于频繁，请稍后再试。' }
    }
    if (input.pin === undefined || input.pin === '' || !this.verifyPin(input.pin)) {
      const remaining = this.pinLimiter.remaining(key, now)
      return {
        ok: false,
        status: 401,
        code: 'pin-required',
        message: `公网访问需要访问 PIN（本地址还剩 ${remaining} 次尝试）。PIN 在运行 DSH 的电脑终端里显示。`,
        pinRequired: true,
      }
    }
    this.pinLimiter.reset(key)
    return { ok: true }
  }

  /**
   * Note a failed device-token authentication on a public authority.
   *
   * Called only after authentication already failed, so it never opens a path —
   * it only bounds brute-force attempts.
   *
   * @param from - source address.
   * @param now - current time.
   * @returns whether the caller should answer 429 instead of 401.
   */
  noteAuthFailure(from: string, now = Date.now()): { limited: false } | { limited: true; message: string } {
    const perSource = this.authLimiter.allow(`auth:${from}`, now)
    const global = this.globalAuthLimiter.allow('auth:global', now)
    if (perSource && global) return { limited: false }
    return {
      limited: true,
      message: '认证失败次数过多，请稍后再试，或在电脑端撤销并重新配对这台设备。',
    }
  }

  /** Clear the failure counters after a successful authentication. */
  noteAuthSuccess(from: string): void {
    this.authLimiter.reset(`auth:${from}`)
  }

  /** Status payload for the phone and the dashboard. */
  status(): PublicAccessStatus {
    if (!this.enabled) {
      return {
        mode: 'disabled',
        configured: false,
        active: false,
        url: null,
        reason:
          '公网访问未启用：手机只能在同一个局域网里查看。需要换个网络也能看时，用 --public 启用（并自备隧道或 HTTPS）。',
      }
    }
    const tlsPart = this.tls ? '本服务已用 HTTPS' : this.behindTlsTerminator ? '由你的隧道/反向代理终止 TLS' : '没有 TLS'
    const pinPart = this.requirePin ? '已要求访问 PIN' : '未要求访问 PIN（只在你明确关闭时才这样）'
    return {
      mode: 'active',
      configured: this.publicUrl !== undefined,
      active: true,
      url: this.publicUrl ?? null,
      reason:
        `公网访问已启用（${tlsPart}；${pinPart}）。未配对设备一律 401；已配对设备换网络后仍可访问。` +
        '本服务不会安装或启动任何隧道客户端，也不会改防火墙。',
    }
  }
}

/**
 * Reserved: automatic tunnel start. Deliberately never implemented — starting a
 * network tunnel and exposing this machine to the internet is the operator's
 * decision, made with their own tooling.
 *
 * @param _options - ignored.
 * @throws always.
 */
export function startPublicAccess(_options?: unknown): never {
  throw new Error(
    '本服务不会自动启动公网隧道：请自行准备隧道（Cloudflare Tunnel / ngrok / Tailscale / 反向代理），' +
      '再用 --public 与 --public-url 把它接进来。',
  )
}

/**
 * Reserved: automatic tunnel stop. Deliberately never implemented.
 *
 * @throws always.
 */
export function stopPublicAccess(): never {
  throw new Error('本服务没有由它管理的隧道可停止；请在你的隧道工具里关闭它。')
}

/** Status used when public mode is off (kept for callers that only need a label). */
export function getPublicAccessStatus(): PublicAccessStatus {
  return {
    mode: 'disabled',
    configured: false,
    active: false,
    url: null,
    reason: '公网访问未启用：当前只在局域网内可访问。',
  }
}

/** Error type kept for the admin endpoint's not-implemented answer. */
export class PublicAccessNotImplementedError extends Error {
  readonly code = 'public_access_not_implemented'

  constructor(operation: string) {
    super(`${operation} 不做：本服务不会下载、安装或启动任何隧道客户端，也不会修改防火墙或路由器配置。`)
    this.name = 'PublicAccessNotImplementedError'
  }
}
