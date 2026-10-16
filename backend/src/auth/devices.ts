/**
 * Paired-device store: the monitor's own identity layer.
 *
 * Only this project's tokens live here. The DSH launch token, DSH cookies and
 * API keys are never read, stored, or forwarded to a phone. Tokens are stored as
 * SHA-256 hashes so a leaked state file cannot be replayed as a session.
 *
 * @module dsh-pocket-monitor/auth/devices
 */

import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto'
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'

/** Scopes a phone session can hold. Deliberately tiny. */
export type DeviceScope = 'status:read' | 'events:read' | 'approval:view'

/** Every scope a paired phone receives; there is no wider one to grant. */
export const DEFAULT_SCOPES: readonly DeviceScope[] = ['status:read', 'events:read', 'approval:view']

/** One bound device. */
export interface DeviceRecord {
  readonly id: string
  readonly name: string
  readonly tokenHash: string
  readonly scopes: readonly DeviceScope[]
  readonly createdAt: number
  readonly lastSeenAt: number
  readonly pairedFrom?: string
  /** Set when the user revoked this device; the record is kept for the audit list. */
  readonly revokedAt?: number
  /** Set when cleanup confirmed the device went stale; its token stops working. */
  readonly expiredAt?: number
}

/** How the registry classifies one device right now. */
export type DeviceStatus = 'active' | 'expired' | 'revoked'

/** Options for {@link DeviceStore}. */
export interface DeviceStoreOptions {
  /**
   * Days a device may sit unused before it expires and its token stops working.
   * `0` disables expiry entirely (every device stays valid until revoked).
   */
  readonly inactivityDays: number
  /** Days a revoked record is kept for the audit list before being dropped. */
  readonly revokedRetentionDays: number
  /** How often a batched `lastSeenAt` update is written to disk. */
  readonly touchFlushMs: number
}

/** Defaults applied when the caller does not configure retention. */
export const DEFAULT_DEVICE_OPTIONS: DeviceStoreOptions = {
  inactivityDays: 30,
  revokedRetentionDays: 30,
  touchFlushMs: 60_000,
}

/** On-disk shape. */
interface DeviceFile {
  readonly version: 1
  readonly devices: readonly DeviceRecord[]
}

/** Hash a bearer token for storage and comparison. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex')
}

/** Compare two hashes without leaking timing information. */
export function hashEquals(left: string, right: string): boolean {
  const a = Buffer.from(left, 'utf8')
  const b = Buffer.from(right, 'utf8')
  if (a.length !== b.length) return false
  return timingSafeEqual(a, b)
}

/** Generate a 256-bit bearer token. */
export function generateToken(): string {
  return randomBytes(32).toString('base64url')
}

/**
 * Persistent, revocable device registry with inactivity expiry.
 *
 * Expiry is enforced the moment it is observed (so a stale token stops working
 * immediately), while the file itself is only rewritten when something changes —
 * `authenticate()` is on the hot path for every phone request, so it must not do
 * disk I/O per request.
 */
export class DeviceStore {
  private readonly path: string
  private readonly options: DeviceStoreOptions
  private devices: DeviceRecord[] = []
  private loaded = false
  /** Changes not yet written back (final lastSeenAt per device). */
  private readonly pendingTouches = new Map<string, number>()
  private lastFlushAt = 0

  constructor(dataDir: string, options: Partial<DeviceStoreOptions> = {}) {
    this.path = join(dataDir, 'devices.json')
    this.options = { ...DEFAULT_DEVICE_OPTIONS, ...options }
  }

  /** Path of the registry file (for the CLI dashboard). */
  get filePath(): string {
    return this.path
  }

  /** Effective retention policy. */
  get retention(): DeviceStoreOptions {
    return this.options
  }

  /** Load the registry, tolerating a missing file. */
  async load(): Promise<void> {
    if (this.loaded) return
    try {
      const raw = await readFile(this.path, 'utf8')
      const parsed = JSON.parse(raw) as Partial<DeviceFile>
      this.devices = Array.isArray(parsed.devices) ? parsed.devices.filter(isDeviceRecord) : []
    } catch {
      this.devices = []
    }
    this.loaded = true
  }

  /** Persist the registry atomically. */
  private async persist(): Promise<void> {
    const payload: DeviceFile = { version: 1, devices: this.devices }
    await mkdir(dirname(this.path), { recursive: true })
    const temp = `${this.path}.tmp-${randomUUID()}`
    await writeFile(temp, `${JSON.stringify(payload, null, 2)}\n`, 'utf8')
    await rename(temp, this.path)
  }

  /** Every device, including revoked and expired ones, newest first. */
  list(): readonly DeviceRecord[] {
    return [...this.devices].sort((a, b) => b.createdAt - a.createdAt)
  }

  /** Only devices that can still authenticate right now. */
  listActive(now = Date.now()): readonly DeviceRecord[] {
    return this.list().filter((device) => this.classify(device, now) === 'active')
  }

  /**
   * Classify one device against the retention policy.
   *
   * Expiry is *computed* from `lastSeenAt`, never inferred from `expiredAt`:
   * the stamp only records when the expiry was first observed (for the audit
   * list), so a device that comes back before cleanup still works. Treating the
   * stamp as the criterion would let one replayed request permanently kill a
   * device that was merely idle.
   *
   * @param device - the record to inspect.
   * @param now - reference time.
   * @returns `revoked`, `expired`, or `active`.
   */
  classify(device: DeviceRecord, now = Date.now()): DeviceStatus {
    if (device.revokedAt !== undefined) return 'revoked'
    const expiresAt = this.expiryOf(device, now)
    return expiresAt !== undefined && expiresAt <= now ? 'expired' : 'active'
  }

  /**
   * When this device goes stale, or undefined when expiry is disabled.
   *
   * @param device - the record to inspect.
   * @param now - reference time (unused; kept so callers read symmetrically).
   * @returns the timestamp after which the device is expired.
   */
  expiryOf(device: DeviceRecord, now = Date.now()): number | undefined {
    if (this.options.inactivityDays <= 0) return undefined
    void now
    return device.lastSeenAt + this.options.inactivityDays * 86_400_000
  }

  /** Look up a device by id. */
  get(id: string): DeviceRecord | undefined {
    return this.devices.find((device) => device.id === id)
  }

  /**
   * Create a device from a freshly paired session.
   *
   * @param input - device name, the raw token, and an optional caller-chosen id
   *   (the pairing service mints it so the phone and the registry agree).
   * @returns the stored record (without the raw token).
   */
  async create(input: { name: string; token: string; id?: string; pairedFrom?: string; now?: number }): Promise<DeviceRecord> {
    await this.load()
    const now = input.now ?? Date.now()
    const record: DeviceRecord = {
      id: input.id ?? randomUUID(),
      name: sanitiseDeviceName(input.name),
      tokenHash: hashToken(input.token),
      scopes: DEFAULT_SCOPES,
      createdAt: now,
      lastSeenAt: now,
      pairedFrom: input.pairedFrom,
    }
    this.devices.push(record)
    await this.persist()
    return record
  }

  /**
   * Resolve a raw bearer token to a usable device.
   *
   * A device that has gone stale stops authenticating here and now; the record
   * itself is removed by {@link sweep} (or by the next write), so the audit list
   * survives a crash between the two.
   *
   * @param token - raw token from the request.
   * @param now - current time (injected for tests).
   * @returns the matching usable device, or undefined.
   */
  async authenticate(token: string, now = Date.now()): Promise<DeviceRecord | undefined> {
    await this.load()
    const hash = hashToken(token)
    for (let index = 0; index < this.devices.length; index += 1) {
      const device = this.devices[index]
      if (device === undefined) continue
      if (hashEquals(device.tokenHash, hash)) {
        if (this.classify(device, now) !== 'active') {
          // Record only *when* the expiry was first observed; the verdict itself
          // stays computed from `lastSeenAt`, so an idle device that comes back
          // before cleanup still authenticates.
          if (device.revokedAt === undefined && device.expiredAt === undefined) {
            const expired: DeviceRecord = { ...device, expiredAt: now }
            this.devices[index] = expired
            await this.persist()
          }
          return undefined
        }
        // Records are immutable; keep the new timestamp in memory and let the
        // periodic flush write it, so a busy phone does not rewrite the file
        // on every single request. A successful use also clears any earlier
        // expiry stamp — activity makes it stale information.
        const touched: DeviceRecord = { ...device, lastSeenAt: now }
        delete (touched as { expiredAt?: number }).expiredAt
        this.devices[index] = touched
        this.pendingTouches.set(touched.id, now)
        await this.flushTouches(now, false)
        return touched
      }
    }
    return undefined
  }

  /**
   * Write batched `lastSeenAt` updates.
   *
   * @param now - current time.
   * @param force - write even when the flush interval has not elapsed.
   */
  async flushTouches(now = Date.now(), force = true): Promise<void> {
    if (this.pendingTouches.size === 0) return
    if (!force && now - this.lastFlushAt < this.options.touchFlushMs) return
    this.lastFlushAt = now
    this.pendingTouches.clear()
    await this.persist()
  }

  /**
   * Drop records that no longer need keeping and report what is currently dead.
   *
   * `expired` counts every device that is stale *right now* (expiry is computed,
   * so this is a snapshot rather than a delta); `removed` counts records that
   * were both dead and past their retention window. With the default policy this
   * is what keeps a long-lived install from accumulating dead entries after
   * repeated pairing attempts.
   *
   * @param now - current time (injected for tests).
   * @returns the current stale count and how many records were removed.
   */
  async sweep(now = Date.now()): Promise<{ expired: number; removed: number }> {
    await this.load()
    const kept: DeviceRecord[] = []
    let expired = 0
    let removed = 0
    for (const device of this.devices) {
      const status = this.classify(device, now)
      if (status === 'active') {
        kept.push(device)
        continue
      }
      if (status === 'expired') expired += 1
      // A revoked or expired record is kept for the audit list, but not forever.
      if (this.retentionElapsed(device, now)) {
        removed += 1
        continue
      }
      kept.push(device)
    }
    const changed = removed > 0 || kept.length !== this.devices.length || expired > 0
    this.devices = kept
    if (changed) await this.persist()
    return { expired, removed }
  }

  /**
   * Whether a dead record's retention window has elapsed.
   *
   * The anchor is *when the device became dead*, not when it was last used: a
   * device that went stale a whole inactivity window before anyone looked must
   * still get its full retention period on the list. `expiresAt` covers records
   * that were already stale when they were loaded (no observed stamp yet, for
   * example after a restart), and `expiredAt` covers the ones we watched expire.
   */
  private retentionElapsed(device: DeviceRecord, now: number): boolean {
    if (this.options.revokedRetentionDays <= 0) return true
    const deadSince = device.revokedAt ?? device.expiredAt ?? this.expiryOf(device, now) ?? device.lastSeenAt
    return now - deadSince >= this.options.revokedRetentionDays * 86_400_000
  }

  /**
   * Revoke one device.
   *
   * @param id - device id.
   * @param now - current time (injected for tests).
   * @returns the revoked record, or undefined when no such device exists.
   */
  async revoke(id: string, now = Date.now()): Promise<DeviceRecord | undefined> {
    await this.load()
    const device = this.devices.find((entry) => entry.id === id)
    if (device === undefined) return undefined
    if (device.revokedAt === undefined) {
      const revoked: DeviceRecord = { ...device, revokedAt: now }
      this.devices = this.devices.map((entry) => (entry.id === id ? revoked : entry))
      await this.persist()
      return revoked
    }
    return device
  }

  /** Remove every device record (used by tests and by "解绑全部"). */
  async clear(): Promise<void> {
    await this.load()
    this.devices = []
    this.pendingTouches.clear()
    await this.persist()
  }
}

/** Whether a parsed value is a usable device record. */
function isDeviceRecord(value: unknown): value is DeviceRecord {
  if (typeof value !== 'object' || value === null) return false
  const record = value as Record<string, unknown>
  return (
    typeof record.id === 'string' &&
    typeof record.name === 'string' &&
    typeof record.tokenHash === 'string' &&
    typeof record.createdAt === 'number' &&
    typeof record.lastSeenAt === 'number'
  )
}

/** Keep device names short and free of control characters. */
export function sanitiseDeviceName(name: string): string {
  const flat = name
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  if (flat === '') return '未命名设备'
  return flat.slice(0, 40)
}
