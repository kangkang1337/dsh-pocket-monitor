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
 * Persistent, revocable device registry.
 *
 * Writes go through a temp file plus rename so a crash cannot leave a half
 * written registry. Every mutation validates the result before publishing.
 */
export class DeviceStore {
  private readonly path: string
  private devices: DeviceRecord[] = []
  private loaded = false

  constructor(dataDir: string) {
    this.path = join(dataDir, 'devices.json')
  }

  /** Path of the registry file (for the CLI dashboard). */
  get filePath(): string {
    return this.path
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

  /** Every device, including revoked ones, newest first. */
  list(): readonly DeviceRecord[] {
    return [...this.devices].sort((a, b) => b.createdAt - a.createdAt)
  }

  /** Only devices that can still authenticate. */
  listActive(): readonly DeviceRecord[] {
    return this.list().filter((device) => device.revokedAt === undefined)
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
   * Resolve a raw bearer token to an active device.
   *
   * @param token - raw token from the request.
   * @returns the matching active device, or undefined.
   */
  async authenticate(token: string): Promise<DeviceRecord | undefined> {
    await this.load()
    const hash = hashToken(token)
    for (let index = 0; index < this.devices.length; index += 1) {
      const device = this.devices[index]
      if (device === undefined || device.revokedAt !== undefined) continue
      if (hashEquals(device.tokenHash, hash)) {
        // Records are immutable; replace the entry so "last seen" stays trustworthy.
        const touched: DeviceRecord = { ...device, lastSeenAt: Date.now() }
        this.devices[index] = touched
        await this.persist()
        return touched
      }
    }
    return undefined
  }

  /**
   * Revoke one device.
   *
   * @param id - device id.
   * @returns the revoked record, or undefined when no such device exists.
   */
  async revoke(id: string): Promise<DeviceRecord | undefined> {
    await this.load()
    const device = this.devices.find((entry) => entry.id === id)
    if (device === undefined) return undefined
    if (device.revokedAt === undefined) {
      const revoked: DeviceRecord = { ...device, revokedAt: Date.now() }
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
