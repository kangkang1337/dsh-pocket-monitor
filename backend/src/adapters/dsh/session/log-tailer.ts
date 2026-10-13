/**
 * Incremental reader for one DSH session log artifact.
 *
 * The log is an append-only concatenation of Zstandard frames, so a monitor can
 * tail it the way DSH itself appends: remember the byte offset where the last
 * complete frame ended, read only the bytes after it, structurally scan for
 * complete frames, and carry an incomplete tail over to the next pass. Nothing
 * is ever written back to the artifact.
 *
 * @module dsh-pocket-monitor/adapters/dsh/session/log-tailer
 */

import { open, stat } from 'node:fs/promises'
import type { FileHandle } from 'node:fs/promises'
import { decodeFrameLines, scanZstdFrames, type ZstdFrameRange } from './zstd-frames.ts'
import {
  createFoldState,
  foldEvent,
  isSessionHeader,
  parseSessionRow,
  type DshSessionEvent,
  type SessionFoldState,
} from './session-model.ts'

/** One incremental read result. */
export interface TailResult {
  readonly changed: boolean
  readonly newEvents: readonly DshSessionEvent[]
  /** True when the artifact was replaced/truncated and state was rebuilt from scratch. */
  readonly restarted: boolean
  /** Set when the artifact is currently unreadable. */
  readonly error?: string
}

/** Bytes read from the artifact per pass. */
const READ_CHUNK_BYTES = 1 << 20

/**
 * Tails one session artifact and folds its events into monitor state.
 *
 * The instance owns the fold state, so callers see a stable
 * {@link SessionFoldState} across passes. Frame boundaries are tracked by an
 * absolute `framedFrom` offset with the undecoded remainder kept in
 * {@link pending}, which keeps torn batches (a partially flushed append) safe to
 * retry on the next pass.
 */
export class SessionLogTailer {
  readonly path: string
  /** Bytes read per pass; smaller values are used by tests to force chunking. */
  private readonly readChunkBytes: number
  private size = -1
  private mtimeMs = 0
  private framedFrom = 0
  private pending = Buffer.alloc(0)
  private fold: SessionFoldState | undefined
  private lastError: string | undefined
  /** Clean prefix found before a damaged frame, reused until the file changes. */
  private stalePrefix: DshSessionEvent[] = []
  /** Whether the corruption at the current size was already delivered. */
  private corruptionDelivered = false

  constructor(path: string, readChunkBytes = READ_CHUNK_BYTES) {
    this.path = path
    this.readChunkBytes = Math.max(64, Math.trunc(readChunkBytes))
  }

  /** Folded state, available once a header has been decoded. */
  get state(): SessionFoldState | undefined {
    return this.fold
  }

  /** Current unreadable reason, if the last pass failed. */
  get error(): string | undefined {
    return this.lastError
  }

  /** Artifact size in bytes as of the last pass. */
  get byteSize(): number {
    return this.size < 0 ? 0 : this.size
  }

  /** Last modification time (epoch ms) as of the last pass. */
  get modifiedAt(): number {
    return this.mtimeMs
  }

  /** Absolute offset of the first byte that is not yet decoded. */
  get decodedBytes(): number {
    return this.framedFrom
  }

  /**
   * Read whatever was appended since the previous pass.
   *
   * @returns newly decoded events plus whether the artifact changed at all.
   */
  async update(): Promise<TailResult> {
    let stats
    try {
      stats = await stat(this.path)
    } catch (error) {
      this.lastError = describeError(error)
      return { changed: false, newEvents: [], restarted: false, error: this.lastError }
    }

    const previousSize = this.size
    const shrank = previousSize >= 0 && stats.size < previousSize
    const replaced = shrank || stats.size < this.framedFrom
    this.mtimeMs = stats.mtimeMs
    if (previousSize >= 0 && stats.size !== previousSize) {
      // The artifact grew (or changed): its tail may be readable again.
      this.corruptionDelivered = false
    }
    this.size = stats.size
    const restarted = replaced || previousSize < 0
    if (replaced) this.resetState()

    const noNewBytes = stats.size === this.framedFrom + this.pending.length
    if (noNewBytes && this.fold !== undefined) {
      // A damaged artifact keeps reporting the same error, and its validated
      // prefix is delivered exactly once instead of being duplicated per poll.
      const prefix = this.corruptionDelivered ? [] : this.stalePrefix
      this.corruptionDelivered = true
      return { changed: false, newEvents: prefix, restarted: false, error: this.lastError }
    }

    const newEvents: DshSessionEvent[] = []
    let handle: FileHandle | undefined
    try {
      handle = await open(this.path, 'r')
      while (this.framedFrom + this.pending.length < stats.size) {
        const want = Math.min(this.readChunkBytes, stats.size - (this.framedFrom + this.pending.length))
        const buffer = Buffer.alloc(want)
        const { bytesRead } = await handle.read(buffer, 0, want, this.framedFrom + this.pending.length)
        if (bytesRead === 0) break
        this.pending = this.pending.length === 0 ? Buffer.from(buffer.subarray(0, bytesRead)) : Buffer.concat([this.pending, buffer.subarray(0, bytesRead)])

        let scan
        try {
          scan = scanZstdFrames(this.pending)
        } catch (error) {
          // A damaged frame is a hard error, but every frame that scanned cleanly
          // before it is still validated data: deliver it, then report.
          const partial = partialFrames(error)
          const delivered: DshSessionEvent[] = []
          if (partial.length > 0) {
            try {
              this.consumeFrames(partial, delivered)
            } catch (decodeError) {
              this.lastError = describeError(decodeError)
              this.stalePrefix = []
              return { changed: true, newEvents: [...newEvents, ...delivered], restarted, error: this.lastError }
            }
          }
          this.stalePrefix = delivered
          this.corruptionDelivered = true
          this.lastError = describeError(error)
          return { changed: true, newEvents: [...newEvents, ...delivered], restarted, error: this.lastError }
        }

        if (scan.frames.length > 0) {
          try {
            this.consumeFrames(scan.frames, newEvents)
          } catch (error) {
            this.lastError = describeError(error)
            return { changed: true, newEvents, restarted, error: this.lastError }
          }
          continue
        }
        // Nothing complete yet. If everything left is already buffered, it is a
        // torn (still being written) tail: stop and carry it over. Otherwise we
        // are mid-frame, so read the next chunk and try again.
        if (this.framedFrom + this.pending.length >= stats.size) break
      }
      this.lastError = undefined
      return { changed: true, newEvents, restarted }
    } catch (error) {
      this.lastError = describeError(error)
      return { changed: false, newEvents: [], restarted: false, error: this.lastError }
    } finally {
      await handle?.close()
    }
  }

  /** Decode the given complete frames, fold them, and advance the frame cursor. */
  private consumeFrames(frames: readonly ZstdFrameRange[], sink: DshSessionEvent[]): void {
    let consumed = 0
    for (const range of frames) {
      const lines = decodeFrameLines(this.pending, range)
      this.consumeLines(lines, sink)
      consumed = range.end
    }
    if (consumed === 0) return
    this.framedFrom += consumed
    this.pending = consumed >= this.pending.length ? Buffer.alloc(0) : Buffer.from(this.pending.subarray(consumed))
  }

  /** Drop all derived state so the next pass rebuilds from byte 0. */
  private resetState(): void {
    this.framedFrom = 0
    this.pending = Buffer.alloc(0)
    this.fold = undefined
    this.stalePrefix = []
    this.corruptionDelivered = false
    this.lastError = undefined
  }

  /** Parse decoded JSONL lines and fold them into state. */
  private consumeLines(lines: readonly string[], sink: DshSessionEvent[]): void {
    for (const line of lines) {
      const row = parseSessionRow(line)
      if (row === undefined) continue
      if (isSessionHeader(row)) {
        this.fold = createFoldState(row)
        continue
      }
      if (this.fold === undefined) {
        this.fold = createFoldState({ type: 'session', version: 0, id: 'unknown', createdAt: row.time })
      }
      foldEvent(this.fold, row)
      sink.push(row)
    }
  }
}

/** Render an unknown thrown value as a short message. */
function describeError(error: unknown): string {
  if (error instanceof Error) return error.message
  return String(error)
}

/**
 * Read the already-scanned frames a structural scan error carries.
 *
 * The scanner rejects a corrupt frame, but the frames it validated before that
 * point are real data; this lets the tailer deliver them before reporting.
 *
 * @param error - the thrown scan error.
 * @returns the validated prefix, or an empty array when none was attached.
 */
function partialFrames(error: unknown): readonly ZstdFrameRange[] {
  if (typeof error !== 'object' || error === null) return []
  const candidate = (error as { frames?: unknown }).frames
  return Array.isArray(candidate) ? (candidate as ZstdFrameRange[]) : []
}
