/**
 * Zstandard frame primitives for DSH session logs.
 *
 * The DSH JSONL persistence backend stores one session artifact as a
 * concatenation of independently decodable, checksummed Zstandard frames: the
 * first frame holds the header line, every later frame holds one durable
 * append batch. Frame boundaries must be found by *structural* scanning —
 * `zstdDecompressSync` silently returns partial output for a truncated frame,
 * so a try/catch probe cannot tell a complete frame from a torn one.
 *
 * The scanner below is a verbatim port of the released DSH algorithm
 * (`@deepseek-ai/dsh-session-persistence-jsonl`, lib/index.js `scanZstdFrames`)
 * so this project decodes exactly what DSH writes, including crash-torn tails.
 *
 * @module dsh-pocket-monitor/adapters/dsh/session/zstd-frames
 */

import { zstdDecompressSync } from 'node:zlib'

/** Little-endian uint32 of the Zstandard frame magic `28 B5 2F FD`. */
const ZSTD_MAGIC = 4247762216

/** One structurally complete frame, as a half-open byte range. */
export interface ZstdFrameRange {
  readonly start: number
  readonly end: number
}

/** Result of a structural frame scan over an available byte range. */
export interface ZstdFrameScan {
  /** Every complete frame found, in file order. */
  readonly frames: readonly ZstdFrameRange[]
  /** Offset where an incomplete final frame begins, when the tail is torn. */
  readonly tornStart?: number
}

/**
 * Locate complete frames without decompressing their blocks.
 *
 * Invalid complete structure rejects (the artifact is corrupt); EOF inside the
 * final frame returns its start so the caller can wait for more bytes. A
 * rejection carries the frames validated before the damage on `error.frames`,
 * so a reader can still deliver clean data while reporting the corruption.
 *
 * @param buffer - complete bytes currently present in the session artifact.
 * @param maxFrames - optional cap on complete frames to scan.
 * @returns complete frame ranges plus an optional torn-final-frame start.
 */
export function scanZstdFrames(buffer: Buffer, maxFrames = Number.POSITIVE_INFINITY): ZstdFrameScan {
  const frames: ZstdFrameRange[] = []
  let offset = 0
  /** Throw a structural error, attaching the frames already validated. */
  const fail = (message: string): never => {
    const error = new Error(message) as Error & { frames: ZstdFrameRange[] }
    error.frames = frames
    throw error
  }
  while (offset < buffer.length) {
    const start = offset
    if (buffer.length - offset < 4) return { frames, tornStart: start }
    if (buffer.readUInt32LE(offset) !== ZSTD_MAGIC) fail(`invalid frame magic at byte ${offset}`)
    offset += 4
    if (offset === buffer.length) return { frames, tornStart: start }
    const descriptor = buffer.readUInt8(offset)
    offset += 1
    if ((descriptor & 24) !== 0) fail(`reserved frame-header bit at byte ${offset - 1}`)
    const contentSizeFlag = descriptor >>> 6
    const singleSegment = (descriptor & 32) !== 0
    const checksum = (descriptor & 4) !== 0
    const dictionaryFlag = descriptor & 3
    const dictionaryBytes = dictionaryFlag === 3 ? 4 : dictionaryFlag
    const contentSizeBytes = contentSizeFlag === 0 ? (singleSegment ? 1 : 0) : 1 << contentSizeFlag
    const remainingHeaderBytes = (singleSegment ? 0 : 1) + dictionaryBytes + contentSizeBytes
    if (buffer.length - offset < remainingHeaderBytes) return { frames, tornStart: start }
    offset += remainingHeaderBytes
    for (;;) {
      if (buffer.length - offset < 3) return { frames, tornStart: start }
      const blockHeader = buffer.readUIntLE(offset, 3)
      offset += 3
      const lastBlock = (blockHeader & 1) !== 0
      const blockType = (blockHeader >>> 1) & 3
      const blockSize = blockHeader >>> 3
      if (blockType === 3) fail(`reserved block type at byte ${offset - 3}`)
      const payloadBytes = blockType === 1 ? 1 : blockSize
      if (buffer.length - offset < payloadBytes) return { frames, tornStart: start }
      offset += payloadBytes
      if (lastBlock) break
    }
    if (checksum) {
      if (buffer.length - offset < 4) return { frames, tornStart: start }
      offset += 4
    }
    frames.push({ start, end: offset })
    if (frames.length === maxFrames) return { frames }
  }
  return { frames }
}

/**
 * Decompress one structurally complete frame and split it into JSONL lines.
 *
 * @param buffer - whole artifact bytes.
 * @param frame - half-open range of one complete frame.
 * @returns decoded non-empty lines, in order.
 */
export function decodeFrameLines(buffer: Buffer, frame: ZstdFrameRange): string[] {
  const text = zstdDecompressSync(buffer.subarray(frame.start, frame.end)).toString('utf8')
  const lines: string[] = []
  for (const line of text.split('\n')) if (line.trim() !== '') lines.push(line)
  return lines
}
