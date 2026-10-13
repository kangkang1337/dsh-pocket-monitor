/**
 * Shared test helpers: synthetic DSH session logs and a fake data source.
 *
 * Session logs are written exactly the way DSH writes them — one checksummed
 * Zstandard frame per durable append batch — so the decoder is exercised by the
 * same physical shape it meets in production.
 *
 * @module dsh-pocket-monitor/tests/helpers
 */

import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { zstdCompressSync, constants } from 'node:zlib'
import type { DshSessionSource } from '../src/adapters/dsh/sessions.ts'
import { projectKey } from '../src/adapters/dsh/sessions.ts'
import type { DshSessionEvent } from '../src/adapters/dsh/session/session-model.ts'
import type { MonitorEvent, StatusPayload } from '../../shared/types/index.ts'

/** Options for {@link buildSessionLog}. */
export interface SessionLogSpec {
  readonly id: string
  readonly cwd: string
  readonly createdAt?: number
  readonly events: ReadonlyArray<{ type: string; seq: number; time: number; data: unknown }>
  /** Append the events as one frame each (DSH's real batching) or all in one. */
  readonly frames?: 'per-event' | 'single'
}

/** Raw event row builder. */
export function event(type: string, seq: number, time: number, data: unknown): { type: string; seq: number; time: number; data: unknown } {
  return { type, seq, time, data }
}

/** Encode one JSONL batch as one checksummed Zstandard frame. */
export function frame(lines: readonly string[]): Buffer {
  return zstdCompressSync(Buffer.from(`${lines.join('\n')}\n`, 'utf8'), {
    params: { [constants.ZSTD_c_checksumFlag]: 1 },
  })
}

/**
 * Compose a DSH session artifact in memory.
 *
 * @param spec - header plus events.
 * @returns the artifact bytes as DSH would have written them.
 */
export function buildSessionLog(spec: SessionLogSpec): Buffer {
  const header = {
    type: 'session',
    version: 4,
    id: spec.id,
    createdAt: spec.createdAt ?? spec.events[0]?.time ?? Date.now(),
    cwd: spec.cwd,
    isSeeded: false,
    delegationDepth: 0,
    agentPreset: 'standard',
  }
  const frames: Buffer[] = [frame([JSON.stringify(header)])]
  if (spec.frames === 'single') {
    frames.push(frame(spec.events.map((entry) => JSON.stringify(entry))))
  } else {
    for (const entry of spec.events) frames.push(frame([JSON.stringify(entry)]))
  }
  return Buffer.concat(frames)
}

/**
 * Write one session artifact into a DSH-home-like sessions tree.
 *
 * @param root - the `sessions` root.
 * @param spec - session to write.
 * @returns the artifact path.
 */
export async function writeSessionLog(root: string, spec: SessionLogSpec): Promise<string> {
  const projectDir = join(root, projectKey(spec.cwd))
  const sessionDir = join(projectDir, spec.id)
  await mkdir(sessionDir, { recursive: true })
  const path = join(sessionDir, 'session.v4.jsonl.zstd')
  await writeFile(path, buildSessionLog(spec))
  return path
}

/** Create a temporary directory that the caller should remove. */
export async function tempDir(prefix: string): Promise<string> {
  return await mkdtemp(join(tmpdir(), prefix))
}

/**
 * A minimal in-memory stand-in for {@link DshSessionSource}.
 *
 * The HTTP surface only consumes these methods, so tests can drive the API with
 * deterministic data instead of relying on whatever the machine happens to have
 * in its session logs.
 */
export class FakeSource {
  payload: StatusPayload
  timelines = new Map<string, readonly MonitorEvent[]>()

  constructor(payload: StatusPayload) {
    this.payload = payload
  }

  /** Replace the payload the next snapshot will return. */
  setPayload(payload: StatusPayload): void {
    this.payload = payload
  }

  /** Set the timeline for one session. */
  setTimeline(sessionId: string, events: readonly MonitorEvent[]): void {
    this.timelines.set(sessionId, events)
  }

  async snapshot(): Promise<{ payload: StatusPayload; sessions: Map<string, unknown>; currentSessionId?: string }> {
    return {
      payload: this.payload,
      sessions: new Map(),
      currentSessionId: this.payload.currentSessionId,
    }
  }

  timelineFor(sessionId: string, limit = 120): readonly MonitorEvent[] {
    return (this.timelines.get(sessionId) ?? []).slice(-limit)
  }

  get watchedSessionIds(): readonly string[] {
    return this.payload.sessions.map((session) => session.sessionId)
  }

  rawEvents(_sessionId: string): readonly DshSessionEvent[] {
    return []
  }
}

/** Cast a fake source to the real adapter type for the service constructor. */
export function asSource(fake: FakeSource): DshSessionSource {
  return fake as unknown as DshSessionSource
}
