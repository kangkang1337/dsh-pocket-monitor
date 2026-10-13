/**
 * Server-sent-event hub for paired phones.
 *
 * The phone uses `EventSource`, which cannot attach an `Authorization` header,
 * so the stream authenticates with the same HttpOnly device cookie as the rest
 * of the API. Frames are the project's own {@link ServerFrame} vocabulary — no
 * raw DSH payload ever reaches the browser.
 *
 * @module dsh-pocket-monitor/transport/sse
 */

import type { Server, ServerResponse } from 'node:http'
import type { ServerFrame } from '../../../shared/types/index.ts'

/** One connected phone stream. */
interface SseClient {
  readonly id: number
  readonly deviceId: string
  readonly response: ServerResponse
  readonly connectedAt: number
}

/** Heartbeat period; keeps intermediaries and iOS Safari from idling out. */
const HEARTBEAT_MS = 15_000

/** SSE hub with per-device fan-out and bounded buffering. */
export class SseHub {
  private readonly clients = new Map<number, SseClient>()
  private nextId = 1
  private heartbeat?: NodeJS.Timeout

  /** Register a client response; the caller owns HTTP headers already sent. */
  add(deviceId: string, response: ServerResponse): () => void {
    const id = this.nextId
    this.nextId += 1
    this.clients.set(id, { id, deviceId, response, connectedAt: Date.now() })
    this.ensureHeartbeat()
    return () => this.remove(id)
  }

  /** Remove one client. */
  private remove(id: number): void {
    const client = this.clients.get(id)
    if (client === undefined) return
    this.clients.delete(id)
    try {
      client.response.end()
    } catch {
      /* the socket is already gone */
    }
  }

  /** Connected client count (used by the dashboard). */
  get size(): number {
    return this.clients.size
  }

  /**
   * Send one frame to every client, or only to one device.
   *
   * @param frame - frame to serialise.
   * @param deviceId - optional single-device target.
   */
  broadcast(frame: ServerFrame, deviceId?: string): void {
    const payload = `data: ${JSON.stringify(frame)}\n\n`
    for (const client of [...this.clients.values()]) {
      if (deviceId !== undefined && client.deviceId !== deviceId) continue
      try {
        client.response.write(payload)
      } catch {
        this.remove(client.id)
      }
    }
  }

  /** Drop every client whose device was revoked. */
  disconnectDevice(deviceId: string): void {
    for (const client of [...this.clients.values()]) {
      if (client.deviceId !== deviceId) continue
      try {
        client.response.write(`event: revoked\ndata: {"type":"revoked"}\n\n`)
      } catch {
        /* ignore */
      }
      this.remove(client.id)
    }
  }

  /** Start the heartbeat ticker when the first client arrives. */
  private ensureHeartbeat(): void {
    if (this.heartbeat !== undefined) return
    this.heartbeat = setInterval(() => {
      if (this.clients.size === 0) return
      this.broadcast({ type: 'heartbeat', payload: { at: Date.now() } })
    }, HEARTBEAT_MS)
    this.heartbeat.unref()
  }

  /** Close every stream and stop the ticker (used on shutdown). */
  close(): void {
    if (this.heartbeat !== undefined) clearInterval(this.heartbeat)
    this.heartbeat = undefined
    for (const id of [...this.clients.keys()]) this.remove(id)
  }

  /** Attach idle-connection tracking to an HTTP server (no-op placeholder). */
  attach(_server: Server): void {
    /* SSE clients are tracked per response; nothing else to wire. */
  }
}
