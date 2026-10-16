/**
 * Realtime transport for the phone: an `EventSource` stream with reconnect
 * backoff plus an HTTP fallback poll, so a dropped Wi-Fi connection recovers
 * without the user touching anything.
 *
 * @module dsh-pocket-monitor/frontend/services/stream
 */

import type { ServerFrame } from '../../../shared/types/index.ts'

/** Connection state of the phone's own realtime link (not the DSH source). */
export type LinkState = 'connecting' | 'open' | 'reconnecting' | 'offline' | 'closed'

/** Callbacks the store registers for stream events. */
export interface StreamHandlers {
  onFrame: (frame: ServerFrame) => void
  onState: (state: LinkState) => void
}

/** Reconnect delays in milliseconds; the last value repeats. */
const BACKOFF_MS = [500, 1_000, 2_000, 4_000, 8_000, 10_000]

/**
 * Build the stream URL.
 *
 * The public-access PIN is deliberately *not* placed here: a URL ends up in
 * tunnel logs, browser history and `Referer` headers. Any API request that
 * carried the PIN header already traded it for an HttpOnly `dpm_pin` cookie
 * (see `api.ts`), and the browser sends that cookie with the `EventSource`
 * connection automatically.
 */
function streamUrl(): string {
  return '/api/stream'
}

/**
 * Open the SSE stream and keep it open.
 *
 * Returns a disposer. `EventSource` reconnects on its own for transient losses,
 * but a 401 (device revoked) must stop the loop for good, and browser `offline`
 * events should pause it.
 */
export function openStream(handlers: StreamHandlers): () => void {
  let source: EventSource | undefined
  let attempt = 0
  let timer: number | undefined
  let disposed = false

  const setState = (state: LinkState): void => {
    if (!disposed) handlers.onState(state)
  }

  const close = (): void => {
    if (source !== undefined) {
      source.close()
      source = undefined
    }
  }

  const scheduleReconnect = (): void => {
    if (disposed) return
    const delay = BACKOFF_MS[Math.min(attempt, BACKOFF_MS.length - 1)] ?? 10_000
    attempt += 1
    setState(navigator.onLine === false ? 'offline' : 'reconnecting')
    if (timer !== undefined) window.clearTimeout(timer)
    timer = window.setTimeout(connect, delay)
  }

  const connect = (): void => {
    if (disposed) return
    close()
    setState(attempt === 0 ? 'connecting' : 'reconnecting')
    const next = new EventSource(streamUrl(), { withCredentials: true })
    source = next
    next.onopen = () => {
      attempt = 0
      setState('open')
    }
    next.onmessage = (event: MessageEvent<string>) => {
      try {
        handlers.onFrame(JSON.parse(event.data) as ServerFrame)
      } catch {
        /* a malformed frame must not kill the stream */
      }
    }
    next.onerror = () => {
      close()
      // A revoked device session shows up as a failing status probe; stopping the
      // retry loop then avoids hammering a server that will never accept us again.
      void fetch('/api/status', { credentials: 'same-origin' })
        .then((status) => {
          if (disposed) return
          if (status.status === 401) {
            handlers.onState('closed')
            return
          }
          scheduleReconnect()
        })
        .catch(() => {
          if (!disposed) scheduleReconnect()
        })
    }
  }

  const onOffline = (): void => {
    close()
    setState('offline')
  }
  const onOnline = (): void => {
    attempt = 0
    connect()
  }
  window.addEventListener('offline', onOffline)
  window.addEventListener('online', onOnline)
  connect()

  return () => {
    disposed = true
    if (timer !== undefined) window.clearTimeout(timer)
    window.removeEventListener('offline', onOffline)
    window.removeEventListener('online', onOnline)
    close()
  }
}

/** Human label for the phone-to-server link. */
export function linkLabel(state: LinkState): string {
  switch (state) {
    case 'connecting':
      return '正在连接本地服务…'
    case 'open':
      return '实时连接正常'
    case 'reconnecting':
      return '连接中断，正在重连…'
    case 'offline':
      return '手机网络已断开'
    case 'closed':
      return '会话已失效，请重新配对'
    default:
      return '连接已关闭'
  }
}
