/**
 * Process view: only the processes this monitor can *verify* belong to DSH.
 *
 * The monitor deliberately does not enumerate every Windows process, collect
 * memory/CPU of unrelated programs, or upload anything about them. It asks WMI
 * for `node.exe` processes whose command line mentions DSH, and asks the TCP
 * table which addresses those PIDs listen on. Non-DSH processes are dropped.
 * Nothing is ever terminated.
 *
 * @module dsh-pocket-monitor/adapters/dsh/processes
 */

import { execFile } from 'node:child_process'
import type { ProcessInfo } from '../../../../shared/types/index.ts'

/** Result of one process probe. */
export interface ProcessProbeResult {
  readonly processes: readonly ProcessInfo[]
  /** How many `node.exe` processes the machine reported, when visible. */
  readonly nodeProcessCount?: number
  readonly error?: string
}

/** Maximum command-line characters kept after redaction. */
const COMMAND_LINE_LIMIT = 180

/**
 * WMI + TCP query, written without quoting characters so it survives being
 * passed to `pwsh -Command` from Node.
 *
 * `dsh|deepseek|harness` matches the CLI, the profile launcher and the known
 * first-party plugin names. `node.exe` only — no other process is inspected.
 * The `total` field lets the caller tell "no DSH process" apart from "WMI could
 * not see any process at all" (some sandboxed/restricted contexts), so the UI
 * can report the truth instead of a misleading empty list.
 */
const PROBE_SCRIPT = [
  '$ErrorActionPreference = "SilentlyContinue"',
  '$ws = @(Get-CimInstance Win32_Process -Filter "Name = node.exe")',
  '$hits = @($ws | Where-Object { $_.CommandLine -and $_.CommandLine -match "dsh|deepseek|harness" })',
  '$conns = @(Get-NetTCPConnection -State Listen)',
  '$out = foreach ($p in $hits) {',
  '  $listen = @($conns | Where-Object { $_.OwningProcess -eq $p.ProcessId } | ForEach-Object { @{ host = $_.LocalAddress; port = [int]$_.LocalPort } })',
  '  $started = $null',
  '  if ($p.CreationDate) { $started = ([datetime]$p.CreationDate).ToUniversalTime().ToString("o") }',
  '  [pscustomobject]@{ pid = [int]$p.ProcessId; name = [string]$p.Name; startedAt = $started; commandLine = [string]$p.CommandLine; listen = $listen }',
  '}',
  'ConvertTo-Json -InputObject @{ total = $ws.Count; hits = @($out) } -Depth 4 -Compress',
].join('; ')

/** How long a single probe may take before it is abandoned. */
const PROBE_TIMEOUT_MS = 8_000

/**
 * Probes for DSH-related processes, with a short-lived cache so a 1-second poll
 * never spawns a shell per tick.
 */
export class DshProcessProbe {
  private readonly cacheMs: number
  private lastRun = 0
  private last: ProcessProbeResult = { processes: [] }

  constructor(cacheMs = 5_000) {
    this.cacheMs = cacheMs
  }

  /**
   * Return the cached probe result, refreshing it when it has expired.
   *
   * @returns DSH-related processes plus an optional probe error message.
   */
  async probe(force = false): Promise<ProcessProbeResult> {
    const now = Date.now()
    if (!force && now - this.lastRun < this.cacheMs) return this.last
    this.lastRun = now
    this.last = await this.runProbe()
    return this.last
  }

  /** Run the WMI/TCP probe once. */
  private async runProbe(): Promise<ProcessProbeResult> {
    if (process.platform !== 'win32') {
      return { processes: [], error: 'process view 目前只在 Windows 上实现' }
    }
    const raw = await new Promise<string>((resolvePromise, rejectPromise) => {
      execFile(
        'pwsh',
        ['-NoProfile', '-NonInteractive', '-Command', PROBE_SCRIPT],
        { timeout: PROBE_TIMEOUT_MS, windowsHide: true, maxBuffer: 4 << 20 },
        (error, stdout) => {
          if (error !== null) {
            rejectPromise(error)
            return
          }
          resolvePromise(stdout)
        },
      )
    }).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error)
      return `__error__${message}`
    })

    if (raw.startsWith('__error__')) return { processes: [], error: raw.slice('__error__'.length) }
    const trimmed = raw.trim()
    if (trimmed === '' || trimmed === '[]') return { processes: [] }

    let parsed: unknown
    try {
      parsed = JSON.parse(trimmed)
    } catch (error) {
      return { processes: [], error: `无法解析进程探测结果：${error instanceof Error ? error.message : String(error)}` }
    }
    // The probe reports `{ total, hits }`; tolerate a bare array from older shells.
    const envelope = Array.isArray(parsed) ? { total: parsed.length, hits: parsed } : (parsed as { total?: unknown; hits?: unknown })
    const total = typeof envelope.total === 'number' ? envelope.total : Number.NaN
    const rawHits = Array.isArray(envelope.hits) ? envelope.hits : []
    if (total === 0) {
      return {
        processes: [],
        nodeProcessCount: 0,
        error: '当前运行环境看不到任何 node.exe 进程（WMI 被受限上下文挡住）。进程视图在普通用户会话里可以正常工作，这里如实报告为不可用。',
      }
    }
    const list = rawHits
    const processes: ProcessInfo[] = []
    for (const entry of list) {
      if (typeof entry !== 'object' || entry === null) continue
      const record = entry as Record<string, unknown>
      const pid = typeof record.pid === 'number' ? record.pid : Number(record.pid)
      if (!Number.isFinite(pid)) continue
      const commandLine = redactCommandLine(typeof record.commandLine === 'string' ? record.commandLine : '')
      const listen = Array.isArray(record.listen)
        ? record.listen.flatMap((item) => {
            if (typeof item !== 'object' || item === null) return []
            const l = item as Record<string, unknown>
            const host = typeof l.host === 'string' ? l.host : ''
            const port = Number(l.port)
            return host !== '' && Number.isFinite(port) ? [{ host, port }] : []
          })
        : []
      const startedRaw = typeof record.startedAt === 'string' ? Date.parse(record.startedAt) : Number.NaN
      processes.push({
        pid,
        name: typeof record.name === 'string' ? record.name : 'node.exe',
        startedAt: Number.isFinite(startedRaw) ? startedRaw : undefined,
        role: describeRole(commandLine, listen),
        commandLine,
        listen,
      })
    }
    processes.sort((a, b) => a.pid - b.pid)
    return { processes, nodeProcessCount: Number.isFinite(total) ? total : undefined }
  }
}

/**
 * Strip secrets and personal absolute prefixes out of a command line.
 *
 * The monitor never needs a token, key or full profile path to describe a
 * process, so they are removed rather than displayed.
 *
 * @param commandLine - raw WMI command line.
 * @returns a redacted, truncated command line.
 */
export function redactCommandLine(commandLine: string): string {
  return commandLine
    .replace(/(--token|--api-key|--apikey|token=|api[_-]?key=|authorization=)\s*[:=]?\s*\S+/gi, '$1 <redacted>')
    .replace(/(sk-[A-Za-z0-9_-]{8,})/g, '<redacted-key>')
    .replace(/[A-Za-z]:\\Users\\[^\\\s"']+/gi, '%USERPROFILE%')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, COMMAND_LINE_LIMIT)
}

/** Describe what a DSH process is, based on verified command-line/port facts. */
export function describeRole(
  commandLine: string,
  listen: readonly { readonly host: string; readonly port: number }[],
): string {
  const parts: string[] = []
  if (/--profile\s+web|\bweb\b/.test(commandLine)) parts.push('dsh web')
  else if (/--profile\s+(tui|dsh-tui)|\btui\b/.test(commandLine)) parts.push('dsh tui')
  else if (/\bheadless\b/.test(commandLine)) parts.push('dsh headless')
  else parts.push('dsh')
  for (const entry of listen) {
    const scope = entry.host === '127.0.0.1' || entry.host === '::1' ? 'loopback' : entry.host
    parts.push(`监听 ${scope}:${entry.port}`)
  }
  if (listen.length === 0) parts.push('无监听端口')
  return parts.join(' · ')
}
