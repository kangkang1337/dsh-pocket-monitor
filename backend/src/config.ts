/**
 * Runtime configuration for the LAN monitor service.
 *
 * Everything is explicit and file-free by default: no config file is required,
 * nothing is auto-started, and no value is read from DSH credentials.
 *
 * @module dsh-pocket-monitor/config
 */

import { resolve } from 'node:path'
import { resolveDshHome } from './adapters/dsh/sessions.ts'

/** Effective service configuration. */
export interface MonitorConfig {
  /** Bind host. Loopback by default; an explicit LAN address enables phones. */
  readonly host: string
  /** Bind port. 0 lets the OS pick a free one. */
  readonly port: number
  /** Workspace whose DSH sessions are watched. */
  readonly workspace: string
  /** `$DSH_HOME` used to find the session logs. */
  readonly dshHome: string
  /** Session-log poll interval in milliseconds. */
  readonly pollIntervalMs: number
  /** Directory for this project's own state (paired devices). Never inside `$DSH_HOME`. */
  readonly dataDir: string
  /** Pairing window in seconds. */
  readonly pairTtlSeconds: number
  /** Failed pairing attempts allowed per window. */
  readonly pairMaxAttempts: number
  /** Extra authorities allowed in `Host`/`Origin` checks. */
  readonly trustedOrigins: readonly string[]
  /** Turn on the synchronous CLI approval prompt (loopback console). */
  readonly terminalApproval: boolean
  /** Print the access URL and QR block on startup. */
  readonly printQr: boolean
}

/** Parsed command-line input for the service. */
export interface CliOptions {
  readonly host?: string
  readonly port?: number
  readonly workspace?: string
  readonly dshHome?: string
  readonly dataDir?: string
  readonly pollIntervalMs?: number
  readonly pairTtlSeconds?: number
  readonly trustedOrigins?: readonly string[]
  readonly terminalApproval?: boolean
  readonly printQr?: boolean
}

/** Flags that take a value, so the parser can reject a missing one. */
const VALUE_FLAGS = new Set([
  '--host',
  '--port',
  '--workspace',
  '--dsh-home',
  '--data-dir',
  '--poll',
  '--pair-ttl',
  '--trusted-origin',
])

/** Boolean flags. */
const BOOLEAN_FLAGS = new Set(['--no-terminal-approval', '--no-qr'])

/**
 * Parse monitor-specific flags out of `argv`.
 *
 * Unknown arguments are ignored on purpose, so the npm scripts can forward
 * extra flags without breaking startup.
 *
 * @param argv - process arguments after the script name.
 * @returns the recognised options.
 * @throws when a value flag is missing its value or a value is not usable.
 */
export function parseCliOptions(argv: readonly string[]): CliOptions {
  let host: string | undefined
  let port: number | undefined
  let workspace: string | undefined
  let dshHome: string | undefined
  let dataDir: string | undefined
  let pollIntervalMs: number | undefined
  let pairTtlSeconds: number | undefined
  const trustedOrigins: string[] = []
  let terminalApproval: boolean | undefined
  let printQr: boolean | undefined

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i]
    if (!VALUE_FLAGS.has(arg) && !BOOLEAN_FLAGS.has(arg)) continue
    if (BOOLEAN_FLAGS.has(arg)) {
      if (arg === '--no-terminal-approval') terminalApproval = false
      if (arg === '--no-qr') printQr = false
      continue
    }
    const value = argv[i + 1]
    if (value === undefined || value.startsWith('--')) throw new Error(`${arg} 需要一个值`)
    i += 1
    switch (arg) {
      case '--host':
        host = value
        break
      case '--port': {
        const parsed = Number(value)
        if (!Number.isInteger(parsed) || parsed < 0 || parsed > 65535) throw new Error(`--port 必须是 0-65535 的整数，收到 ${value}`)
        port = parsed
        break
      }
      case '--workspace':
        workspace = resolve(value)
        break
      case '--dsh-home':
        dshHome = resolve(value)
        break
      case '--data-dir':
        dataDir = resolve(value)
        break
      case '--poll': {
        const parsed = Number(value)
        if (!Number.isFinite(parsed) || parsed < 200) throw new Error(`--poll 至少 200 毫秒，收到 ${value}`)
        pollIntervalMs = parsed
        break
      }
      case '--pair-ttl': {
        const parsed = Number(value)
        if (!Number.isFinite(parsed) || parsed < 30) throw new Error(`--pair-ttl 至少 30 秒，收到 ${value}`)
        pairTtlSeconds = parsed
        break
      }
      case '--trusted-origin':
        trustedOrigins.push(value)
        break
      default:
        break
    }
  }

  return {
    ...(host === undefined ? {} : { host }),
    ...(port === undefined ? {} : { port }),
    ...(workspace === undefined ? {} : { workspace }),
    ...(dshHome === undefined ? {} : { dshHome }),
    ...(dataDir === undefined ? {} : { dataDir }),
    ...(pollIntervalMs === undefined ? {} : { pollIntervalMs }),
    ...(pairTtlSeconds === undefined ? {} : { pairTtlSeconds }),
    ...(trustedOrigins.length === 0 ? {} : { trustedOrigins }),
    ...(terminalApproval === undefined ? {} : { terminalApproval }),
    ...(printQr === undefined ? {} : { printQr }),
  }
}

/**
 * Resolve the effective configuration from options, environment and defaults.
 *
 * @param options - parsed CLI options.
 * @param env - environment (injected for tests).
 * @param cwd - workspace default.
 * @returns the effective configuration.
 */
export function resolveConfig(
  options: CliOptions = {},
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): MonitorConfig {
  const workspace = options.workspace ?? resolve(env.DSH_POCKET_MONITOR_WORKSPACE ?? cwd)
  const dshHome = options.dshHome ?? resolveDshHome(env)
  const dataDir = options.dataDir ?? resolve(cwd, 'data')
  return {
    host: options.host ?? env.DSH_POCKET_MONITOR_HOST ?? '0.0.0.0',
    port: options.port ?? numberFromEnv(env.DSH_POCKET_MONITOR_PORT, 3099),
    workspace,
    dshHome,
    pollIntervalMs: options.pollIntervalMs ?? numberFromEnv(env.DSH_POCKET_MONITOR_POLL, 1_000),
    dataDir,
    pairTtlSeconds: options.pairTtlSeconds ?? numberFromEnv(env.DSH_POCKET_MONITOR_PAIR_TTL, 300),
    pairMaxAttempts: numberFromEnv(env.DSH_POCKET_MONITOR_PAIR_ATTEMPTS, 8),
    trustedOrigins: options.trustedOrigins ?? [],
    terminalApproval: options.terminalApproval ?? env.DSH_POCKET_MONITOR_TERMINAL_APPROVAL !== '0',
    printQr: options.printQr ?? env.DSH_POCKET_MONITOR_PRINT_QR !== '0',
  }
}

/** Read a positive integer from the environment with a fallback. */
function numberFromEnv(raw: string | undefined, fallback: number): number {
  if (raw === undefined || raw.trim() === '') return fallback
  const parsed = Number(raw)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback
}
