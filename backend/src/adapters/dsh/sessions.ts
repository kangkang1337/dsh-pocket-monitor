/**
 * DSH session-log adapter: the monitor's only DSH data source.
 *
 * It reads `$DSH_HOME/sessions/**` read-only, decodes each session artifact
 * incrementally, and projects the confirmed facts into the monitor's own model.
 * Nothing in this module writes to the DSH home, and no DSH credential is read.
 *
 * Verified facts this module depends on are documented in docs/dsh-integration.md.
 *
 * @module dsh-pocket-monitor/adapters/dsh/sessions
 */

import { readdir, stat } from 'node:fs/promises'
import { homedir } from 'node:os'
import { join, resolve } from 'node:path'
import type {
  Capabilities,
  ConnectionStatus,
  DecidedApproval,
  MonitorEvent,
  PendingApproval,
  SessionView,
  SourceHealth,
  StatusPayload,
} from '../../../../shared/types/index.ts'
import { SessionLogTailer } from './session/log-tailer.ts'
import { projectSession, type DshSessionEvent, type SessionFoldState } from './session/session-model.ts'
import { DshProcessProbe, type ProcessProbeResult } from './processes.ts'

/** Live window for a session's log to count as "still being written". */
const LIVE_WINDOW_MS = 8_000
/** How many recently decided approvals to keep for display. */
const DECIDED_WINDOW = 20

/** Configuration for the session-log adapter. */
export interface DshSourceConfig {
  /** `$DSH_HOME`; defaults to `<home>/.dsh`. */
  readonly dshHome: string
  /** Workspace whose project directory is watched (ignored when `watchAll`). */
  readonly workspace: string
  /** Poll interval in milliseconds. */
  readonly pollIntervalMs: number
  /**
   * Watch every project under the sessions root instead of one workspace, so a
   * TUI session in one directory and a web session in another show up together.
   */
  readonly watchAll?: boolean
  /** Upper bound on watched sessions in watch-all mode (default 30). */
  readonly maxSessions?: number
}

/** One watched session: its artifact path and incremental reader. */
interface WatchedSession {
  readonly sessionId: string
  readonly path: string
  /** Workspace recorded in the session header (what the phone groups by). */
  readonly workspace: string
  readonly formatVersion: number
  readonly newerGenerations: readonly string[]
  readonly tailer: SessionLogTailer
  /** Last artifact modification time, read through to the tailer. */
  readonly modifiedAt: number
}

/** A discovered session artifact before it is watched. */
interface DiscoveredSession {
  readonly sessionId: string
  readonly path: string
  readonly workspace: string
  readonly version: number
  readonly newer: readonly string[]
  /** Artifact mtime, used only to rank candidates in watch-all mode. */
  readonly modifiedAt: number
}

/** How long a discovery result is trusted before the sessions root is rescanned. */
const DISCOVERY_TTL_MS = 3_000
/** Default cap on watched sessions in watch-all mode. */
const DEFAULT_MAX_SESSIONS = 30

/** One session's projected snapshot. */
export interface SessionSnapshot {
  readonly state: SessionFoldState
  readonly timeline: readonly MonitorEvent[]
  readonly pending: readonly PendingApproval[]
  readonly decided: readonly DecidedApproval[]
  readonly formatVersion: number
  readonly newerGenerations: readonly string[]
  readonly artifactPath: string
}

/** A status snapshot plus the raw timing facts behind it. */
export interface AdapterSnapshot {
  readonly payload: StatusPayload
  readonly sessions: ReadonlyMap<string, SessionSnapshot>
  readonly currentSessionId?: string
}

/**
 * Encode a project path into DSH's readable project directory key.
 *
 * Ported from `@deepseek-ai/dsh-session-persistence-jsonl` (`projectKey`): `/`,
 * `\` and `:` collapse to a single `-`, `[A-Za-z0-9._-]` pass through, every
 * other code unit becomes `~XXXX`, leading dashes are dropped, the result is
 * capped at 251 characters, and the whole key is wrapped in `--`.
 *
 * @param cwd - absolute project path as DSH would record it.
 * @returns the project directory name used under the sessions root.
 */
export function projectKey(cwd: string): string {
  if (cwd.length === 0) throw new Error('cannot encode an empty project path')
  let readable = ''
  let separatorRun = false
  for (let i = 0; i < cwd.length; i += 1) {
    const code = cwd.charCodeAt(i)
    const ch = String.fromCharCode(code)
    if (ch === '/' || ch === '\\' || ch === ':') {
      if (!separatorRun) readable += '-'
      separatorRun = true
    } else if (ch !== '~' && /^[A-Za-z0-9._-]$/.test(ch)) {
      readable += ch
      separatorRun = false
    } else {
      readable += `~${code.toString(16).toUpperCase().padStart(4, '0')}`
      separatorRun = false
    }
  }
  return `--${(readable.replace(/^-+/, '') || 'root').slice(0, 251)}--`
}

/** Resolve the DSH home directory the way the CLI does. */
export function resolveDshHome(env: NodeJS.ProcessEnv = process.env): string {
  const configured = env.DSH_HOME?.trim()
  if (configured !== undefined && configured !== '') return resolve(configured)
  return join(homedir(), '.dsh')
}

/** Normalise a path for comparison (Windows is case-insensitive). */
export function normalisePath(path: string): string {
  const trimmed = path.replace(/[\\/]+$/, '')
  return process.platform === 'win32' ? trimmed.toLowerCase() : trimmed
}

/** Match `session.vN.jsonl.zstd`; group 1 is the version (absent for v0). */
const SESSION_FILE_PATTERN = /^session(?:\.v(\d+))?\.jsonl\.zstd$/

/** Rank session artifacts by format version, highest first. */
function rankSessionFiles(names: readonly string[]): Array<{ name: string; version: number }> {
  const ranked: Array<{ name: string; version: number }> = []
  for (const name of names) {
    const match = SESSION_FILE_PATTERN.exec(name)
    if (match === null) continue
    ranked.push({ name, version: match[1] === undefined ? 0 : Number(match[1]) })
  }
  ranked.sort((a, b) => b.version - a.version)
  return ranked
}

/**
 * Whether a project directory key literally encodes this workspace.
 *
 * Deliberately permissive: it only rejects directories whose key disagrees with
 * the workspace's own key prefix, which is enough to skip unrelated projects
 * without re-reading every header. The recorded `cwd` remains the real test.
 *
 * @param projectDir - absolute project directory under the sessions root.
 * @param wantedCwd - normalised workspace path.
 * @returns true when the directory is worth inspecting.
 */
function projectKeyMatches(projectDir: string, wantedCwd: string): boolean {
  const key = projectDir.replace(/[\\/]+$/, '').split(/[\\/]/).pop() ?? ''
  let expected: string
  try {
    expected = projectKey(wantedCwd)
  } catch {
    return true
  }
  // Both keys are `--<slug>--`; compare the slug prefix so a case difference or a
  // trailing segment does not hide a legitimate match.
  const strip = (value: string): string => value.replace(/^-+|-+$/g, '').toLowerCase()
  const left = strip(key)
  const right = strip(expected)
  if (left === right) return true
  const shorter = left.length < right.length ? left : right
  return shorter.length >= 3 && (left.startsWith(right) || right.startsWith(left))
}

/**
 * Watch DSH session logs and expose confirmable facts.
 *
 * Without `watchAll` it follows one workspace; with it, every project under the
 * sessions root, each session tagged with the workspace from its own header.
 *
 * The adapter never claims more than it can prove: a session's state comes from
 * turn/step/tool/approval events, and "connected" means "this artifact is
 * readable and being appended to right now".
 */
export class DshSessionSource {
  readonly config: DshSourceConfig
  readonly sessionsRoot: string
  private readonly watchers = new Map<string, WatchedSession>()
  private readonly processes: DshProcessProbe
  private lastScanAt = 0
  private lastError: string | undefined
  private lastStatus: ConnectionStatus = 'source-missing'
  private statusMessage = '尚未扫描'
  private projectDir: string | undefined
  private projectDirExists = false
  /** Cached discovery result, invalidated when the sessions root changes. */
  private discoveryCache: { readonly at: number; readonly rootMtime: number; readonly sessions: readonly DiscoveredSession[] } | undefined
  /** Human note about watch-all truncation, surfaced in the status message. */
  private truncationNote: string | undefined

  constructor(config: DshSourceConfig, processes = new DshProcessProbe()) {
    this.config = config
    this.sessionsRoot = join(config.dshHome, 'sessions')
    this.processes = processes
  }

  /** Whether every project under the sessions root is watched. */
  get watchingAll(): boolean {
    return this.config.watchAll === true
  }

  /** Upper bound on watched sessions. */
  get maxSessions(): number {
    return this.config.maxSessions ?? DEFAULT_MAX_SESSIONS
  }

  /** Absolute path of the project directory this workspace maps to. */
  get projectDirectory(): string | undefined {
    return this.projectDir
  }

  /** Refresh every watched artifact. Call this on the poll interval. */
  async refresh(): Promise<void> {
    this.lastScanAt = Date.now()
    this.projectDir = this.watchingAll ? undefined : join(this.sessionsRoot, projectKey(this.config.workspace))
    const discovered = await this.discoverSessions()
    this.projectDirExists =
      discovered.length > 0 ||
      (this.projectDir !== undefined && (await this.isDirectory(this.projectDir)))
    const sessions = await this.selectSessions(discovered)
    const seen = new Set<string>()

    for (const artifact of sessions) {
      seen.add(artifact.sessionId)
      let watcher = this.watchers.get(artifact.sessionId)
      if (watcher === undefined || watcher.path !== artifact.path) {
        const tailer = new SessionLogTailer(artifact.path)
        watcher = {
          sessionId: artifact.sessionId,
          path: artifact.path,
          workspace: artifact.workspace,
          formatVersion: artifact.version,
          newerGenerations: artifact.newer,
          tailer,
          get modifiedAt() {
            return tailer.modifiedAt
          },
        }
        this.watchers.set(artifact.sessionId, watcher)
      }
      const result = await watcher.tailer.update()
      if (result.error !== undefined) this.lastError = result.error
    }

    for (const id of [...this.watchers.keys()]) if (!seen.has(id)) this.watchers.delete(id)

    this.updateStatus()
  }

  /**
   * Decide which discovered sessions to watch.
   *
   * Without `watchAll` this is "everything in the chosen workspace". With it, the
   * cap keeps a long-lived DSH home from making the poll unbounded: the most
   * recently written sessions win, and the truncation is stated rather than
   * silently dropping sessions.
   */
  private async selectSessions(discovered: readonly DiscoveredSession[]): Promise<readonly DiscoveredSession[]> {
    const cap = this.maxSessions
    if (discovered.length <= cap) {
      this.truncationNote = undefined
      return discovered
    }
    const ranked = [...discovered].sort((a, b) => b.modifiedAt - a.modifiedAt)
    const kept = ranked.slice(0, cap)
    this.truncationNote = `共发现 ${discovered.length} 个会话，只跟踪最近活跃的 ${cap} 个（可用 --max-sessions 调整）。`
    return kept
  }

  /** Compute the connection status from the last refresh. */
  private updateStatus(): void {
    const watchers = [...this.watchers.values()]
    const now = Date.now()
    if (this.lastError !== undefined && watchers.length === 0) {
      this.lastStatus = 'unreadable'
      this.statusMessage = `会话日志不可读：${this.lastError}`
      return
    }
    if (watchers.length === 0) {
      this.lastStatus = 'source-missing'
      this.statusMessage = this.watchingAll
        ? '还没找到任何 DSH 会话日志（DSH 可能还没在这台机器上跑过）'
        : this.projectDirExists
          ? '找到项目目录，但里面还没有会话日志'
          : '还没找到这个工作目录的 DSH 会话日志（DSH 可能还没在这个目录里跑过）'
      return
    }
    const newest = watchers
      .map((w) => ({ w, at: w.tailer.state?.lastEventAt ?? 0, mtime: w.modifiedAt }))
      .sort((a, b) => b.at - a.at || b.mtime - a.mtime)[0]
    const live = newest !== undefined && now - newest.w.modifiedAt <= LIVE_WINDOW_MS
    const source = this.watchingAll ? '全机' : '当前'
    this.lastStatus = live ? 'connected' : 'watching'
    const tail = live ? '最新一批事件刚落盘' : '当前没有新的追加'
    this.statusMessage = `正在跟踪${source} ${watchers.length} 个会话日志（${tail}）`
    if (this.truncationNote !== undefined) this.statusMessage = `${this.statusMessage}。${this.truncationNote}`
  }

  /**
   * Discover session artifacts.
   *
   * In workspace mode the project-directory key is only a fast path: the key is
   * lossy, so every candidate project directory is confirmed by the `cwd` DSH
   * recorded in the session header. In watch-all mode every project directory is
   * read, and each session carries the workspace from its own header — that is
   * what lets a TUI session in one directory and a web session in another appear
   * side by side on the phone.
   *
   * The result is cached until the sessions root changes (a new project directory
   * or a new session directory bumps its mtime), so watching dozens of sessions
   * does not mean re-reading dozens of headers on every poll.
   */
  private async discoverSessions(): Promise<readonly DiscoveredSession[]> {
    const rootMtime = await this.modifiedTime(this.sessionsRoot)
    const cached = this.discoveryCache
    if (cached !== undefined && cached.rootMtime === rootMtime && Date.now() - cached.at < DISCOVERY_TTL_MS * 4) {
      return cached.sessions
    }
    const sessions = this.watchingAll ? await this.discoverEveryProject() : await this.discoverWorkspace()
    this.discoveryCache = { at: Date.now(), rootMtime, sessions }
    return sessions
  }

  /** Discover every session under every project directory (watch-all mode). */
  private async discoverEveryProject(): Promise<readonly DiscoveredSession[]> {
    const found: DiscoveredSession[] = []
    for (const entry of await this.listDirectories(this.sessionsRoot)) {
      for (const sessionDir of await this.listDirectories(entry)) {
        const artifacts = await this.collectArtifacts(sessionDir)
        found.push(...artifacts)
      }
    }
    return found
  }

  /** Discover this workspace's session artifacts (single-workspace mode). */
  private async discoverWorkspace(): Promise<readonly DiscoveredSession[]> {
    const projectDirs = new Set<string>()
    if (this.projectDir !== undefined && (await this.isDirectory(this.projectDir))) projectDirs.add(this.projectDir)

    const wanted = normalisePath(this.config.workspace)
    for (const path of await this.listDirectories(this.sessionsRoot)) {
      if (projectDirs.has(path)) continue
      // Coarse filter first: only project directories whose key could encode this
      // workspace are worth confirming against the recorded header.
      if (!projectKeyMatches(path, wanted)) continue
      const sessionDirs = await this.listDirectories(path)
      for (const sessionDir of sessionDirs.slice(0, 8)) {
        const artifacts = await this.collectArtifacts(sessionDir)
        if (artifacts.length === 0) continue
        if (artifacts.some((artifact) => normalisePath(artifact.workspace) === wanted)) {
          projectDirs.add(path)
          break
        }
      }
    }

    const found: DiscoveredSession[] = []
    for (const projectDir of projectDirs) {
      for (const sessionDir of await this.listDirectories(projectDir)) {
        for (const artifact of await this.collectArtifacts(sessionDir)) {
          if (normalisePath(artifact.workspace) === wanted) found.push(artifact)
        }
      }
    }
    return found
  }

  /**
   * Read one session directory's artifact (header included).
   *
   * @param sessionDir - directory holding the session log.
   * @returns the artifact, or an empty list when there is nothing readable.
   */
  private async collectArtifacts(sessionDir: string): Promise<readonly DiscoveredSession[]> {
    const artifact = await this.pickArtifact(sessionDir)
    if (artifact === undefined) return []
    const header = await this.readHeader(artifact.path)
    if (header?.cwd === undefined) return []
    return [
      {
        sessionId: artifact.sessionId,
        path: artifact.path,
        workspace: header.cwd,
        version: artifact.version,
        newer: artifact.newer,
        modifiedAt: header.modifiedAt,
      },
    ]
  }

  /** Read just the header of an artifact (frame 1) plus its file mtime. */
  private async readHeader(path: string): Promise<{ cwd: string; modifiedAt: number } | undefined> {
    const probe = new SessionLogTailer(path)
    await probe.update()
    const cwd = probe.state?.header.cwd
    if (cwd === undefined) return undefined
    return { cwd, modifiedAt: probe.modifiedAt }
  }

  /** List session-owned directories under one project directory. */
  private async listDirectories(path: string): Promise<string[]> {
    try {
      const entries = await readdir(path, { withFileTypes: true })
      return entries.filter((e) => e.isDirectory()).map((e) => join(path, e.name))
    } catch {
      return []
    }
  }

  /** Choose the highest-format artifact inside one session directory. */
  private async pickArtifact(
    sessionDir: string,
  ): Promise<{ sessionId: string; path: string; version: number; newer: readonly string[] } | undefined> {
    let names: string[]
    try {
      names = await readdir(sessionDir)
    } catch {
      return undefined
    }
    const ranked = rankSessionFiles(names)
    if (ranked.length === 0) return undefined
    const [chosen, ...older] = ranked
    return {
      sessionId: sessionDir.replace(/[\\/]+$/, '').split(/[\\/]/).pop() ?? sessionDir,
      path: join(sessionDir, chosen.name),
      version: chosen.version,
      newer: older.map((entry) => entry.name),
    }
  }

  /** Whether a path is a readable directory. */
  private async isDirectory(path: string): Promise<boolean> {
    try {
      const stats = await stat(path)
      return stats.isDirectory()
    } catch {
      return false
    }
  }

  /**
   * Modification time of a path, or a sentinel when it cannot be read.
   *
   * Used to invalidate the discovery cache: a new project or session directory
   * changes the mtime of its parent, which is exactly when a rescan is needed.
   *
   * @param path - path to stat.
   * @returns epoch milliseconds, or -1 when unreadable.
   */
  private async modifiedTime(path: string): Promise<number> {
    try {
      return (await stat(path)).mtimeMs
    } catch {
      return -1
    }
  }

  /** Build the full status payload (this also refreshes every artifact). */
  async snapshot(now = Date.now()): Promise<AdapterSnapshot> {
    await this.refresh()
    const sessions = new Map<string, SessionSnapshot>()
    const views: SessionView[] = []
    for (const watcher of this.watchers.values()) {
      const state = watcher.tailer.state
      if (state === undefined) continue
      const { view, timeline } = projectSession(state, now)
      // Approvals are maintained incrementally while folding, so an approval asked
      // more than EVENT_WINDOW events ago is still reported here.
      const stillPending = [...state.pendingApprovals.values()].sort((a, b) => a.askedAt - b.askedAt)
      const decided = state.decidedApprovals.slice(-DECIDED_WINDOW)
      sessions.set(watcher.sessionId, {
        state,
        timeline,
        pending: stillPending,
        decided,
        formatVersion: watcher.formatVersion,
        newerGenerations: watcher.newerGenerations,
        artifactPath: watcher.path,
      })
      views.push(view)
    }

    views.sort((a, b) => b.lastEventAt - a.lastEventAt)

    let probes: ProcessProbeResult
    try {
      probes = await this.processes.probe()
    } catch (error) {
      probes = { processes: [], error: error instanceof Error ? error.message : String(error) }
    }

    const currentSessionId = views[0]?.sessionId
    const pendingApprovals = [...sessions.values()].flatMap((s) => s.pending).sort((a, b) => a.askedAt - b.askedAt)
    const recentlyDecided = [...sessions.values()].flatMap((s) => s.decided).sort((a, b) => b.decidedAt - a.decidedAt).slice(0, DECIDED_WINDOW)

    const source: SourceHealth = {
      kind: 'dsh-session-log',
      status: this.lastStatus,
      message: this.statusMessage,
      sessionsRoot: this.sessionsRoot,
      workspace: this.config.workspace,
      projectDir: this.projectDirExists ? this.projectDir : undefined,
      lastScanAt: this.lastScanAt,
      lastError: this.lastError,
      processNote: probes.error,
      nodeProcessCount: probes.nodeProcessCount,
      approvalWritable: false,
      watchAll: this.watchingAll,
      watchedSessionCount: this.watchers.size,
      discoveredSessionCount: this.discoveryCache?.sessions.length ?? this.watchers.size,
      maxSessions: this.maxSessions,
      // Group by the normalised path: Windows records the same directory with
      // different casing (`system32` vs `System32`), which must not become two
      // workspaces (and therefore two project chips) on the phone.
      workspaceCount: new Set([...this.watchers.values()].map((watcher) => normalisePath(watcher.workspace))).size,
    }

    const payload: StatusPayload = {
      generatedAt: now,
      source,
      currentSessionId,
      sessions: views,
      processes: probes.processes,
      pendingApprovals,
      recentlyDecided,
      capabilities: capabilities(),
    }
    return { payload, sessions, currentSessionId }
  }

  /** Timeline entries for one session, newest last, bounded by `limit`. */
  timelineFor(sessionId: string, limit = 120): readonly MonitorEvent[] {
    const watcher = this.watchers.get(sessionId)
    if (watcher?.tailer.state === undefined) return []
    const { timeline } = projectSession(watcher.tailer.state, Date.now())
    return timeline.slice(-limit)
  }

  /** Every session id currently watched. */
  get watchedSessionIds(): readonly string[] {
    return [...this.watchers.keys()]
  }

  /** Raw decoded events for one session (used by tests and deep diagnostics). */
  rawEvents(sessionId: string): readonly DshSessionEvent[] {
    return this.watchers.get(sessionId)?.tailer.state?.events ?? []
  }
}

/** Capability report for this build. */
export function capabilities(): Capabilities {
  return {
    monitoring: true,
    processView: true,
    pairing: true,
    approvalViewing: true,
    approvalDeciding: false,
    approvalDecidingReason:
      'DSH 0.2.0-rc.2 的审批决定只在 DSH 进程内的 approval/request waterfall 里产生，没有面向外部进程的审批通道；会话日志是只追加产物，写它不会影响正在运行的 DSH。本项目不模拟批准、也不用通用 RPC 代偿。',
    publicAccess: 'disabled',
    publicAccessReason: '首期只做 LAN；公网访问模式 B 仅预留接口，未实现也不会自动安装任何隧道客户端。',
    chat: false,
    commandExecution: false,
  }
}
