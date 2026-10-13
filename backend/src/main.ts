#!/usr/bin/env node
/**
 * Entry point for the DSH Pocket Monitor LAN service.
 *
 * Startup is manual and single-purpose: bind a socket, watch the DSH session
 * logs read-only, print the phone URL and pairing code, and exit cleanly on
 * Ctrl+C — revoking the live pairing code and dropping every stream, while
 * leaving DSH itself and every other program alone.
 *
 * @module dsh-pocket-monitor/main
 */

import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DshSessionSource } from './adapters/dsh/sessions.ts'
import { DeviceStore } from './auth/devices.ts'
import { MonitorService } from './server.ts'
import { parseCliOptions, resolveConfig, type MonitorConfig } from './config.ts'
import { getPublicAccessStatus } from './services/public-access.ts'
import { runDashboard } from './cli/dashboard.ts'

/** Backend source root, used to locate the built frontend without hard-coded paths. */
const here = dirname(fileURLToPath(import.meta.url))

/** Whether the process should also drive the interactive terminal dashboard. */
function wantsDashboard(): boolean {
  if (process.env.DSH_POCKET_MONITOR_NO_DASHBOARD === '1') return false
  return process.stdin.isTTY === true && process.stdout.isTTY === true
}

/** Read this project's version from package.json, tolerating a missing file. */
async function readVersion(): Promise<string> {
  for (const candidate of [resolve(here, '../../package.json'), resolve(here, '../../../package.json')]) {
    try {
      const parsed: unknown = JSON.parse(await readFile(candidate, 'utf8'))
      if (typeof parsed === 'object' && parsed !== null && typeof (parsed as { version?: unknown }).version === 'string') {
        return (parsed as { version: string }).version
      }
    } catch {
      /* try the next candidate */
    }
  }
  return '0.0.0'
}

/** Locate the built frontend directory. */
async function resolveFrontendDir(): Promise<string> {
  const configured = process.env.DSH_POCKET_MONITOR_FRONTEND_DIR
  if (configured !== undefined && configured !== '') return resolve(configured)
  return resolve(here, '../../frontend/dist')
}

/** Print the fatal startup error with actionable advice. */
function reportFatal(config: MonitorConfig, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error)
  const lines = ['', '启动失败，服务没有开始监听。', `原因：${message}`, '']
  if (/EADDRINUSE/i.test(message)) {
    lines.push(`端口 ${config.port} 已被占用。`)
    lines.push('本程序不会杀掉占用端口的其他程序，也不会修改 DSH 的端口。请选择别的端口：')
    lines.push(`  npm run start:lan -- --port ${config.port + 1}`)
    lines.push(`（也就是 DSH_POCKET_MONITOR_PORT=${config.port + 1} 或用 --port 参数）`)
  } else {
    lines.push('排查建议：确认端口没有被占用、绑定的网卡地址确实存在，以及 Node 版本 >= 22。')
  }
  lines.push('')
  process.stderr.write(`${lines.join('\n')}\n`)
}

/** Wire the pieces and run until stopped. */
async function main(): Promise<void> {
  const options = parseCliOptions(process.argv.slice(2))
  const config = resolveConfig(options)
  const version = await readVersion()
  const frontendDir = await resolveFrontendDir()

  const devices = new DeviceStore(config.dataDir)
  await devices.load()
  const source = new DshSessionSource({
    dshHome: config.dshHome,
    workspace: config.workspace,
    pollIntervalMs: config.pollIntervalMs,
  })
  const service = new MonitorService({ config, source, devices, frontendDir })

  let runtime
  try {
    runtime = await service.start()
  } catch (error) {
    reportFatal(config, error)
    process.exitCode = 1
    return
  }

  const publicAccess = getPublicAccessStatus()
  process.stdout.write(
    [
      '',
      `DSH Pocket Monitor v${version}`,
      `  数据源：DSH 会话日志（只读）  ${config.dshHome}\\sessions`,
      `  工作目录：${config.workspace}`,
      `  监听：${config.host}:${runtime.port}`,
      `  本机地址：http://127.0.0.1:${runtime.port}/`,
      `  公网访问：${publicAccess.mode}（模式 B 未实现，也不会自动安装隧道）`,
      `  关闭方法：在终端按 Ctrl+C（或在本终端输入 q 回车）`,
      '',
    ].join('\n'),
  )

  const useDashboard = wantsDashboard()
  let stopping = false
  const shutdown = (): void => {
    if (stopping) return
    stopping = true
    process.stdout.write('\n正在关闭：撤销临时配对码、断开手机实时连接、关闭 HTTP 服务…\n')
    void service.stop().then(() => {
      process.stdout.write('已关闭。DSH 与其他程序未受影响。\n')
      process.exit(0)
    })
  }

  process.on('SIGINT', shutdown)
  process.on('SIGTERM', shutdown)
  process.on('SIGHUP', shutdown)
  process.on('uncaughtException', (error) => {
    process.stderr.write(`未捕获异常：${error instanceof Error ? error.stack ?? error.message : String(error)}\n`)
    shutdown()
  })

  if (!useDashboard) {
    const view = service.pairing.issue(Date.now(), true)
    process.stdout.write(
      [
        '未检测到交互式终端（例如从脚本或后台启动），跳过二维码界面。',
        `本次配对码：${view.code}（有效期至 ${new Date(view.expiresAt).toLocaleTimeString()}，过后可用 --pair-ttl 调整或重启服务）`,
        '手机访问地址：',
        ...runtime.urls.map((url) => `  ${url}`),
        '手机提交配对请求后，请在本机执行（会自动读取确认凭证）：',
        '  npm run approve',
        '',
      ].join('\n'),
    )
    await new Promise<void>(() => {
      /* run until a signal arrives */
    })
    return
  }

  await runDashboard({
    port: runtime.port,
    lanAddresses: runtime.lanAddresses,
    devices,
    pairing: service.pairing,
    publicAccess,
    shutdown,
    refreshNow: () => {
      void service.currentStatus(true)
    },
  })
}

await main()
