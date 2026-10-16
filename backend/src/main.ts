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

import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DshSessionSource } from './adapters/dsh/sessions.ts'
import { DeviceStore } from './auth/devices.ts'
import { MonitorService } from './server.ts'
import { parseCliOptions, resolveConfig, validatePublicMode, type MonitorConfig } from './config.ts'
import { PublicGate } from './services/public-access.ts'
import { listLanAddresses } from './services/lan.ts'
import { runDashboard } from './cli/dashboard.ts'
import { readVersion } from './version.ts'

/** Backend source root, used to locate the built frontend without hard-coded paths. */
const here = dirname(fileURLToPath(import.meta.url))

/** Whether the process should also drive the interactive terminal dashboard. */
function wantsDashboard(): boolean {
  if (process.env.DSH_POCKET_MONITOR_NO_DASHBOARD === '1') return false
  return process.stdin.isTTY === true && process.stdout.isTTY === true
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

  // Refuse an unsafe public exposure before binding anything: device tokens must
  // never travel in clear text, and the PIN requirement is the second factor that
  // makes a leaked token alone insufficient.
  const problems = validatePublicMode(config)
  if (problems.length > 0) {
    process.stderr.write(`\n公网模式配置有问题，服务没有启动：\n${problems.map((line) => `  · ${line}`).join('\n')}\n\n`)
    process.exitCode = 1
    return
  }

  const devices = new DeviceStore(config.dataDir, { inactivityDays: config.deviceInactivityDays })
  await devices.load()
  const source = new DshSessionSource({
    dshHome: config.dshHome,
    workspace: config.workspace,
    pollIntervalMs: config.pollIntervalMs,
  })

  const gate = new PublicGate({
    enabled: config.public,
    ...(config.publicUrl === undefined ? {} : { publicUrl: config.publicUrl }),
    tls: config.tlsCertPath !== undefined && config.tlsKeyPath !== undefined,
    behindTlsTerminator: config.behindTlsTerminator,
    dataDir: config.dataDir,
    requirePin: config.publicRequirePin,
    // Addresses this machine owns stay on the LAN path even in public mode.
    localAuthorities: [...listLanAddresses().map((entry) => entry.address), config.host],
  })
  const generatedPin = await gate.load()
  if (config.publicPin !== undefined) await gate.setPin(config.publicPin, false)

  const service = new MonitorService({ config, source, devices, frontendDir, gate })

  let runtime
  try {
    runtime = await service.start()
  } catch (error) {
    reportFatal(config, error)
    process.exitCode = 1
    return
  }

  const publicAccess = gate.status()
  process.stdout.write(
    [
      '',
      `DSH Pocket Monitor v${version}`,
      `  数据源：DSH 会话日志（只读）  ${config.dshHome}\\sessions`,
      `  工作目录：${config.workspace}`,
      `  监听：${config.host}:${runtime.port}`,
      `  本机地址：http://127.0.0.1:${runtime.port}/`,
      `  公网访问：${publicAccess.mode}${publicAccess.url === null ? '' : `  ${publicAccess.url}`}`,
      `            ${publicAccess.reason}`,
      `  设备过期：${config.deviceInactivityDays === 0 ? '不自动过期（只受手动撤销控制）' : `${config.deviceInactivityDays} 天未使用即失效`}`,
      `  关闭方法：在终端按 Ctrl+C（或在本终端输入 q 回车）`,
      '',
    ].join('\n'),
  )

  if (config.public) {
    const lines: string[] = ['公网模式已开启：']
    if (generatedPin !== undefined) {
      lines.push(`  首次生成访问 PIN：${generatedPin}   ← 手机在新网络首次访问时需要输入`)
      lines.push('  （已保存到 data/access-pin.json，只存哈希；忘记可用 npm run pin 重新生成）')
    } else if (gate.hasPin) {
      lines.push('  访问 PIN 已存在（忘记可用 npm run pin 重新生成）')
    } else {
      lines.push('  访问 PIN 未启用：任何拿到设备令牌的客户端都能读取，风险自负（--public-no-pin）')
    }
    lines.push(`  公网域名：${config.publicUrl ?? '(未声明，将接受任何非本地 Host)'}`)
    lines.push('  未配对设备一律 401；已配对设备换网络后仍可访问；撤销设备立即失效。')
    lines.push('  本服务不安装也不启动任何隧道客户端——请自行用你的隧道工具指向本端口。')
    lines.push('')
    process.stdout.write(`${lines.join('\n')}\n`)
  }

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
