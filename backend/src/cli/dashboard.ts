/**
 * Terminal dashboard: the desktop half of the pairing flow.
 *
 * It prints the LAN address and a scannable QR block, owns the pairing code, and
 * asks the operator to confirm (or reject) a phone that claimed the code. It is
 * the only place that ever sees the pairing nonce.
 *
 * @module dsh-pocket-monitor/cli/dashboard
 */

import { createInterface } from 'node:readline'
import { networkInterfaces } from 'node:os'
import QRCode from 'qrcode'
import type { DeviceRecord } from '../auth/devices.ts'
import type { DeviceStore } from '../auth/devices.ts'
import type { PairingService } from '../auth/pairing.ts'
import { listLanAddresses, preferredLanAddress, type LanAddress } from '../services/lan.ts'
import type { PublicAccessStatus } from '../../../shared/types/index.ts'

/** Everything the dashboard needs from the running service. */
export interface DashboardHost {
  readonly port: number
  readonly lanAddresses: readonly LanAddress[]
  readonly devices: DeviceStore
  readonly pairing: PairingService
  readonly publicAccess: PublicAccessStatus
  /** Stop the service gracefully (same path as Ctrl+C). */
  shutdown: () => void
  /** Force an immediate source refresh. */
  refreshNow: () => void
}

/** ANSI helpers kept tiny; the terminal is not the product. */
const BOLD = '\u001b[1m'
const DIM = '\u001b[2m'
const RESET = '\u001b[0m'
const CYAN = '\u001b[36m'
const YELLOW = '\u001b[33m'

/**
 * Render a QR code with half-block characters so it stays scannable in a
 * terminal that reports a roughly 2:1 character cell aspect ratio.
 *
 * @param text - usually the phone URL.
 * @returns the rendered block as a string.
 */
export async function renderTerminalQr(text: string): Promise<string> {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' })
  const size = qr.modules.size
  const data = qr.modules.data
  const isDark = (row: number, col: number): boolean => row >= 0 && col >= 0 && row < size && col < size && data[row * size + col] === 1
  const quiet = 2
  const lines: string[] = []
  for (let row = -quiet; row < size + quiet; row += 2) {
    let line = ''
    for (let col = -quiet; col < size + quiet; col += 1) {
      const top = isDark(row, col)
      const bottom = isDark(row + 1, col)
      if (top && bottom) line += '█'
      else if (top) line += '▀'
      else if (bottom) line += '▄'
      else line += ' '
    }
    lines.push(line)
  }
  return lines.join('\n')
}

/** Build the phone URL for one LAN address. */
export function phoneUrl(address: string, port: number): string {
  return `http://${address}:${port}/`
}

/**
 * Build the QR payload.
 *
 * It carries only the LAN URL and this round's short-lived pairing code — never
 * a DSH token, never a long-lived credential. The phone still needs the desktop
 * to confirm the claim, so the code alone cannot bind a device.
 *
 * @param address - LAN address to embed.
 * @param port - service port.
 * @param code - current one-time pairing code.
 * @returns the text encoded in the QR block.
 */
export function qrPayload(address: string, port: number, code: string): string {
  return `${phoneUrl(address, port)}?pair=${code}`
}

/**
 * Drive the interactive dashboard until the process is stopped.
 *
 * @param host - service hooks and state.
 */
export async function runDashboard(host: DashboardHost): Promise<void> {
  const preferred = preferredLanAddress(host.lanAddresses)
  let pairing = host.pairing.issue(Date.now(), true)
  let lastRenderedClaim: string | undefined

  const printHeader = async (): Promise<void> => {
    const lines: string[] = []
    lines.push('')
    lines.push(`${BOLD}DSH Pocket Monitor — LAN 模式已启动${RESET}`)
    lines.push(`${DIM}（本服务由你手动启动；按 Ctrl+C 或输入 q 回车即可停止，退出后服务不再监听）${RESET}`)
    lines.push('')
    if (preferred === undefined) {
      lines.push(`${YELLOW}没有检测到局域网 IPv4 地址。${RESET}只有本机能通过 http://127.0.0.1:${host.port}/ 访问。`)
    } else {
      lines.push(`${BOLD}手机访问地址：${RESET}${CYAN}${phoneUrl(preferred.address, host.port)}${RESET}  ${DIM}(${preferred.iface} · ${preferred.kind})${RESET}`)
      if (host.lanAddresses.length > 1) {
        lines.push(`${DIM}其他可用地址：${host.lanAddresses.slice(1).map((entry) => `${entry.address}(${entry.iface})`).join('  ')}${RESET}`)
      }
    }
    lines.push(`${DIM}本机访问地址：http://127.0.0.1:${host.port}/  （配对码只在终端显示）${RESET}`)
    lines.push('')
    lines.push(`${BOLD}本次配对码：${RESET}${BOLD}${CYAN}${pairing.code}${RESET}   ${DIM}有效期至 ${new Date(pairing.expiresAt).toLocaleTimeString()}；用过即失效${RESET}`)
    lines.push(`${DIM}二维码内容 = 上面的局域网地址 + ?pair=<配对码>；不含任何 DSH 凭证。${RESET}`)
    lines.push(`${DIM}配对码是一次性的：手机提交后必须在这台电脑上确认，才会下发设备令牌。${RESET}`)
    lines.push(`${DIM}公网访问：${host.publicAccess.mode} — ${host.publicAccess.reason}${RESET}`)
    lines.push('')
    process.stdout.write(`${lines.join('\n')}\n`)

    if (preferred !== undefined) {
      const qr = await renderTerminalQr(qrPayload(preferred.address, host.port, pairing.code))
      process.stdout.write(`${qr}\n\n`)
    }
    await printDevices()
    process.stdout.write(`${DIM}命令：r=刷新新配对码  d=设备列表  a=确认待配对  x=拒绝待配对  q=退出${RESET}\n`)
  }

  const printDevices = async (): Promise<void> => {
    const devices = host.devices.list()
    if (devices.length === 0) {
      process.stdout.write(`${DIM}已绑定设备：无${RESET}\n`)
      return
    }
    process.stdout.write(`${BOLD}已绑定设备：${RESET}\n`)
    for (const device of devices) {
      const state = device.revokedAt === undefined ? '有效' : `已撤销 ${new Date(device.revokedAt).toLocaleString()}`
      process.stdout.write(
        `  · ${device.name}  ${DIM}id=${device.id.slice(0, 8)} 绑定于 ${new Date(device.createdAt).toLocaleString()} 最近使用 ${new Date(device.lastSeenAt).toLocaleString()} 状态=${state}${RESET}\n`,
      )
    }
  }

  const showClaim = (): void => {
    const view = host.pairing.currentView()
    const claim = view?.claim
    if (view === undefined || claim === undefined) {
      process.stdout.write(`${DIM}当前没有手机提交配对请求。${RESET}\n`)
      return
    }
    lastRenderedClaim = claim.secretHash
    process.stdout.write(
      `\n${BOLD}收到配对请求${RESET}：设备名「${claim.deviceName}」来源 ${claim.claimedFrom} 状态 ${claim.status}\n` +
        `${DIM}请确认这就是你手上的手机；确认后令牌只会下发给提交这次请求的设备。${RESET}\n`,
    )
  }

  const approve = (approveIt: boolean): void => {
    const view = host.pairing.currentView()
    if (view === undefined) {
      process.stdout.write(`${YELLOW}没有可确认的配对码（可能已过期或已被使用）。按 r 生成新码。${RESET}\n`)
      return
    }
    if (!approveIt) {
      const rejected = host.pairing.decide({ pairingId: view.id, nonce: pairing.nonce, approve: false })
      if (!rejected.ok) {
        process.stdout.write(`${YELLOW}拒绝失败：${rejected.reason}${RESET}\n`)
        return
      }
      process.stdout.write(`${YELLOW}已拒绝这次配对。${RESET}\n`)
      return
    }
    const decision = host.pairing.decide({ pairingId: view.id, nonce: pairing.nonce, approve: true })
    if (!decision.ok) {
      process.stdout.write(`${YELLOW}确认失败：${decision.reason}${RESET}\n`)
      return
    }
    if (decision.status === 'rejected') {
      process.stdout.write(`${YELLOW}已拒绝这次配对。${RESET}\n`)
      return
    }
    void host.devices
      .create({
        id: decision.deviceId,
        name: view.claim?.deviceName ?? '手机',
        token: decision.token,
        pairedFrom: view.claim?.claimedFrom,
      })
      .then(async (device: DeviceRecord) => {
        process.stdout.write(`${CYAN}已确认绑定：${device.name}（${device.id.slice(0, 8)}）${RESET}\n`)
        await printDevices()
      })
      .catch((error: unknown) => {
        process.stdout.write(`${YELLOW}绑定写入失败：${error instanceof Error ? error.message : String(error)}${RESET}\n`)
      })
  }

  await printHeader()

  const rl = createInterface({ input: process.stdin, output: process.stdout })
  let stopped = false
  const ticker = setInterval(() => {
    if (stopped) return
    const view = host.pairing.currentView()
    const claim = view?.claim
    if (claim !== undefined && claim.status === 'pending' && claim.secretHash !== lastRenderedClaim) showClaim()
    if (view === undefined && host.pairing.currentView() === undefined && Date.now() > pairing.expiresAt) {
      pairing = host.pairing.issue(Date.now(), true)
      process.stdout.write(`${YELLOW}配对码已过期，已生成新码：${pairing.code}${RESET}\n`)
    }
  }, 1_500)
  ticker.unref()

  process.stdout.write('> ')
  for await (const line of rl) {
    const command = line.trim().toLowerCase()
    if (command === 'q' || command === 'quit' || command === 'exit') {
      stopped = true
      clearInterval(ticker)
      host.shutdown()
      return
    }
    if (command === 'r') {
      pairing = host.pairing.issue(Date.now(), true)
      lastRenderedClaim = undefined
      await printHeader()
    } else if (command === 'd') {
      await printDevices()
    } else if (command === 'a') {
      approve(true)
    } else if (command === 'x') {
      approve(false)
    } else if (command === 'p') {
      host.refreshNow()
      process.stdout.write(`${DIM}已触发一次数据源刷新。${RESET}\n`)
    } else if (command !== '') {
      process.stdout.write(`${DIM}可用命令：r 刷新配对码 / d 设备列表 / a 确认 / x 拒绝 / p 刷新数据 / q 退出${RESET}\n`)
    }
    process.stdout.write('> ')
  }
  stopped = true
  clearInterval(ticker)
  host.shutdown()
}

/** List local IPv4 candidates for the startup banner (re-exported for the entry point). */
export function lanCandidates(): LanAddress[] {
  return listLanAddresses(networkInterfaces())
}
