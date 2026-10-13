#!/usr/bin/env node
/**
 * `npm run approve` — confirm a pairing request from a second terminal.
 *
 * The monitor prints a pairing code and, when a phone claims it, a confirmation
 * nonce. This helper talks to the loopback-only admin API of the running service
 * so the operator can approve or reject without the interactive dashboard.
 *
 * @module dsh-pocket-monitor/cli/approve
 */

import { createInterface } from 'node:readline'
import { parseCliOptions, resolveConfig } from '../config.ts'

/** Minimal JSON fetch with a timeout and a clear connection-failure message. */
async function request(url: string, init: RequestInit = {}): Promise<{ status: number; body: unknown }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), 5_000)
  try {
    const response = await fetch(url, { ...init, signal: controller.signal })
    const text = await response.text()
    let body: unknown = text
    try {
      body = JSON.parse(text)
    } catch {
      /* keep the raw text */
    }
    return { status: response.status, body }
  } catch (error) {
    const reason = error instanceof Error && error.name === 'AbortError' ? '请求超时' : '连接失败'
    throw new Error(
      `${reason}：连不上 http://127.0.0.1 上的监控服务。\n` +
        '请确认：1) 服务正在这台电脑上运行（npm run start:lan）；2) 端口用 --port 改过（本命令可用同样的 --port 指定）。',
    )
  } finally {
    clearTimeout(timer)
  }
}

/** Read the admin session state from the running service. */
async function readSession(port: number): Promise<Record<string, unknown>> {
  const { status, body } = await request(`http://127.0.0.1:${port}/api/admin/session`)
  if (status !== 200 || typeof body !== 'object' || body === null) {
    throw new Error(`无法读取本机管理接口（HTTP ${status}）。服务是否在运行？端口是否正确？`)
  }
  return body as Record<string, unknown>
}

/** Entry point. */
async function main(): Promise<void> {
  const options = parseCliOptions(process.argv.slice(2))
  const config = resolveConfig(options)
  let session
  try {
    session = await readSession(config.port)
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
    process.exitCode = 1
    return
  }

  const claim = session['claim'] as Record<string, unknown> | null | undefined
  if (claim === undefined || claim === null || claim['status'] !== 'pending') {
    process.stdout.write('当前没有等待确认的配对请求。\n')
    process.stdout.write(`当前配对码：${String(session['pairingCode'] ?? '无')}（在服务终端按 r 可生成新码）\n`)
    return
  }

  process.stdout.write(
    [
      '',
      `收到配对请求：`,
      `  设备名：${String(claim['deviceName'] ?? '未命名')}`,
      `  来源：  ${String(claim['claimedFrom'] ?? '未知')}`,
      `  时间：  ${new Date(Number(claim['claimedAt'] ?? Date.now())).toLocaleString()}`,
      '',
      '确认这就是你手上的手机吗？输入 y 批准 / n 拒绝（直接回车 = 不操作）：',
    ].join('\n'),
  )

  const rl = createInterface({ input: process.stdin, output: process.stdout })
  const answer = await new Promise<string>((resolvePromise) => {
    rl.question('> ', (value) => {
      rl.close()
      resolvePromise(value.trim().toLowerCase())
    })
  })
  if (answer !== 'y' && answer !== 'n') {
    process.stdout.write('未做任何操作。\n')
    return
  }

  const nonce = session['pairingNonce']
  if (typeof nonce !== 'string' || nonce === '') {
    process.stderr.write('管理接口没有返回确认凭证；请在服务所在终端里用 a/x 命令确认。\n')
    process.exitCode = 1
    return
  }

  const { status, body } = await request(`http://127.0.0.1:${config.port}/api/admin/pairing/claim`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ nonce, approve: answer === 'y' }),
  })
  if (status !== 200) {
    const message =
      typeof body === 'object' && body !== null && 'error' in body
        ? String((body as { error: { message?: unknown } }).error.message ?? '')
        : String(body)
    process.stderr.write(`操作失败（HTTP ${status}）：${message}\n`)
    process.exitCode = 1
    return
  }
  process.stdout.write(answer === 'y' ? '已批准，手机端会拿到受限令牌。\n' : '已拒绝这次配对。\n')
}

await main()
