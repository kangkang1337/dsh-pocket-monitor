/**
 * One-off end-to-end verification (not part of the test suite).
 *
 * Builds a synthetic DSH home containing a pending approval, starts the real
 * service stack in this process (so no child process is needed — some sandboxes
 * forbid spawning with pipes), pairs a device through the HTTP API, and checks
 * exactly what the phone would see. Run with:
 *
 *   node --experimental-strip-types scripts/e2e-check.ts
 */

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { constants, zstdCompressSync } from 'node:zlib'
import { DeviceStore } from '../backend/src/auth/devices.ts'
import { DshSessionSource, projectKey } from '../backend/src/adapters/dsh/sessions.ts'
import { MonitorService } from '../backend/src/server.ts'
import { PublicGate } from '../backend/src/services/public-access.ts'
import { listLanAddresses } from '../backend/src/services/lan.ts'
import { resolveConfig, validatePublicMode } from '../backend/src/config.ts'

/** Encode one JSONL batch as one checksummed Zstandard frame (as DSH does). */
function frame(lines: readonly string[]): Buffer {
  return zstdCompressSync(Buffer.from(`${lines.join('\n')}\n`, 'utf8'), { params: { [constants.ZSTD_c_checksumFlag]: 1 } })
}

/** Collect one GET through a raw client, so `Host` can be set exactly. */
async function rawGet(
  port: number,
  path: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  const { request } = await import('node:http')
  return await new Promise((resolvePromise, rejectPromise) => {
    const req = request({ host: '127.0.0.1', port, path, method: 'GET', headers }, (response) => {
      let body = ''
      response.setEncoding('utf8')
      response.on('data', (chunk) => (body += chunk))
      response.on('end', () => resolvePromise({ status: response.statusCode ?? 0, body }))
    })
    req.on('error', rejectPromise)
    req.end()
  })
}

async function main(): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), 'dpm-e2e-'))
  const workspace = 'C:\\fake\\project'
  const sessionId = 'session-e2e-1'
  const home = join(root, 'dsh-home')
  const sessionsRoot = join(home, 'sessions')
  const sessionDir = join(sessionsRoot, projectKey(workspace), sessionId)
  await mkdir(sessionDir, { recursive: true })

  const now = Date.now()
  const header = { type: 'session', version: 4, id: sessionId, createdAt: now, cwd: workspace, isSeeded: false, delegationDepth: 0, agentPreset: 'standard' }
  const events = [
    { type: 'permission/preset', seq: 0, time: now, data: { preset: 'workspace-write' } },
    { type: 'approval/policy', seq: 1, time: now, data: { policy: 'ask' } },
    { type: 'turn/start', seq: 2, time: now, data: { turn: 1 } },
    { type: 'step/start', seq: 3, time: now, data: { turn: 1, step: 1 } },
    {
      type: 'tool/call',
      seq: 4,
      time: now,
      data: { turn: 1, step: 1, callId: 'call_e2e_1', name: 'pwsh', arguments: '{"description":"build the frontend"}' },
    },
    {
      type: 'approval/asked',
      seq: 5,
      time: now,
      data: {
        id: 'ap-e2e-1',
        toolName: 'pwsh',
        callId: 'call_e2e_1',
        reason: 'escalate sandbox to danger-full-access: building the frontend needs to spawn a child process',
      },
    },
  ]
  await writeFile(
    join(sessionDir, 'session.v4.jsonl.zstd'),
    Buffer.concat([frame([JSON.stringify(header)]), ...events.map((entry) => frame([JSON.stringify(entry)]))]),
  )

  const dataDir = join(root, 'data')
  const frontendDir = resolve(fileURLToPath(new URL('../frontend/dist', import.meta.url)))
  const pin = '246810'

  // 1. An unsafe public configuration must be refused before anything binds.
  const unsafeConfig = resolveConfig({ public: true, dataDir, port: 0 }, {}, workspace)
  const problems = validatePublicMode(unsafeConfig)
  const results: string[] = []
  const check = (label: string, ok: boolean, detail = ''): void => {
    results.push(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail === '' ? '' : `  — ${detail}`}`)
  }
  check('公网模式缺 TLS 时被拒绝', problems.length === 1 && problems[0]?.includes('TLS'), problems[0]?.slice(0, 80) ?? '')

  // 2. Start the real stack with public mode + TLS terminator declared.
  const config = resolveConfig(
    {
      host: '127.0.0.1',
      port: 0,
      public: true,
      publicUrl: 'mon.example.com',
      publicPin: pin,
      behindTlsTerminator: true,
      dataDir,
      pollIntervalMs: 300,
    },
    {},
    workspace,
  )
  await mkdir(dataDir, { recursive: true })
  const devices = new DeviceStore(dataDir)
  await devices.load()
  const source = new DshSessionSource({ dshHome: home, workspace, pollIntervalMs: config.pollIntervalMs })
  const gate = new PublicGate({
    enabled: true,
    publicUrl: 'mon.example.com',
    tls: false,
    behindTlsTerminator: true,
    dataDir,
    requirePin: true,
    localAuthorities: [...listLanAddresses().map((entry) => entry.address), '127.0.0.1', 'localhost'],
  })
  await gate.load()
  const service = new MonitorService({ config, source, devices, frontendDir, gate })

  try {
    const runtime = await service.start()
    const base = `http://127.0.0.1:${runtime.port}`
    check('服务启动并响应 /api/health', await fetch(`${base}/api/health`).then((r) => r.ok).catch(() => false))

    // 3. Pair a phone for real, over loopback.
    const admin = (await (await fetch(`${base}/api/admin/session`)).json()) as Record<string, unknown>
    check('管理接口暴露配对码与确认凭证', typeof admin.pairingCode === 'string' && typeof admin.pairingNonce === 'string')
    check('管理接口报告公网模式与域名', admin.publicAccessEnabled === true && String((admin.publicAccess as { url?: string }).url) === 'mon.example.com')

    const pairSecret = 'e2e-secret-0123456789abcdef'
    const claimed = await fetch(`${base}/api/pair/claim`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ code: admin.pairingCode, pairSecret, deviceName: 'E2E iPhone' }),
    })
    check('配对请求被接受（回环自动确认）', claimed.status === 202, `HTTP ${claimed.status}`)

    const poll = await fetch(`${base}/api/pair/poll`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pairingId: admin.pairingId, pairSecret }),
    })
    const pollBody = (await poll.json()) as { state?: string }
    const cookie = (poll.headers.getSetCookie?.() ?? []).map((entry) => entry.split(';')[0]).join('; ')
    check('单次下发设备令牌并种下 cookie', pollBody.state === 'approved' && cookie.startsWith('dpm_device='), `HTTP ${poll.status}`)

    // 4. What the phone renders.
    const status = (await (await fetch(`${base}/api/status`, { headers: { cookie } })).json()) as {
      currentSessionId?: string
      sessions: Array<{ state: string; pendingApprovals: Array<{ toolName: string; requiredAction?: string; hint?: string }> }>
      capabilities: { approvalDeciding: boolean; publicAccess: string }
    }
    check('读到真实会话日志', status.currentSessionId === sessionId, String(status.currentSessionId))
    const session = status.sessions[0]
    check('会话处于「等待审批」', session?.state === 'waiting-approval', String(session?.state))
    const pending = session?.pendingApprovals[0]
    check('待审批项带上了 requiredAction', pending?.requiredAction === 'sandbox-escalation', String(pending?.requiredAction))
    check('待审批项带上了「一句话提示」', (pending?.hint ?? '').includes('danger-full-access'), String(pending?.hint))
    check('公网访问在能力报告里为 active', status.capabilities.publicAccess === 'active')
    check('审批下发仍如实报告为不可用', status.capabilities.approvalDeciding === false)

    // 5. The approval endpoint refuses honestly and returns the hint.
    const decision = await fetch(`${base}/api/approvals/ap-e2e-1/decision`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'approve', clientRequestId: 'e2e-request-1' }),
    })
    const decisionBody = (await decision.json()) as { nextStep?: string; deliveredToDsh?: boolean }
    check('审批接口返回 501（不假装成功）', decision.status === 501, `HTTP ${decision.status}`)
    check('审批接口给出电脑端操作指引', (decisionBody.nextStep ?? '').includes('电脑'), String(decisionBody.nextStep).slice(0, 50))
    check('审批明确未下发到 DSH', decisionBody.deliveredToDsh === false)

    // 6. The fence: unknown authorities still refused, public authority reachable.
    const unknownHost = await rawGet(runtime.port, '/api/status', { host: 'attacker.example.com' })
    check('未知 Host 仍被栅栏拒绝（403）', unknownHost.status === 403, `HTTP ${unknownHost.status}`)
    const publicNoPin = await rawGet(runtime.port, '/api/status', { host: 'mon.example.com' })
    check('公网域名可达但无 PIN 时被拒（401）', publicNoPin.status === 401, `HTTP ${publicNoPin.status}`)
    check('公网拒绝响应未泄露会话数据', !publicNoPin.body.includes('currentSessionId'))

    // 7. Honest public-access reporting.
    const publicAccess = (await (await fetch(`${base}/api/public-access`, { headers: { cookie } })).json()) as {
      mode: string
      url: string | null
      reason: string
    }
    check('公网状态接口如实汇报', publicAccess.mode === 'active' && publicAccess.url === 'mon.example.com')
    check('公网状态说明包含「不会安装隧道」', publicAccess.reason.includes('不会安装或启动任何隧道客户端'))

    // 8. Admin surface stays loopback-only even with public mode on.
    const adminLocally = await rawGet(runtime.port, '/api/admin/session', { host: `127.0.0.1:${runtime.port}` })
    check('管理接口在本机仍可用', adminLocally.status === 200, `HTTP ${adminLocally.status}`)

    // 9. Shutdown releases everything.
    await service.stop()
    const afterStop = await fetch(`${base}/api/health`).catch(() => undefined)
    check('退出后端口不再响应', afterStop === undefined || !afterStop.ok)
    check('退出后实时连接清空', service.sse.size === 0)
    check('退出后配对码失效', service.pairing.hasActiveCode() === false)
  } finally {
    await service.stop().catch(() => undefined)
    await rm(root, { recursive: true, force: true })
    process.stdout.write(`\n${results.join('\n')}\n`)
    const failed = results.filter((line) => line.startsWith('FAIL')).length
    process.stdout.write(`\n${results.length - failed}/${results.length} 项通过\n`)
    process.exit(failed === 0 ? 0 : 1)
  }
}

await main()
