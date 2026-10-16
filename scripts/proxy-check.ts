/**
 * Security regression: a same-machine tunnel must not impersonate the operator.
 *
 * The topology this guards against is the one the README suggests —
 * `cloudflared tunnel --url http://127.0.0.1:3099` — where every remote request
 * reaches the service from a **loopback socket** while keeping the **public
 * `Host`**. Treating a loopback peer as "the operator" there meant the public PIN
 * was skipped, the admin surface was reachable, and a pairing request could be
 * auto-confirmed by a remote attacker.
 *
 * Run with:
 *   node --experimental-strip-types scripts/proxy-check.ts
 */

import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { DeviceStore } from '../backend/src/auth/devices.ts'
import { DshSessionSource, projectKey } from '../backend/src/adapters/dsh/sessions.ts'
import { MonitorService } from '../backend/src/server.ts'
import { PublicGate } from '../backend/src/services/public-access.ts'
import { listLanAddresses } from '../backend/src/services/lan.ts'
import { resolveConfig } from '../backend/src/config.ts'
import { constants, zstdCompressSync } from 'node:zlib'

const PUBLIC_HOST = 'mon.example.com'
const PIN = '424242'
const results: string[] = []

function check(label: string, ok: boolean, detail = ''): void {
  results.push(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail === '' ? '' : `  — ${detail}`}`)
}

function report(): void {
  process.stdout.write(`\n${results.join('\n')}\n`)
  const failed = results.filter((line) => line.startsWith('FAIL')).length
  process.stdout.write(`\n${results.length - failed}/${results.length} 项通过\n`)
}

/** Encode one JSONL batch as one checksummed frame, as DSH writes it. */
function frame(lines: readonly string[]): Buffer {
  return zstdCompressSync(Buffer.from(`${lines.join('\n')}\n`, 'utf8'), {
    params: { [constants.ZSTD_c_checksumFlag]: 1 },
  })
}

interface RawResponse {
  status: number
  body: string
  setCookie: readonly string[]
}

/**
 * Send a request with an exact `Host` header.
 *
 * `fetch` cannot do this: undici treats `Host` as a forbidden header and silently
 * drops it, so a test built on `fetch` would never actually reproduce the tunnel
 * topology (it would look like an ordinary loopback request).
 */
async function raw(
  base: string,
  path: string,
  options: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<RawResponse> {
  const url = new URL(path, base)
  const payload = options.body
  return await new Promise((resolvePromise, rejectPromise) => {
    const request = httpRequest(
      {
        host: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: options.method ?? 'GET',
        headers: {
          ...(options.headers ?? {}),
          ...(payload === undefined ? {} : { 'content-length': String(Buffer.byteLength(payload)) }),
        },
      },
      (response) => {
        let body = ''
        response.setEncoding('utf8')
        response.on('data', (chunk) => {
          body += chunk
        })
        response.on('end', () =>
          resolvePromise({
            status: response.statusCode ?? 0,
            body,
            setCookie: (response.headers['set-cookie'] ?? []).map((entry) => entry.split(';')[0] ?? ''),
          }),
        )
      },
    )
    request.on('error', rejectPromise)
    if (payload !== undefined) request.write(payload)
    request.end()
  })
}

async function main(): Promise<number> {
  const root = await mkdtemp(join(tmpdir(), 'dpm-proxy-'))
  const workspace = 'C:\\fake\\project'
  const sessionId = 'session-proxy-check'
  const dataDir = join(root, 'data')
  const home = join(root, 'dsh-home')
  const sessionDir = join(home, 'sessions', projectKey(workspace), sessionId)
  await mkdir(sessionDir, { recursive: true })
  await mkdir(dataDir, { recursive: true })

  // One real session with a pending approval, so the data routes have something
  // they would leak if the fence were wrong.
  const now = Date.now()
  const header = { type: 'session', version: 4, id: sessionId, createdAt: now, cwd: workspace, isSeeded: false, delegationDepth: 0, agentPreset: 'standard' }
  const events = [
    { type: 'turn/start', seq: 0, time: now, data: { turn: 1 } },
    { type: 'step/start', seq: 1, time: now, data: { turn: 1, step: 1 } },
    { type: 'approval/asked', seq: 2, time: now, data: { id: 'ap-proxy-1', toolName: 'pwsh', reason: 'escalate sandbox to danger-full-access: needs a child process' } },
  ]
  await writeFile(
    join(sessionDir, 'session.v4.jsonl.zstd'),
    Buffer.concat([frame([JSON.stringify(header)]), ...events.map((entry) => frame([JSON.stringify(entry)]))]),
  )

  const config = resolveConfig(
    {
      host: '127.0.0.1',
      port: 0,
      public: true,
      publicUrl: PUBLIC_HOST,
      publicPin: PIN,
      behindTlsTerminator: true,
      dataDir,
      pollIntervalMs: 300,
    },
    {},
    workspace,
  )
  const devices = new DeviceStore(dataDir)
  await devices.load()
  const source = new DshSessionSource({ dshHome: home, workspace, pollIntervalMs: config.pollIntervalMs })
  const gate = new PublicGate({
    enabled: true,
    publicUrl: PUBLIC_HOST,
    tls: false,
    behindTlsTerminator: true,
    dataDir,
    requirePin: true,
    localAuthorities: [...listLanAddresses().map((entry) => entry.address), '127.0.0.1', 'localhost'],
  })
  await gate.load()
  await gate.setPin(PIN, false)
  const frontendDir = resolve(fileURLToPath(new URL('../frontend/dist', import.meta.url)))
  const service = new MonitorService({ config, source, devices, frontendDir, gate })

  try {
    const runtime = await service.start()
    const base = `http://127.0.0.1:${runtime.port}`
    // What a tunnel forwards: loopback peer + public Host + forwarding headers.
    const tunnelHeaders = { host: PUBLIC_HOST, 'x-forwarded-for': '203.0.113.7', 'x-forwarded-proto': 'https' }

    // 1. The page still loads (the PIN prompt lives in the bundle).
    const shell = await raw(base, '/', { headers: tunnelHeaders })
    check('隧道请求能加载页面（PIN 输入框在页面里）', shell.status === 200, `HTTP ${shell.status}`)

    // 2. Data needs the PIN even though the socket is loopback.
    const noPin = await raw(base, '/api/status', { headers: tunnelHeaders })
    const noPinBody = noPin.body
    check(
      '隧道来源的数据请求被 PIN 拦住',
      (noPin.status === 401 && noPinBody.includes('pinRequired')) || noPin.status === 429,
      `HTTP ${noPin.status}`,
    )
    check('被拦住时没有泄露会话数据', !noPinBody.includes(sessionId) && !noPinBody.includes('sessionId'), noPinBody.slice(0, 80))

    // 3. With the PIN, the data route works — and planting the cookie lets the
    //    SSE stream through without a PIN in the URL.
    const withPin = await raw(base, '/api/status', { headers: { ...tunnelHeaders, 'x-dsh-pocket-pin': PIN } })
    check('带正确 PIN 时仍会被设备认证挡住（未配对）', withPin.status === 401, `HTTP ${withPin.status}`)
    const pinCookie = withPin.setCookie.find((entry) => entry.startsWith('dpm_pin='))
    check('PIN 被换成 HttpOnly cookie（不再出现在 URL 里）', pinCookie !== undefined, pinCookie ?? '(无)')

    // 4. Admin is unreachable through the tunnel, PIN or not.
    for (const path of ['/api/admin/session', '/api/admin/devices/sweep']) {
      const refused = await raw(base, path, { method: path.endsWith('sweep') ? 'POST' : 'GET', headers: { ...tunnelHeaders, 'x-dsh-pocket-pin': PIN } })
      check(`隧道无法访问 ${path}`, refused.status === 403, `HTTP ${refused.status}`)
      check(`拒绝原因是 loopback-only（${path}）`, refused.body.includes('loopback-only'))
    }

    // 5. Pairing over the tunnel is accepted but never auto-confirmed.
    const admin = (await raw(base, '/api/admin/session', { headers: { host: `127.0.0.1:${runtime.port}` } })).body
    const pairingCode = (JSON.parse(admin) as { pairingCode?: string }).pairingCode
    check('本机直连仍可读到配对码', typeof pairingCode === 'string')
    const claimed = await raw(base, '/api/pair/claim', {
      method: 'POST',
      headers: { ...tunnelHeaders, 'content-type': 'application/json', 'x-dsh-pocket-pin': PIN },
      body: JSON.stringify({ code: String(pairingCode), pairSecret: 'proxy-check-secret-0123456789', deviceName: 'Remote iPhone' }),
    })
    const claimBody = claimed.body
    check('隧道来的配对请求被接受', claimed.status === 202, `HTTP ${claimed.status}`)
    check('隧道来的配对请求保持 pending（未被自动确认）', claimBody.includes('"pending"'), claimBody.slice(0, 100))
    const pairingId = (JSON.parse(claimBody) as { pairingId?: string }).pairingId
    const polled = await raw(base, '/api/pair/poll', {
      method: 'POST',
      headers: { ...tunnelHeaders, 'content-type': 'application/json', 'x-dsh-pocket-pin': PIN },
      body: JSON.stringify({ pairingId: String(pairingId), pairSecret: 'proxy-check-secret-0123456789' }),
    })
    check('未确认前不下发令牌', polled.body.includes('"pending"'))
    check('未确认前不种设备 cookie', !polled.setCookie.some((entry) => entry.startsWith('dpm_device=')))

    // 6. The operator sitting at the machine is still allowed (the fix must not
    //    break the real workflow).
    const local = await raw(base, '/api/admin/session', { headers: { host: `127.0.0.1:${runtime.port}` } })
    check('本机直连（无代理头）仍可管理', local.status === 200, `HTTP ${local.status}`)

    // 7. A foreign-authority Host is still refused outright.
    const attacker = await raw(base, '/api/status', { headers: { host: 'attacker.example.com' } })
    check('未知 Host 仍被栅栏拒绝', attacker.status === 403, `HTTP ${attacker.status}`)

    await service.stop()
    check('退出后实时连接清空', service.sse.size === 0)
  } finally {
    await service.stop().catch(() => undefined)
    await rm(root, { recursive: true, force: true })
  }
  return results.filter((line) => line.startsWith('FAIL')).length
}

try {
  const failed = await main()
  report()
  process.exit(failed === 0 ? 0 : 1)
} catch (error) {
  report()
  process.stderr.write(`\n脚本自身失败：${error instanceof Error ? error.stack ?? error.message : String(error)}\n`)
  process.exit(1)
}
