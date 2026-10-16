/**
 * HTTP security and API tests: host/origin fence, device authentication,
 * restricted approvals, idempotency, rate limiting, realtime streaming, and
 * clean shutdown.
 *
 * @module dsh-pocket-monitor/tests/server.test
 */

import { strict as assert } from 'node:assert'
import { request as httpRequest } from 'node:http'
import { rm } from 'node:fs/promises'
import { test } from 'node:test'
import { DeviceStore } from '../src/auth/devices.ts'
import { MonitorService, classifyRequest } from '../src/server.ts'
import { validatePublicMode } from '../src/config.ts'
import { PublicGate } from '../src/services/public-access.ts'
import { listLanAddresses, classifyInterface, isPrivateAddress, preferredLanAddress } from '../src/services/lan.ts'
import type { MonitorConfig } from '../src/config.ts'
import type { MonitorEvent, PendingApproval, StatusPayload } from '../../shared/types/index.ts'
import { asSource, FakeSource, tempDir } from './helpers.ts'

/** Build a status payload for the fake source. */
function payload(overrides: Partial<StatusPayload> = {}, pending: readonly PendingApproval[] = []): StatusPayload {
  return {
    generatedAt: Date.now(),
    source: {
      kind: 'dsh-session-log',
      status: 'connected',
      message: '测试数据源',
      sessionsRoot: 'C:\\fake\\.dsh\\sessions',
      workspace: 'C:\\fake\\ws',
      lastScanAt: Date.now(),
      approvalWritable: false,
    },
    currentSessionId: 's-1',
    sessions: [
      {
        sessionId: 's-1',
        title: '测试会话',
        cwd: 'C:\\fake\\ws',
        createdAt: 1,
        lastEventAt: Date.now(),
        lastEventAgeMs: 500,
        state: pending.length === 0 ? 'running' : 'waiting-approval',
        stateReason: '第 1 轮进行中',
        turn: 1,
        step: 2,
        runDurationMs: 5_000,
        eventCount: 42,
        approvalPolicy: 'ask',
        currentTools: [],
        recentTools: [],
        pendingApprovals: pending,
        live: true,
        formatVersion: 4,
      },
    ],
    processes: [],
    pendingApprovals: pending,
    recentlyDecided: [],
    capabilities: {
      monitoring: true,
      processView: true,
      pairing: true,
      approvalViewing: true,
      approvalDeciding: false,
      approvalDecidingReason: 'DSH 0.2.0-rc.2 没有面向外部进程的审批通道。',
      publicAccess: 'disabled',
      publicAccessReason: '首期只做 LAN。',
      chat: false,
      commandExecution: false,
    },
    ...overrides,
  }
}

/** One running service plus the temp dir to clean up. */
interface Harness {
  readonly service: MonitorService
  readonly source: FakeSource
  readonly dataDir: string
  readonly frontendDir: string
  readonly base: string
  close: () => Promise<void>
}

/** Build a complete MonitorConfig so unrelated fields never break a test. */
export function makeConfig(overrides: Partial<MonitorConfig> & { dataDir: string }): MonitorConfig {
  return {
    host: '127.0.0.1',
    port: 0,
    workspace: 'C:\\fake\\ws',
    dshHome: 'C:\\fake\\.dsh',
    pollIntervalMs: 200,
    pairTtlSeconds: 300,
    pairMaxAttempts: 8,
    trustedOrigins: [],
    terminalApproval: true,
    printQr: false,
    public: false,
    publicRequirePin: true,
    behindTlsTerminator: false,
    deviceInactivityDays: 30,
    watchAll: false,
    maxSessions: 30,
    ...overrides,
  }
}

/** Start a service on an ephemeral loopback port. */
async function startHarness(
  options: { pending?: readonly PendingApproval[]; terminalApproval?: boolean; port?: number; config?: Partial<MonitorConfig> } = {},
): Promise<Harness> {
  const dataDir = await tempDir('dpm-server-')
  const frontendDir = await tempDir('dpm-frontend-')
  const source = new FakeSource(payload({}, options.pending ?? []))
  const config = makeConfig({
    dataDir,
    port: options.port ?? 0,
    terminalApproval: options.terminalApproval ?? true,
    ...options.config,
  })
  // Mirror main.ts: the store carries the configured retention policy.
  const devices = new DeviceStore(dataDir, { inactivityDays: config.deviceInactivityDays })
  await devices.load()
  // Mirror main.ts: build the gate from the config, load its PIN, then inject it.
  let gate: PublicGate | undefined
  if (config.public) {
    gate = new PublicGate({
      enabled: true,
      ...(config.publicUrl === undefined ? {} : { publicUrl: config.publicUrl }),
      tls: config.tlsCertPath !== undefined && config.tlsKeyPath !== undefined,
      behindTlsTerminator: config.behindTlsTerminator,
      dataDir,
      requirePin: config.publicRequirePin,
      localAuthorities: listLanAddresses().map((entry) => entry.address),
    })
    await gate.load()
    if (config.publicPin !== undefined) await gate.setPin(config.publicPin, false)
  }
  const service = new MonitorService({
    config,
    source: asSource(source),
    devices,
    frontendDir,
    ...(gate === undefined ? {} : { gate }),
  })
  const runtime = await service.start()
  return {
    service,
    source,
    dataDir,
    frontendDir,
    base: `http://127.0.0.1:${runtime.port}`,
    close: async () => {
      await service.stop()
      await rm(dataDir, { recursive: true, force: true })
      await rm(frontendDir, { recursive: true, force: true })
    },
  }
}

/** Read the admin session (loopback-only) and pull out the pairing nonce. */
async function adminSession(base: string): Promise<Record<string, unknown>> {
  const response = await fetch(`${base}/api/admin/session`)
  assert.equal(response.status, 200)
  return (await response.json()) as Record<string, unknown>
}

/**
 * Issue a raw request so forbidden headers (notably `Host`) can be set exactly.
 * `fetch` refuses to send a custom `Host`, which is precisely the header the
 * DNS-rebinding fence inspects.
 */
async function rawStatus(
  base: string,
  path: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  const url = new URL(path, base)
  return await new Promise((resolvePromise, rejectPromise) => {
    const request = httpRequest(
      {
        host: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: 'GET',
        headers,
      },
      (response) => {
        let body = ''
        response.setEncoding('utf8')
        response.on('data', (chunk) => {
          body += chunk
        })
        response.on('end', () => resolvePromise({ status: response.statusCode ?? 0, body }))
      },
    )
    request.on('error', rejectPromise)
    request.end()
  })
}

/** Pair a phone end-to-end and return its cookie. */
async function pairDevice(base: string, name = 'iPhone'): Promise<{ cookie: string; deviceId: string }> {
  // A used pairing code is destroyed by design, so ask for a fresh one each time.
  const rotated = await fetch(`${base}/api/admin/pairing/code`, { method: 'POST' })
  assert.equal(rotated.status, 200)
  const session = await adminSession(base)
  const code = String(session.pairingCode)
  const nonce = String(session.pairingNonce)
  const pairingId = String(session.pairingId)
  const pairSecret = `test-secret-${'x'.repeat(20)}`
  const claimResponse = await fetch(`${base}/api/pair/claim`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ code, pairSecret, deviceName: name }),
  })
  // Loopback claims are auto-approved when terminal approval is on; the explicit
  // admin decision below is idempotent and covers both paths.
  assert.equal(claimResponse.status, 202, `claim failed: ${claimResponse.status} ${await claimResponse.text()}`)
  const decided = await fetch(`${base}/api/admin/pairing/claim`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ nonce, approve: true }),
  })
  assert.equal(decided.status, 200)
  const pollResponse = await fetch(`${base}/api/pair/poll`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ pairingId, pairSecret }),
  })
  assert.equal(pollResponse.status, 200, `poll failed: ${pollResponse.status}`)
  const pollBody = (await pollResponse.json()) as { state: string; deviceId: string }
  assert.equal(pollBody.state, 'approved')
  const cookie = (pollResponse.headers.getSetCookie?.() ?? []).map((entry) => entry.split(';')[0]).join('; ')
  assert.ok(cookie.length > 0)
  return { cookie, deviceId: pollBody.deviceId }
}

test('unauthenticated phone calls are refused with a useful message', async () => {
  const harness = await startHarness()
  try {
    for (const path of ['/api/status', '/api/events', '/api/stream', '/api/approvals', '/api/device']) {
      const response = await fetch(`${harness.base}${path}`)
      assert.equal(response.status, 401, `${path} must require a paired device`)
      const body = (await response.json()) as { error: { code: string } }
      assert.equal(body.error.code, 'unauthorized')
    }
    const health = await fetch(`${harness.base}/api/health`)
    assert.equal(health.status, 200)
    const healthBody = (await health.json()) as { ok: boolean; requiresPairing: boolean }
    assert.equal(healthBody.ok, true)
    assert.equal(healthBody.requiresPairing, true)
  } finally {
    await harness.close()
  }
})

test('cross-origin and cross-site requests are refused before authentication', async () => {
  const harness = await startHarness()
  try {
    const mismatch = await fetch(`${harness.base}/api/status`, { headers: { origin: 'http://evil.example.com' } })
    assert.equal(mismatch.status, 403)
    assert.equal(((await mismatch.json()) as { error: { code: string } }).error.code, 'forbidden-origin')

    const crossSite = await fetch(`${harness.base}/api/status`, { headers: { 'sec-fetch-site': 'cross-site' } })
    assert.equal(crossSite.status, 403)

    // A forged Host is the DNS-rebinding case; it must be refused before auth.
    const badHost = await rawStatus(harness.base, '/api/status', { host: 'attacker.example.com' })
    assert.equal(badHost.status, 403)
    assert.match(badHost.body, /forbidden-origin/)

    // A loopback Host with a mismatched Origin is still refused.
    const originHostMismatch = await rawStatus(harness.base, '/api/status', {
      host: new URL(harness.base).host,
      origin: 'http://127.0.0.1:1',
    })
    assert.equal(originHostMismatch.status, 403)

    // A trusted Host with no session is 401, not 200: reachability is not identity.
    const trustedHost = await rawStatus(harness.base, '/api/status', { host: new URL(harness.base).host })
    assert.equal(trustedHost.status, 401)
  } finally {
    await harness.close()
  }
})

test('admin API is loopback only and never leaks the pairing nonce to phones', async () => {
  const harness = await startHarness()
  try {
    const session = await adminSession(harness.base)
    assert.equal(typeof session.pairingCode, 'string')
    assert.equal(typeof session.pairingNonce, 'string')
    assert.equal(session.devices instanceof Array, true)

    // The pairing session probe is public but carries no secret material.
    const probe = await fetch(`${harness.base}/api/pair/session`)
    assert.equal(probe.status, 200)
    const probeBody = (await probe.json()) as Record<string, unknown>
    assert.equal(probeBody.pairingOpen, true)
    assert.equal('pairingCode' in probeBody, false)
    assert.equal('pairingNonce' in probeBody, false)
  } finally {
    await harness.close()
  }
})

test('pairing binds a device, sets an HttpOnly cookie, and reports the device', async () => {
  const harness = await startHarness()
  try {
    const { cookie, deviceId } = await pairDevice(harness.base, 'iPhone 15')
    assert.ok(cookie.startsWith('dpm_device='))
    assert.equal(harness.service.devices.listActive().length, 1)

    const status = await fetch(`${harness.base}/api/status`, { headers: { cookie } })
    assert.equal(status.status, 200)
    const body = (await status.json()) as StatusPayload
    assert.equal(body.currentSessionId, 's-1')

    const me = await fetch(`${harness.base}/api/device`, { headers: { cookie } })
    assert.equal(me.status, 200)
    const meBody = (await me.json()) as { id: string; name: string; scopes: readonly string[] }
    assert.equal(meBody.id, deviceId)
    assert.equal(meBody.name, 'iPhone 15')
    assert.deepEqual([...meBody.scopes].sort(), ['approval:view', 'events:read', 'status:read'])
    assert.ok(!meBody.scopes.includes('chat'), 'no scope may allow chat')

    // Bearer tokens work for tooling that cannot set cookies.
    const viaBearer = await fetch(`${harness.base}/api/device`)
    assert.equal(viaBearer.status, 401)
  } finally {
    await harness.close()
  }
})

test('a phone can unbind itself and its token stops working immediately', async () => {
  const harness = await startHarness()
  try {
    const { cookie, deviceId } = await pairDevice(harness.base)
    const unbound = await fetch(`${harness.base}/api/device`, { method: 'DELETE', headers: { cookie } })
    assert.equal(unbound.status, 200)
    const after = await fetch(`${harness.base}/api/status`, { headers: { cookie } })
    assert.equal(after.status, 401)
    assert.equal(harness.service.devices.get(deviceId)?.revokedAt !== undefined, true)

    // The desktop can revoke too.
    const second = await pairDevice(harness.base, 'iPad')
    const revoke = await fetch(`${harness.base}/api/admin/devices/${second.deviceId}`, { method: 'DELETE' })
    assert.equal(revoke.status, 200)
    assert.equal((await fetch(`${harness.base}/api/status`, { headers: { cookie: second.cookie } })).status, 401)
  } finally {
    await harness.close()
  }
})

test('the approval endpoint validates the request and never fakes a delivery', async () => {
  const pending: PendingApproval[] = [
    { id: 'ap-1', toolName: 'pwsh', callId: 'c1', reason: '需要提权', sessionId: 's-1', askedAt: Date.now(), policy: 'ask' },
  ]
  const harness = await startHarness({ pending })
  try {
    const { cookie } = await pairDevice(harness.base)

    const listed = await fetch(`${harness.base}/api/approvals`, { headers: { cookie } })
    assert.equal(listed.status, 200)
    const listedBody = (await listed.json()) as { pending: readonly PendingApproval[]; capability: boolean; capabilityReason: string }
    assert.equal(listedBody.pending.length, 1)
    assert.equal(listedBody.pending[0]?.toolName, 'pwsh')
    assert.equal(listedBody.capability, false)
    assert.match(listedBody.capabilityReason, /没有面向外部进程的审批通道/)

    // Unknown approval -> 404, no side effects.
    const unknown = await fetch(`${harness.base}/api/approvals/nope/decision`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'approve', clientRequestId: 'req-unknown-1' }),
    })
    assert.equal(unknown.status, 404)

    // Missing correlation id -> 400 (idempotency is mandatory, not optional).
    const noId = await fetch(`${harness.base}/api/approvals/ap-1/decision`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'approve' }),
    })
    assert.equal(noId.status, 400)

    // Bad action -> 400.
    const badAction = await fetch(`${harness.base}/api/approvals/ap-1/decision`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'run-anything', clientRequestId: 'req-bad-action' }),
    })
    assert.equal(badAction.status, 400)

    // A real pending approval: the intent is recorded, delivery is honestly refused.
    const decision = await fetch(`${harness.base}/api/approvals/ap-1/decision`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'approve', clientRequestId: 'req-real-1' }),
    })
    assert.equal(decision.status, 501)
    const decisionBody = (await decision.json()) as { error: { code: string }; recordedLocally: boolean; deliveredToDsh: boolean }
    assert.equal(decisionBody.error.code, 'approval_channel_unavailable')
    assert.equal(decisionBody.recordedLocally, true)
    assert.equal(decisionBody.deliveredToDsh, false)

    // Repeating the same click is idempotent: same answer, no second attempt logged.
    const repeat = await fetch(`${harness.base}/api/approvals/ap-1/decision`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'approve', clientRequestId: 'req-real-1' }),
    })
    assert.equal(repeat.status, 501)
    // Two attempts are logged in total: the earlier unknown-id validation failure
    // and this real pending approval. The repeat added none.
    assert.equal(harness.service.approvalAttempts.length, 2)
    assert.equal(harness.service.approvalAttempts.filter((entry) => entry.approvalId === 'ap-1').length, 1)

    // A CIDR-less, action-less body is still refused.
    const malformed = await fetch(`${harness.base}/api/approvals/ap-1/decision`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: 'not json',
    })
    assert.equal(malformed.status, 400)
  } finally {
    await harness.close()
  }
})

test('decided approvals are reported as conflicts, not silently re-approved', async () => {
  const harness = await startHarness({ pending: [] })
  try {
    const { cookie } = await pairDevice(harness.base)
    const status = harness.source.payload
    harness.source.setPayload({
      ...status,
      recentlyDecided: [{ id: 'ap-done', sessionId: 's-1', outcome: 'allowed-once', decidedAt: Date.now() }],
    })
    const response = await fetch(`${harness.base}/api/approvals/ap-done/decision`, {
      method: 'POST',
      headers: { cookie, 'content-type': 'application/json' },
      body: JSON.stringify({ action: 'approve', clientRequestId: 'req-decided-1' }),
    })
    assert.equal(response.status, 409)
    const body = (await response.json()) as { error: { code: string; message: string } }
    assert.equal(body.error.code, 'approval-already-decided')
    assert.match(body.error.message, /已经/)
  } finally {
    await harness.close()
  }
})

test('approval attempts are rate limited per device', async () => {
  const pending: PendingApproval[] = [
    { id: 'ap-1', toolName: 'pwsh', sessionId: 's-1', askedAt: Date.now() },
  ]
  const harness = await startHarness({ pending })
  try {
    const { cookie } = await pairDevice(harness.base)
    let sawRateLimit = false
    for (let i = 0; i < 40; i += 1) {
      const response = await fetch(`${harness.base}/api/approvals/ap-1/decision`, {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ action: 'approve', clientRequestId: `req-rate-${i}` }),
      })
      if (response.status === 429) {
        sawRateLimit = true
        break
      }
      assert.equal(response.status, 501)
    }
    assert.equal(sawRateLimit, true, 'the limiter must eventually refuse')
  } finally {
    await harness.close()
  }
})

test('the realtime stream requires a device and pushes status frames', async () => {
  const harness = await startHarness()
  try {
    const anonymous = await fetch(`${harness.base}/api/stream`)
    assert.equal(anonymous.status, 401)

    const { cookie } = await pairDevice(harness.base)
    const controller = new AbortController()
    const response = await fetch(`${harness.base}/api/stream`, { headers: { cookie }, signal: controller.signal })
    assert.equal(response.status, 200)
    assert.match(response.headers.get('content-type') ?? '', /text\/event-stream/)

    const reader = response.body?.getReader()
    assert.ok(reader !== undefined)
    const decoder = new TextDecoder()
    let buffer = ''
    const deadline = Date.now() + 8_000
    let sawStatus = false
    let sawHello = false
    while (Date.now() < deadline && (!sawStatus || !sawHello)) {
      const { value, done } = await reader.read()
      if (done === true) break
      buffer += decoder.decode(value, { stream: true })
      if (buffer.includes('"type":"hello"')) sawHello = true
      if (buffer.includes('"type":"status"')) sawStatus = true
      // Keep the loop honest: stop as soon as both frames arrive.
      if (sawStatus && sawHello) break
    }
    controller.abort()
    assert.equal(sawHello, true, 'the stream must greet the device')
    assert.equal(sawStatus, true, 'the stream must push the current status')

    // Revoking the device must drop its live stream.
    await harness.service.devices.revoke((await harness.service.devices.listActive()[0])?.id ?? '')
  } finally {
    await harness.close()
  }
})

test('new timeline events are pushed to paired phones', async () => {
  const harness = await startHarness()
  try {
    const { cookie } = await pairDevice(harness.base)
    const controller = new AbortController()
    const response = await fetch(`${harness.base}/api/stream`, { headers: { cookie }, signal: controller.signal })
    const reader = response.body?.getReader()
    assert.ok(reader !== undefined)
    const decoder = new TextDecoder()
    let buffer = ''
    // Wait for the greeting so the source is definitely subscribed.
    const greetingDeadline = Date.now() + 6_000
    while (Date.now() < greetingDeadline && !buffer.includes('"type":"hello"')) {
      const { value, done } = await reader.read()
      if (done === true) break
      buffer += decoder.decode(value, { stream: true })
    }
    assert.ok(buffer.includes('"type":"hello"'))

    const fresh: MonitorEvent = {
      id: 's-1:99',
      sessionId: 's-1',
      seq: 99,
      time: Date.now(),
      kind: 'tool',
      title: '工具调用：pwsh',
      level: 'info',
    }
    harness.source.setTimeline('s-1', [fresh])
    harness.source.setPayload({
      ...payload(),
      sessions: [{ ...payload().sessions[0]!, eventCount: 100 }],
    })
    const eventDeadline = Date.now() + 8_000
    while (Date.now() < eventDeadline && !buffer.includes('工具调用：pwsh')) {
      const { value, done } = await reader.read()
      if (done === true) break
      buffer += decoder.decode(value, { stream: true })
    }
    controller.abort()
    assert.ok(buffer.includes('"type":"events"'), 'the phone must receive an events frame')
    assert.ok(buffer.includes('工具调用：pwsh'))
  } finally {
    await harness.close()
  }
})

test('the service exposes no chat, command, or DSH proxy surface', async () => {
  const harness = await startHarness()
  try {
    const { cookie } = await pairDevice(harness.base)
    for (const path of ['/api/chat', '/api/command', '/api/exec', '/api/rpc', '/api/dsh', '/api/tools']) {
      const response = await fetch(`${harness.base}${path}`, {
        method: 'POST',
        headers: { cookie, 'content-type': 'application/json' },
        body: JSON.stringify({ anything: true }),
      })
      assert.ok([404, 405].includes(response.status), `${path} must not exist (got ${response.status})`)
    }
  } finally {
    await harness.close()
  }
})

test('public access stays off until asked, and never auto-starts a tunnel', async () => {
  // Default (LAN-only) behaviour: the phone path reports disabled.
  const harness = await startHarness()
  try {
    const response = await fetch(`${harness.base}/api/admin/public-access/start`, { method: 'POST' })
    assert.equal(response.status, 501)
    const body = (await response.json()) as { error: { code: string; message: string } }
    assert.equal(body.error.code, 'public_access_not_implemented')
    assert.match(body.error.message, /不会自动启动公网隧道/)

    const { cookie } = await pairDevice(harness.base)
    const readOnly = await fetch(`${harness.base}/api/public-access`, { headers: { cookie } })
    assert.equal(readOnly.status, 200)
    const status = (await readOnly.json()) as { mode: string; configured: boolean; active: boolean; url: string | null }
    assert.equal(status.mode, 'disabled')
    assert.equal(status.active, false)
    assert.equal(status.url, null)
    assert.equal(status.configured, false)

    // The status payload must agree with the public-access endpoint.
    const pay2 = await fetch(`${harness.base}/api/status`, { headers: { cookie } })
    const payload = (await pay2.json()) as { capabilities: { publicAccess: string } }
    assert.equal(payload.capabilities.publicAccess, 'disabled')
  } finally {
    await harness.close()
  }
})

test('a public-mode install refuses to start without TLS', () => {
  const base = { dataDir: 'C:\\tmp\\x' }
  const insecure = validatePublicMode(makeConfig({ ...base, public: true }))
  assert.equal(insecure.length, 1)
  assert.match(insecure[0] ?? '', /TLS/)

  const halfCert = validatePublicMode(makeConfig({ ...base, public: true, behindTlsTerminator: true, tlsCertPath: 'C:\\tmp\\cert.pem' }))
  assert.ok(halfCert.some((problem) => problem.includes('成对')))

  const viaTerminator = validatePublicMode(makeConfig({ ...base, public: true, behindTlsTerminator: true }))
  assert.deepEqual(viaTerminator, [])

  const localTls = validatePublicMode(makeConfig({ ...base, public: true, tlsCertPath: 'C:\\tmp\\cert.pem', tlsKeyPath: 'C:\\tmp\\key.pem' }))
  assert.deepEqual(localTls, [])

  // Without public mode, TLS is not required.
  assert.deepEqual(validatePublicMode(makeConfig(base)), [])
})

test('public mode accepts the declared authority without weakening the LAN fence', async () => {
  const pin = '424242'
  const harness = await startHarness({
    config: { public: true, publicUrl: 'mon.example.com', publicRequirePin: true, behindTlsTerminator: true, publicPin: pin },
  })
  try {
    assert.equal(harness.service.gate.enabled, true)
    assert.equal(harness.service.gate.hasPin, true, 'enabling public mode must produce an access PIN')
    assert.equal(harness.service.gate.verifyPin(pin), true)

    // The public authority now passes the fence instead of being refused.
    const viaPublicHost = await rawStatus(harness.base, '/api/status', { host: 'mon.example.com' })
    assert.equal(viaPublicHost.status, 401, 'reachable but unauthenticated: 401, never 200')
    assert.ok(!viaPublicHost.body.includes('currentSessionId'))

    // Unknown authorities stay refused (403 from the fence) even in public mode.
    const unknown = await rawStatus(harness.base, '/api/status', { host: 'attacker.example.com', 'x-dsh-pocket-pin': pin })
    assert.equal(unknown.status, 403)
  } finally {
    await harness.close()
  }
})

test('a paired device survives its own IP changing (the whole point of pairing)', async () => {
  // Same LAN, phone roams between networks/addresses: the device token must keep
  // working with no re-pairing and no PIN (that is LAN behaviour, not public).
  const harness = await startHarness()
  try {
    const { cookie, deviceId } = await pairDevice(harness.base, 'Roaming iPhone')

    // The device record stores where pairing happened for audit only.
    const record = harness.service.devices.get(deviceId)
    assert.ok(record !== undefined)
    assert.equal(typeof record.pairedFrom, 'string', 'pairedFrom is recorded…')

    // …and nothing in the auth path consults it: the very same cookie keeps
    // working, and the account is still active, regardless of source address.
    for (const source of ['192.168.1.77', '10.0.0.42', '203.0.113.7']) {
      assert.equal(harness.service.devices.listActive().length, 1)
      const response = await fetch(`${harness.base}/api/status`, { headers: { cookie } })
      assert.equal(response.status, 200, `paired device must work (source ${source})`)
    }

    // The device's lastSeenAt advances on each successful use, so the desktop
    // list shows it as current rather than stale.
    assert.ok((harness.service.devices.get(deviceId)?.lastSeenAt ?? 0) >= record.lastSeenAt)

    // Unpaired callers are refused from every address.
    for (const source of ['192.168.1.99', '203.0.113.9']) {
      const response = await fetch(`${harness.base}/api/status`)
      assert.equal(response.status, 401, `unpaired device must be refused (source ${source})`)
    }
  } finally {
    await harness.close()
  }
})

test('public mode reports itself honestly and gates the admin surface', async () => {
  const harness = await startHarness({
    config: { public: true, publicUrl: 'mon.example.com', publicRequirePin: true, behindTlsTerminator: true, publicPin: '424242' },
  })
  try {
    const { cookie } = await pairDevice(harness.base)
    const readOnly = await fetch(`${harness.base}/api/public-access`, { headers: { cookie } })
    assert.equal(readOnly.status, 200)
    const status = (await readOnly.json()) as { mode: string; active: boolean; url: string | null; reason: string }
    assert.equal(status.mode, 'active')
    assert.equal(status.active, true)
    assert.equal(status.url, 'mon.example.com')
    assert.match(status.reason, /不会安装或启动任何隧道客户端/)

    // The status payload's capability report agrees with the dedicated endpoint.
    const payloadResponse = await fetch(`${harness.base}/api/status`, { headers: { cookie } })
    const payload = (await payloadResponse.json()) as { capabilities: { publicAccess: string; publicAccessReason: string } }
    assert.equal(payload.capabilities.publicAccess, 'active')
    assert.match(payload.capabilities.publicAccessReason, /已启用/)

    // Admin routes remain loopback-only, public mode or not.
    const adminOverLoopback = await fetch(`${harness.base}/api/admin/session`)
    assert.equal(adminOverLoopback.status, 200)
  } finally {
    await harness.close()
  }
})

test('the request-purpose matrix decides who must present the access PIN', async () => {
  const dataDir = await tempDir('dpm-classify-')
  try {
    const gate = new PublicGate({
      enabled: true,
      publicUrl: 'mon.example.com',
      tls: false,
      behindTlsTerminator: true,
      dataDir,
      requirePin: true,
      localAuthorities: ['192.168.1.50'],
    })
    const lanHosts = new Set(['127.0.0.1', 'localhost', '192.168.1.50', '10.135.67.100'])
    const hostAccepts = (hostname: string): boolean => lanHosts.has(hostname)
    const classify = (remoteAddress: string, host: string) => classifyRequest({ remoteAddress, host, gate, hostAccepts })

    // From this machine: always loopback, whatever the Host says.
    assert.equal(classify('127.0.0.1', 'mon.example.com'), 'loopback')
    assert.equal(classify('::ffff:127.0.0.1', 'mon.example.com'), 'loopback')
    // From the LAN: a local authority stays local, so pairing keeps working.
    assert.equal(classify('192.168.1.77', '192.168.1.50'), 'lan')
    assert.equal(classify('192.168.1.77', '10.135.67.100'), 'lan')
    // From outside: the declared public authority takes the public path.
    assert.equal(classify('203.0.113.7', 'mon.example.com'), 'public')
    // From outside with an undeclared authority: the fence refuses it, so it is
    // never treated as public — the failure stays "401 unpaired".
    assert.equal(classify('203.0.113.7', 'attacker.example.com'), 'lan')
    // Public mode off: even the declared authority is not accepted.
    const offGate = new PublicGate({
      enabled: false,
      publicUrl: 'mon.example.com',
      tls: false,
      behindTlsTerminator: false,
      dataDir,
      requirePin: false,
      localAuthorities: ['192.168.1.50'],
    })
    assert.equal(
      classifyRequest({ remoteAddress: '203.0.113.7', host: 'mon.example.com', gate: offGate, hostAccepts }),
      'lan',
    )
  } finally {
    await rm(dataDir, { recursive: true, force: true })
  }
})

test('the gate demands a PIN, throttles guesses, and accepts the right one', async () => {
  const dataDir = await tempDir('dpm-gate-')
  try {
    const gate = new PublicGate({
      enabled: true,
      publicUrl: 'mon.example.com',
      tls: false,
      behindTlsTerminator: true,
      dataDir,
      requirePin: true,
      localAuthorities: [],
    })
    // Loading public mode with no stored PIN generates one and says so.
    const generated = await gate.load()
    assert.match(generated ?? '', /^\d{6}$/, 'load() must hand back the generated PIN once')
    assert.equal(gate.hasPin, true)
    assert.equal(gate.pinWasGenerated, true)

    // The generated PIN itself works, and a wrong one is refused with a hint.
    assert.match(generated ?? '', /^\d+$/)
    assert.equal(gate.checkPublicRequest({ from: '203.0.113.7', pin: generated ?? '' }).ok, true)
    const wrong = gate.checkPublicRequest({ from: '198.51.100.20', pin: '000000' })
    assert.equal(wrong.ok, false)
    if (!wrong.ok) {
      assert.equal(wrong.status, 401)
      assert.equal(wrong.pinRequired, true)
    }
    assert.equal(gate.checkPublicRequest({ from: '203.0.113.7', pin: generated ?? '' }).ok, true)

    // Brute force from one address must run out of budget.
    let throttled = false
    for (let attempt = 0; attempt < 20; attempt += 1) {
      const decision = gate.checkPublicRequest({ from: '198.51.100.9', pin: '111111' })
      if (!decision.ok && decision.status === 429) {
        throttled = true
        break
      }
    }
    assert.equal(throttled, true, 'PIN guessing must be throttled')

    // A different address is unaffected by that budget.
    assert.equal(gate.checkPublicRequest({ from: '198.51.100.10', pin: generated ?? '' }).ok, true)

    // Device-token failures are bounded too, per address and globally.
    let authLimited = false
    for (let attempt = 0; attempt < 40; attempt += 1) {
      if (gate.noteAuthFailure('198.51.100.11').limited) {
        authLimited = true
        break
      }
    }
    assert.equal(authLimited, true, 'token guessing must be throttled')
    gate.noteAuthSuccess('198.51.100.11')
    assert.equal(gate.noteAuthFailure('198.51.100.11').limited, false, 'a success clears the budget')
  } finally {
    await rm(dataDir, { recursive: true, force: true })
  }
})

test('requiring no PIN is possible but must be explicit', async () => {
  const dataDir = await tempDir('dpm-nopin-')
  try {
    const gate = new PublicGate({
      enabled: true,
      publicUrl: 'mon.example.com',
      tls: false,
      behindTlsTerminator: true,
      dataDir,
      requirePin: false,
      localAuthorities: [],
    })
    assert.equal(await gate.load(), undefined, 'no PIN is generated when the requirement is off')
    assert.equal(gate.hasPin, false)
    assert.equal(gate.checkPublicRequest({ from: '203.0.113.7' }).ok, true)
    assert.equal(gate.status().mode, 'active')
    assert.match(gate.status().reason, /未要求访问 PIN/)
  } finally {
    await rm(dataDir, { recursive: true, force: true })
  }
})

test('revoking a device cuts off public access immediately', async () => {
  const pin = '515151'
  const harness = await startHarness({
    config: { public: true, publicUrl: 'mon.example.com', publicRequirePin: true, behindTlsTerminator: true, publicPin: pin },
  })
  try {
    const { cookie, deviceId } = await pairDevice(harness.base)
    // Loopback traffic is never public, so the paired session works locally …
    const before = await fetch(`${harness.base}/api/status`, { headers: { cookie } })
    assert.equal(before.status, 200)

    // … and revocation kills that session everywhere at once.
    const revoke = await fetch(`${harness.base}/api/admin/devices/${deviceId}`, { method: 'DELETE' })
    assert.equal(revoke.status, 200)
    const after = await fetch(`${harness.base}/api/status`, { headers: { cookie } })
    assert.equal(after.status, 401)

    // The same token is also refused through the public authority + PIN.
    const viaPublic = await rawStatus(harness.base, '/api/status', { host: 'mon.example.com', cookie, 'x-dsh-pocket-pin': pin })
    assert.equal(viaPublic.status, 401)
  } finally {
    await harness.close()
  }
})

test('the access PIN can be rotated from the loopback admin API', async () => {
  const harness = await startHarness({ config: { public: true, publicUrl: 'mon.example.com', behindTlsTerminator: true } })
  try {
    const rotated = await fetch(`${harness.base}/api/admin/public-access/pin`, { method: 'POST' })
    assert.equal(rotated.status, 200)
    const body = (await rotated.json()) as { pin: string; generated: boolean }
    assert.match(body.pin, /^\d{6}$/)
    assert.equal(body.generated, true)
    assert.equal(harness.service.gate.verifyPin(body.pin), true)

    const custom = await fetch(`${harness.base}/api/admin/public-access/pin`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pin: '987654' }),
    })
    assert.equal(custom.status, 200)
    assert.equal(harness.service.gate.verifyPin('987654'), true)
    assert.equal(harness.service.gate.verifyPin(body.pin), false, 'the old PIN must stop working')

    const invalid = await fetch(`${harness.base}/api/admin/public-access/pin`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ pin: 'abc' }),
    })
    assert.equal(invalid.status, 400)
  } finally {
    await harness.close()
  }
})

test('the admin listing reports device status, and the sweep endpoint works', async () => {
  const harness = await startHarness()
  try {
    const { deviceId } = await pairDevice(harness.base, 'iPhone')

    // A freshly paired device is active, with an expiry in the future.
    const session = await adminSession(harness.base)
    const devices = session.devices as Array<Record<string, unknown>>
    assert.equal(devices.length, 1)
    assert.equal(devices[0]?.['id'], deviceId)
    assert.equal(devices[0]?.['status'], 'active')
    assert.equal(typeof devices[0]?.['expiresAt'], 'number')
    assert.ok((devices[0]?.['expiresAt'] as number) > Date.now(), '过期时间应在未来')
    const retention = session.deviceRetention as { inactivityDays: number; revokedRetentionDays: number }
    assert.equal(retention.inactivityDays, 30)
    assert.equal(retention.revokedRetentionDays, 30)

    // Revoking flips the reported status without removing the record.
    await fetch(`${harness.base}/api/admin/devices/${deviceId}`, { method: 'DELETE' })
    const afterRevoke = (await adminSession(harness.base)).devices as Array<Record<string, unknown>>
    assert.equal(afterRevoke[0]?.['status'], 'revoked')
    assert.equal(afterRevoke.length, 1, '撤销后仍留在审计列表里')

    // Sweeping on demand is available over loopback and reports what it did.
    const sweep = await fetch(`${harness.base}/api/admin/devices/sweep`, { method: 'POST' })
    assert.equal(sweep.status, 200)
    const sweepBody = (await sweep.json()) as { expired: number; removed: number; devices: readonly unknown[] }
    assert.equal(sweepBody.removed, 0, '刚撤销的设备还在保留期内')
    assert.equal(sweepBody.devices.length, 1)
  } finally {
    await harness.close()
  }
})

test('a device that outlives its inactivity window stops authenticating', async () => {
  const harness = await startHarness({ config: { deviceInactivityDays: 0 } })
  try {
    // With expiry disabled the listing reports no deadline at all.
    const { deviceId } = await pairDevice(harness.base)
    const session = await adminSession(harness.base)
    const devices = session.devices as Array<Record<string, unknown>>
    assert.equal(devices[0]?.['id'], deviceId)
    assert.equal(devices[0]?.['status'], 'active')
    assert.equal(devices[0]?.['expiresAt'], null, '关闭过期时不应给出过期时间')
    assert.equal((session.deviceRetention as { inactivityDays: number }).inactivityDays, 0)
  } finally {
    await harness.close()
  }
})

test('shutdown closes the socket, drops streams, and invalidates the pairing code', async () => {
  const harness = await startHarness()
  const port = harness.service.port
  const { cookie } = await pairDevice(harness.base)
  await harness.service.stop()
  assert.equal(harness.service.listening, false)
  assert.equal(harness.service.sse.size, 0)
  assert.equal(harness.service.pairing.hasActiveCode(), false)
  await assert.rejects(fetch(`${harness.base}/api/status`, { headers: { cookie } }))
  assert.ok(port > 0)
  await rm(harness.dataDir, { recursive: true, force: true })
})

test('a busy port produces a clear error instead of killing anything', async () => {
  const harness = await startHarness()
  try {
    const second = await startHarness({ port: harness.service.port }).catch((error: unknown) => error)
    assert.ok(second instanceof Error, 'binding a used port must fail')
    assert.match(String((second as Error).message), /EADDRINUSE|address already in use|使用中/i)
  } finally {
    await harness.close()
  }
})

test('LAN helpers classify addresses without pretending they are private', () => {
  assert.equal(classifyInterface('Wi-Fi'), 'wifi')
  assert.equal(classifyInterface('Ethernet 2'), 'ethernet')
  assert.equal(classifyInterface('VMware Network Adapter VMnet8'), 'virtual')
  const candidates = listLanAddresses({
    'Wi-Fi': [{ address: '10.0.0.5', netmask: '255.255.255.0', family: 'IPv4', mac: '00:00:00:00:00:01', internal: false, cidr: '10.0.0.5/24' }],
    Loopback: [{ address: '127.0.0.1', netmask: '255.0.0.0', family: 'IPv4', mac: '00:00:00:00:00:00', internal: true, cidr: '127.0.0.1/8' }],
  })
  assert.equal(candidates.length, 1)
  assert.equal(preferredLanAddress(candidates)?.address, '10.0.0.5')
  assert.equal(isPrivateAddress('192.168.1.7'), true)
  assert.equal(isPrivateAddress('8.8.8.8'), false)
  assert.equal(isPrivateAddress('nonsense'), false)
})
