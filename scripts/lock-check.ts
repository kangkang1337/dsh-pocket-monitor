/**
 * Reproduce the reported crash: a phone request while devices.json is locked.
 *
 * Before the fix this raised an unhandled rejection inside the request handler
 * and main.ts's `uncaughtException` handler shut the whole service down. This
 * script asserts the opposite: the request still succeeds from memory, the
 * service stays up, and the failure is reported instead of thrown.
 */

import { mkdir, mkdtemp, open, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DeviceStore } from '../backend/src/auth/devices.ts'
import { PairingService } from '../backend/src/auth/pairing.ts'
import { MonitorService } from '../backend/src/server.ts'
import { resolveConfig } from '../backend/src/config.ts'
import { asSource } from '../backend/tests/helpers.ts'

/** Minimal stand-in for the DSH log source; this script tests the registry, not DSH. */
const fakeSource = asSource({
  snapshot: async () => ({
    payload: {
      generatedAt: Date.now(),
      source: {
        kind: 'dsh-session-log' as const,
        status: 'connected' as const,
        message: '锁文件测试用的假数据源',
        sessionsRoot: 'C:\\fake\\.dsh\\sessions',
        workspace: 'C:\\fake\\ws',
        lastScanAt: Date.now(),
        approvalWritable: false,
      },
      currentSessionId: 'lock-check',
      sessions: [],
      capabilities: { approvalDeciding: false, processView: false } as never,
    },
    sessions: new Map<string, unknown>(),
    currentSessionId: 'lock-check',
  }),
})

const results: string[] = []
const check = (label: string, ok: boolean, detail = ''): void => {
  results.push(`${ok ? 'PASS' : 'FAIL'}  ${label}${detail === '' ? '' : `  — ${detail}`}`)
}

function report(): void {
  process.stdout.write(`\n${results.join('\n')}\n`)
  const failed = results.filter((line) => line.startsWith('FAIL')).length
  process.stdout.write(`\n${results.length - failed}/${results.length} 项通过\n`)
}

async function main(): Promise<number> {
  const root = await mkdtemp(join(tmpdir(), 'dpm-lock-e2e-'))
  const dataDir = join(root, 'data')
  await mkdir(dataDir, { recursive: true })

  const config = resolveConfig({ host: '127.0.0.1', port: 0, dataDir, pollIntervalMs: 500 }, {}, root)
  const devices = new DeviceStore(dataDir, { inactivityDays: 30, touchFlushMs: 0 })
  await devices.load()
  const pairing = new PairingService({ ttlSeconds: 300, maxAttemptsPerIp: 8, attemptWindowSeconds: 300 })

  const token = 'lock-test-token-0123456789abcdef'
  const device = await devices.create({ name: 'iPhone', token, pairedFrom: '127.0.0.1' })

  const service = new MonitorService({
    config,
    devices,
    pairing,
    source: fakeSource,
    frontendDir: join(root, 'missing'),
  })
  try {
    const runtime = await service.start()
    const base = `http://127.0.0.1:${runtime.port}`
    const cookie = `dpm_device=${token}`

    const before = await fetch(`${base}/api/status`, { headers: { cookie } })
    check('锁文件之前：手机能读状态', before.status === 200, `HTTP ${before.status}`)

    // Simulate the reported failure mode: make the registry impossible to replace.
    await rm(join(dataDir, 'devices.json'), { force: true })
    await mkdir(join(dataDir, 'devices.json'))
    const locked = await open(join(dataDir, 'devices.json'), 'r').catch(() => undefined)

    const during = await fetch(`${base}/api/status`, { headers: { cookie } })
    check('锁文件期间：手机请求仍然成功（从内存读）', during.status === 200, `HTTP ${during.status}`)
    const health = await fetch(`${base}/api/health`)
    check('锁文件期间：服务仍然活着', health.ok, `HTTP ${health.status}`)

    await devices.flushPendingWrites()
    check(
      '写失败被记录到 lastPersistError',
      devices.lastPersistError !== undefined,
      String(devices.lastPersistError).slice(0, 60),
    )

    const admin = (await (await fetch(`${base}/api/admin/session`)).json()) as {
      deviceRetention?: { persistError?: string | null }
      devices?: readonly { status?: string }[]
    }
    check(
      '管理接口把写失败暴露给运维',
      (admin.deviceRetention?.persistError ?? null) !== null,
      String(admin.deviceRetention?.persistError).slice(0, 50),
    )
    check('管理接口仍能列出设备', (admin.devices?.length ?? 0) === 1)

    // A pairing attempt while the file is locked must be refused, not faked.
    await locked?.close().catch(() => undefined)
    let threw = false
    try {
      await devices.create({ name: '新手机', token: 'another-token-0123456789abcdef', pairedFrom: '127.0.0.1' })
    } catch {
      threw = true
    }
    check('锁文件期间：新配对明确失败（不假成功）', threw)
    check('失败的配对没有留在内存里', devices.list().length === 1, `设备数 ${devices.list().length}`)

    // Cleanup, then confirm the service is still serving and the registry recovers.
    await rm(join(dataDir, 'devices.json'), { recursive: true, force: true })
    await writeFile(join(dataDir, 'devices.json'), `${JSON.stringify({ version: 1, devices: [device] }, null, 2)}\n`, 'utf8')
    const after = await fetch(`${base}/api/status`, { headers: { cookie } })
    check('解锁之后：服务照常工作', after.status === 200, `HTTP ${after.status}`)

    await service.stop()
    check('退出时连接清空', service.sse.size === 0)
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
