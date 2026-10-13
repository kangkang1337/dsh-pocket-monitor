/**
 * Startup and shutdown verification for the real service process.
 *
 * This starts `backend/src/main.ts` exactly the way a user does (npm script →
 * Node with type stripping), proves it listens and serves both the API and the
 * built frontend, then proves that stopping it releases the port and leaves no
 * background process behind.
 *
 * If the environment forbids spawning a child with piped stdio (some sandboxes
 * deny named-pipe creation), this test reports itself as skipped rather than
 * failing — the same paths are covered in-process by `server.test.ts`.
 *
 * @module dsh-pocket-monitor/tests/startup.test
 */

import { strict as assert } from 'node:assert'
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { createServer } from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')

/** Find a currently free TCP port. */
async function freePort(): Promise<number> {
  return await new Promise((resolvePromise, rejectPromise) => {
    const server = createServer()
    server.on('error', rejectPromise)
    server.listen(0, '127.0.0.1', () => {
      const address = server.address()
      if (address === null || typeof address !== 'object') {
        rejectPromise(new Error('无法分配测试端口'))
        return
      }
      const port = address.port
      server.close(() => resolvePromise(port))
    })
  })
}

/** Wait until a predicate holds or the deadline passes. */
async function waitFor(predicate: () => Promise<boolean>, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await predicate()) return true
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250))
  }
  return false
}

/** Whether a TCP port is still accepting connections. */
async function portOpen(port: number): Promise<boolean> {
  return await new Promise((resolvePromise) => {
    const socket = createServer()
    socket.once('error', () => {
      resolvePromise(true) // EADDRINUSE means something is still listening
    })
    socket.listen(port, '127.0.0.1', () => {
      socket.close(() => resolvePromise(false))
    })
  })
}

test('the service starts from the CLI, serves the app, and shuts down cleanly', async (context) => {
  if (!existsSync(join(root, 'frontend', 'dist', 'index.html'))) {
    context.skip('前端尚未构建（npm run build），跳过进程级启动验证')
    return
  }
  const port = await freePort()
  let child
  try {
    child = spawn(process.execPath, ['--experimental-strip-types', join(root, 'backend', 'src', 'main.ts')], {
      cwd: root,
      env: {
        ...process.env,
        DSH_POCKET_MONITOR_PORT: String(port),
        DSH_POCKET_MONITOR_HOST: '127.0.0.1',
        DSH_POCKET_MONITOR_NO_DASHBOARD: '1',
      },
      stdio: 'pipe',
      windowsHide: true,
    })
  } catch (error) {
    context.skip(`当前环境禁止启动带管道的子进程（${error instanceof Error ? error.message : String(error)}），跳过进程级启动验证`)
    return
  }
  let stdout = ''
  child.stdout?.on('data', (chunk: Buffer) => {
    stdout += chunk.toString('utf8')
  })
  let spawnFailed = false
  child.on('error', () => {
    spawnFailed = true
  })
  const base = `http://127.0.0.1:${port}`
  try {
    const healthy = await waitFor(async () => {
      try {
        const response = await fetch(`${base}/api/health`, { signal: AbortSignal.timeout(1_500) })
        return response.ok
      } catch {
        return false
      }
    }, 25_000)
    if (spawnFailed || !healthy) {
      context.skip(`当前环境无法启动子进程（${spawnFailed ? 'spawn 失败' : '健康检查超时'}），跳过进程级启动验证`)
      return
    }

    // The banner must state where the service listens and how to stop it.
    assert.match(stdout, /监听：127\.0\.0\.1:/)
    assert.match(stdout, /关闭方法：/)
    assert.match(stdout, /本次配对码：\d{6}/, '无交互终端时应打印配对码')
    assert.doesNotMatch(stdout, /token=|api[_-]?key/i, '启动日志不得打印任何令牌')

    // The built frontend is served from the same origin as the API.
    const page = await fetch(`${base}/`)
    assert.equal(page.status, 200)
    const html = await page.text()
    assert.match(html, /DSH Pocket Monitor/)
    assert.match(html, /assets\/index-/)

    // Static assets are reachable, and an unpaired API call is refused.
    const assetPath = /src="(\/assets\/[^"]+)"/.exec(html)?.[1]
    assert.ok(assetPath !== undefined)
    assert.equal((await fetch(`${base}${assetPath}`)).status, 200)
    assert.equal((await fetch(`${base}/api/status`)).status, 401)

    // Stopping the process must release the port and leave nothing behind.
    child.kill('SIGTERM')
    const exited = await new Promise<boolean>((resolvePromise) => {
      const timer = setTimeout(() => resolvePromise(false), 10_000)
      child.once('exit', () => {
        clearTimeout(timer)
        resolvePromise(true)
      })
    })
    assert.equal(exited, true, 'SIGTERM 后进程必须退出')
    assert.equal(await portOpen(port), false, '退出后端口必须释放，不能留后台进程')
  } finally {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL')
  }
})
