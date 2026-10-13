#!/usr/bin/env node
/**
 * Development helper: prints the two dev commands and, when possible, runs the
 * Vite dev server (which proxies `/api` to the backend) next to the backend.
 *
 * Run the backend with `npm run dev:backend` in one terminal and this Vite
 * server in another — that keeps Ctrl+C meaningful for each one and avoids
 * leaving a background process behind. This script is the convenience path for
 * environments that allow spawning children.
 *
 * @module dsh-pocket-monitor/scripts/dev
 */

import { existsSync } from 'node:fs'
import { spawn } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const port = process.env.DSH_POCKET_MONITOR_PORT ?? '3099'
const vite = join(root, 'node_modules', 'vite', 'bin', 'vite.js')

process.stdout.write(
  [
    '',
    `开发模式：Vite 会在 5173 起前端，并把 /api 代理到后端的 ${port} 端口。`,
    '如果后端还没启动，请在另一个终端执行：',
    `  set DSH_POCKET_MONITOR_PORT=${port} && npm run dev:backend`,
    '',
  ].join('\n'),
)

if (!existsSync(vite)) {
  process.stdout.write('没有找到 vite，请先运行 npm install。\n')
  process.exit(1)
}

const child = spawn(process.execPath, [vite, '--host'], {
  cwd: join(root, 'frontend'),
  stdio: 'inherit',
  env: { ...process.env, DSH_POCKET_MONITOR_PORT: port },
})

child.on('exit', (code) => {
  process.exit(code ?? 0)
})

const stop = () => {
  child.kill()
  process.exit(0)
}
process.on('SIGINT', stop)
process.on('SIGTERM', stop)
