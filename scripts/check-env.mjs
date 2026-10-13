#!/usr/bin/env node
/**
 * Environment check for DSH Pocket Monitor.
 *
 * Non-destructive and side-effect free: it only reports what is missing, so a
 * `npm install` never silently fails because of the environment, and a
 * `npm run start:lan` can tell the operator exactly what to fix.
 *
 * Run directly:  node scripts/check-env.mjs
 * Strict mode:   node scripts/check-env.mjs --strict   (exit 1 on problems)
 */

import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { networkInterfaces } from 'node:os'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const strict = process.argv.includes('--strict')
const problems = []
const notes = []

const [major, minor] = process.versions.node.split('.').map(Number)
if (major < 22 || (major === 22 && minor < 6)) {
  problems.push(`Node 版本过低：当前 ${process.versions.node}，需要 >= 22.6（本项目用 Node 内置 TypeScript 类型剥离运行后端，不额外引入加载器）。`)
} else {
  notes.push(`Node ${process.versions.node} 可用（>= 22.6，支持 --experimental-strip-types）。`)
}

const rootModules = join(root, 'node_modules')
const frontendModules = join(root, 'frontend', 'node_modules')
if (!existsSync(rootModules)) problems.push('根目录依赖未安装，请先运行 npm install。')
if (!existsSync(frontendModules) && !existsSync(join(rootModules, 'vite'))) {
  problems.push('前端依赖未安装（npm workspaces 应把 vite/vue 装在根 node_modules），请先运行 npm install。')
}

const frontendDist = join(root, 'frontend', 'dist', 'index.html')
if (!existsSync(frontendDist)) {
  problems.push('前端还没有构建：正式运行前请执行 npm run build（或开发时用 npm run dev）。')
} else {
  notes.push('前端构建产物存在：frontend/dist/index.html。')
}

if (existsSync(join(root, 'package.json'))) {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
  if (typeof pkg.version === 'string') notes.push(`项目版本：${pkg.version}。`)
}

const home = process.env.USERPROFILE ?? process.env.HOME ?? ''
const dshHome = process.env.DSH_HOME ?? (home === '' ? '' : join(home, '.dsh'))
if (dshHome === '' || !existsSync(dshHome)) {
  problems.push(`没有找到 DSH Home（${dshHome || '未知'}）。如果你把 DSH_HOME 设到别处，请用 --dsh-home 参数或 DSH_HOME 环境变量指定。`)
} else if (!existsSync(join(dshHome, 'sessions'))) {
  notes.push(`DSH Home 下还没有 sessions 目录（${join(dshHome, 'sessions')}）——DSH 还没在这个工作目录里跑过时是正常的，服务仍会启动并等待日志出现。`)
} else {
  notes.push(`DSH 会话日志根目录：${join(dshHome, 'sessions')}`)
}

const lan = Object.entries(networkInterfaces())
  .flatMap(([name, entries]) => (entries ?? []).filter((e) => e.family === 'IPv4' && !e.internal).map((e) => `${e.address} (${name})`))
if (lan.length === 0) {
  problems.push('没有检测到局域网 IPv4 地址：手机将无法访问，只能在本机用 127.0.0.1 打开。')
} else {
  notes.push(`局域网地址候选：${lan.join('，')}`)
}

const print = (title, items) => {
  if (items.length === 0) return
  process.stdout.write(`\n${title}\n`)
  for (const item of items) process.stdout.write(`  · ${item}\n`)
}

process.stdout.write('DSH Pocket Monitor 环境检查\n')
print('正常', notes)
print('需要注意', problems)

if (problems.length === 0) {
  process.stdout.write('\n下一步：npm run build && npm run start:lan\n')
} else {
  process.stdout.write('\n请先解决上面的问题，再运行 npm run start:lan。\n')
}

if (strict && problems.length > 0) process.exitCode = 1
