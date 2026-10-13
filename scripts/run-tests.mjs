#!/usr/bin/env node
/**
 * In-process test runner for DSH Pocket Monitor.
 *
 * `node --test` spawns one child process per test file, and child-process spawn
 * with piped stdio is blocked in sandboxed environments (Windows named-pipe
 * creation is denied). This runner imports the very same `node:test` files into
 * one process — they register and run exactly as under `node --test` — and hooks
 * the runner's own exit so the summary and the exit code are always honest.
 * `npm run test:node` keeps the standard runner for environments that can spawn.
 *
 * Set `DSH_POCKET_MONITOR_TEST_VERBOSE=1` to also see the raw TAP stream.
 */

import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const testsDir = join(root, 'backend', 'tests')
const only = process.argv.slice(2).filter((arg) => !arg.startsWith('-'))
const verbose = process.env.DSH_POCKET_MONITOR_TEST_VERBOSE === '1'

const files = readdirSync(testsDir)
  .filter((name) => name.endsWith('.test.ts'))
  .filter((name) => only.length === 0 || only.some((pattern) => name.includes(pattern)))
  .sort()

if (files.length === 0) {
  process.stdout.write('没有找到测试文件。\n')
  process.exit(1)
}

/** Count top-level `test(...)` cases declared in one test file's source. */
function countCases(source) {
  return source.split('\n').filter((line) => /^test(\.\w+)?\(/.test(line.trim())).length
}

let expected = 0
const perFile = []
for (const name of files) {
  const count = countCases(readFileSync(join(testsDir, name), 'utf8'))
  expected += count
  perFile.push({ name, count, seen: 0 })
}

/** Totals parsed from the runner's own TAP stream. */
const totals = { pass: 0, fail: 0, skipped: 0, todo: 0, failedNames: [] }

// Mirror and, in quiet mode, suppress the runner's TAP output.
const stdoutWrite = process.stdout.write.bind(process.stdout)
const stderrWrite = process.stderr.write.bind(process.stderr)
const observe = (text) => {
  const nameMatch = /^\s*not ok \d+ - (.*)$/.exec(text.replace(/\r?\n$/, ''))
  if (nameMatch !== null) totals.failedNames.push(nameMatch[1])
  const countMatch = /^# (pass|fail|skipped|todo) (\d+)$/.exec(text.trim())
  if (countMatch !== null) totals[countMatch[1]] = Number(countMatch[2])
}
const shouldSuppress = (text) => {
  const trimmed = text.trimStart()
  if (trimmed === '' || trimmed.startsWith('#')) return !trimmed.startsWith('# fail') && !trimmed.startsWith('# pass')
  return trimmed.startsWith('ok ') || trimmed.startsWith('not ok ') || trimmed.startsWith('TAP version') || trimmed.startsWith('  ') || trimmed.startsWith('...') || trimmed.startsWith('---')
}

process.stdout.write = (chunk, encoding, callback) => {
  const text = typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString(encoding === 'buffer' ? 'utf8' : (encoding ?? 'utf8'))
  observe(text)
  if (verbose || !shouldSuppress(text)) return stdoutWrite(chunk, encoding, callback)
  if (typeof callback === 'function') callback()
  return true
}
process.stderr.write = (chunk, encoding, callback) => {
  const text = typeof chunk === 'string' ? chunk : Buffer.from(chunk).toString('utf8')
  observe(text)
  if (verbose) return stderrWrite(chunk, encoding, callback)
  stderrWrite(chunk, encoding, callback)
  return true
}

const started = performance.now()
let summarised = false

/** Print the summary once, derived from the runner's own counters. */
function summarise() {
  if (summarised) return
  summarised = true
  const ms = Math.round(performance.now() - started)
  process.stdout.write = stdoutWrite
  process.stderr.write = stderrWrite
  const body = [
    '',
    `测试文件 ${files.length} 个（源码声明用例 ${expected} 个）`,
    `通过 ${totals.pass}，失败 ${totals.fail}，跳过 ${totals.skipped}，待办 ${totals.todo}（${ms} ms）`,
  ]
  if (totals.failedNames.length > 0) {
    body.push('失败用例：')
    for (const name of totals.failedNames.slice(0, 20)) body.push(`  ✗ ${name}`)
  }
  if (totals.pass + totals.fail + totals.skipped + totals.todo < expected) {
    body.push('注意：实际用例数少于源码声明的数量，可能有用例没有执行。')
  }
  stdoutWrite.call(process.stdout, `${body.join('\n')}\n`)
}

/** How many cases the runner reported in total. */
function reported() {
  return totals.pass + totals.fail + totals.skipped + totals.todo
}

/** Whether the run is not clean: failures, or silently missing cases. */
function notClean() {
  return totals.fail > 0 || reported() < expected
}

const realExit = process.exit.bind(process)
process.exit = (code) => {
  summarise()
  realExit(notClean() ? 1 : (code ?? 0))
}

process.on('exit', () => {
  summarise()
  if (notClean()) process.exitCode = 1
})

for (const name of files) {
  await import(pathToFileURL(join(testsDir, name)).href)
}
