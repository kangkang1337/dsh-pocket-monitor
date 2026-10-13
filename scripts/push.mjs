#!/usr/bin/env node
/**
 * `npm run push` — push this repo to GitHub on machines whose network needs the
 * SSH-over-443 workaround documented in `.ssh-local/README.md`.
 *
 * On a normal network this is just `git push`, so the script only adds the
 * workaround when the wrapper is actually present.
 */

import { existsSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const wrapper = join(root, '.ssh-local', 'ssh-wrapper.cmd')
const knownHosts = join(root, '.ssh-local', 'known_hosts')

if (!existsSync(wrapper)) {
  process.stdout.write('没有 .ssh-local/ssh-wrapper.cmd，直接按普通方式推送。\n')
}

if (existsSync(wrapper) && !existsSync(knownHosts)) {
  process.stderr.write(
    [
      '',
      '缺少 .ssh-local/known_hosts（GitHub 的 SSH 主机密钥）——没有它推送会卡在主机密钥确认上。',
      '先执行一次：',
      '',
      '  ssh -o UserKnownHostsFile=".\\.ssh-local\\known_hosts" -o StrictHostKeyChecking=accept-new -T git@github.com',
      '',
      '（看到 “successfully authenticated” 即成功；GitHub 不提供 shell，所以退出码非 0 是正常的。）',
      '',
    ].join('\n'),
  )
  process.exit(1)
}

const env = { ...process.env }
if (existsSync(wrapper)) env.GIT_SSH = wrapper

process.stdout.write(`git push（GIT_SSH=${env.GIT_SSH ?? '未设置'}）\n`)
const result = spawnSync('git', ['push', ...process.argv.slice(2)], { cwd: root, env, stdio: 'inherit' })
process.exit(result.status ?? 1)
