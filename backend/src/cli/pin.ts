#!/usr/bin/env node
/**
 * `npm run pin` — show or rotate the public-access PIN.
 *
 * The PIN is the second factor a roaming phone presents alongside its device
 * token. It is stored as a hash, so it cannot be read back: this script either
 * reports that one exists (and which authority it is for), generates a new one,
 * or sets the one you pass.
 *
 * @module dsh-pocket-monitor/cli/pin
 */

import { parseCliOptions, resolveConfig } from '../config.ts'
import { PublicGate } from '../services/public-access.ts'

/** Entry point. */
async function main(): Promise<void> {
  const options = parseCliOptions(process.argv.slice(2))
  const config = resolveConfig(options)
  const requested = options.publicPin

  const gate = new PublicGate({
    enabled: true,
    ...(config.publicUrl === undefined ? {} : { publicUrl: config.publicUrl }),
    tls: config.tlsCertPath !== undefined && config.tlsKeyPath !== undefined,
    behindTlsTerminator: config.behindTlsTerminator,
    dataDir: config.dataDir,
    requirePin: true,
    localAuthorities: [],
  })

  // `load()` only generates when public mode is on and no PIN exists.
  const existing = await gate.load()
  if (requested !== undefined) {
    await gate.setPin(requested, false)
    process.stdout.write(`已设置新的公网访问 PIN：${requested}\n下次手机从新网络访问时输入它即可。\n`)
    return
  }

  if (!config.public) {
    process.stdout.write(
      [
        '当前没有启用公网模式（--public），所以不需要访问 PIN。',
        `已有的 PIN 记录：${gate.hasPin ? '有' : '无'}（文件：${gate.pinFilePath}）`,
        '',
      ].join('\n'),
    )
    return
  }

  if (existing !== undefined) {
    process.stdout.write(`首次生成访问 PIN：${existing}\n把它输入手机页面即可继续访问。\n`)
    return
  }
  if (gate.hasPin) {
    process.stdout.write(
      [
        'PIN 已存在，但只保存了哈希，无法显示原文。',
        `创建时间：${new Date(gate.pinCreatedAtValue).toLocaleString()}`,
        '想换一个就运行：npm run pin -- --public-pin 123456（或任意 4-12 位数字）',
        '',
      ].join('\n'),
    )
    return
  }
  process.stdout.write('没有启用 PIN 要求（--public-no-pin），任何持有设备令牌的客户端都能读取。\n')
}

await main()
