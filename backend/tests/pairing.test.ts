/**
 * Pairing and device-registry tests: one-time codes, expiry, attempt limits,
 * revocation, and the single token hand-over.
 *
 * @module dsh-pocket-monitor/tests/pairing.test
 */

import { strict as assert } from 'node:assert'
import { readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { test } from 'node:test'
import { DeviceStore, generateToken, hashToken, sanitiseDeviceName } from '../src/auth/devices.ts'
import { PairingService } from '../src/auth/pairing.ts'
import { tempDir } from './helpers.ts'

const T0 = 1_800_000_000_000

/** Build a pairing service with a deterministic window. */
function service(overrides: Partial<{ ttlSeconds: number; maxAttemptsPerIp: number; attemptWindowSeconds: number }> = {}): PairingService {
  return new PairingService({
    ttlSeconds: overrides.ttlSeconds ?? 300,
    maxAttemptsPerIp: overrides.maxAttemptsPerIp ?? 8,
    attemptWindowSeconds: overrides.attemptWindowSeconds ?? 300,
  })
}

/** Claim as a phone would. */
function claim(svc: PairingService, code: string, secret = 'phone-secret-value-1234', from = '192.168.1.20', now = T0) {
  return svc.claim({ code, pairSecret: secret, deviceName: 'iPhone', from }, now)
}

test('device tokens are hashed, compared safely, and revocable', async () => {
  const dir = await tempDir('dpm-devices-')
  try {
    const store = new DeviceStore(dir)
    await store.load()
    assert.equal(store.list().length, 0)

    const token = generateToken()
    assert.ok(token.length >= 40)
    assert.notEqual(hashToken(token), token)

    const device = await store.create({ name: '  iPhone 15  ', token, pairedFrom: '192.168.1.5', now: T0 })
    assert.equal(device.name, 'iPhone 15')
    assert.equal(device.revokedAt, undefined)

    const authenticated = await store.authenticate(token)
    assert.equal(authenticated?.id, device.id)
    assert.equal(await store.authenticate('wrong-token'), undefined)

    // Persisted with a hash, never the raw token.
    const raw = await readFile(join(dir, 'devices.json'), 'utf8')
    assert.ok(!raw.includes(token))
    assert.ok(raw.includes(hashToken(token)))

    const revoked = await store.revoke(device.id)
    assert.ok(revoked?.revokedAt !== undefined)
    assert.equal(await store.authenticate(token), undefined, 'a revoked token must stop working')
    assert.equal(store.listActive().length, 0)
    assert.equal((await store.revoke(device.id))?.revokedAt, revoked.revokedAt, 'revocation is idempotent')
    assert.equal(await store.revoke('nope'), undefined)

    const reloaded = new DeviceStore(dir)
    await reloaded.load()
    assert.equal(reloaded.list().length, 1)
    assert.equal(reloaded.listActive().length, 0)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('device names are sanitised and bounded', () => {
  assert.equal(sanitiseDeviceName('  iPhone\n15  '), 'iPhone 15')
  assert.equal(sanitiseDeviceName('\u0000\u0007'), '未命名设备')
  assert.equal(sanitiseDeviceName('x'.repeat(80)).length, 40)
})

test('pairing codes are one-time, desktop-confirmed, and hand the token over once', async () => {
  const svc = service()
  const session = svc.issue(T0, true)
  assert.match(session.code, /^\d{6}$/)
  assert.equal(svc.hasActiveCode(T0), true)

  // A wrong code never claims the live one.
  const wrong = claim(svc, '000000' === session.code ? '111111' : '000000')
  assert.equal(wrong.ok, false)

  const claimed = claim(svc, session.code)
  assert.ok(claimed.ok)
  assert.equal(svc.currentView(T0)?.claim?.status, 'pending')

  // The phone's poll says pending until the desktop decides.
  assert.deepEqual(svc.poll({ pairingId: session.id, pairSecret: 'phone-secret-value-1234' }, T0), { ok: true, state: 'pending' })

  // Polling with the wrong secret must not reveal anything.
  const forged = svc.poll({ pairingId: session.id, pairSecret: 'not-the-secret-value' }, T0)
  assert.equal(forged.ok, false)

  // A second anonymous claim cannot steal the pending request.
  const steal = claim(svc, session.code, 'attacker-secret-value-9999', '192.168.1.99')
  assert.equal(steal.ok, false)
  if (!steal.ok) assert.equal(steal.reason, 'already-claimed')

  const refused = svc.decide({ pairingId: session.id, nonce: 'wrong-nonce', approve: true }, T0)
  assert.equal(refused.ok, false)

  const decided = svc.decide({ pairingId: session.id, nonce: session.nonce, approve: true }, T0)
  assert.ok(decided.ok && decided.status === 'approved')
  const first = svc.poll({ pairingId: session.id, pairSecret: 'phone-secret-value-1234' }, T0)
  assert.ok(first.ok && first.state === 'approved')

  // The code is destroyed with the hand-over.
  assert.equal(svc.currentView(T0), undefined)
  assert.equal(svc.hasActiveCode(T0), false)
  const second = svc.poll({ pairingId: session.id, pairSecret: 'phone-secret-value-1234' }, T0)
  assert.equal(second.ok, false)
  assert.equal(claim(svc, session.code).ok, false, 'a used code must never pair again')
})

test('pairing codes expire and expired claims cannot be approved', () => {
  const svc = service({ ttlSeconds: 60 })
  const session = svc.issue(T0, true)
  assert.ok(claim(svc, session.code, 'phone-secret-value-1234', '192.168.1.20', T0 + 30_000).ok)

  const afterExpiry = T0 + 61_000
  assert.equal(svc.hasActiveCode(afterExpiry), false)
  const late = svc.decide({ pairingId: session.id, nonce: session.nonce, approve: true }, afterExpiry)
  assert.equal(late.ok, false)
  if (!late.ok) assert.match(late.reason, /过期/)

  const latePoll = svc.poll({ pairingId: session.id, pairSecret: 'phone-secret-value-1234' }, afterExpiry)
  assert.equal(latePoll.ok, false)
})

test('rejection is reported to the phone and the code stays unusable', () => {
  const svc = service()
  const session = svc.issue(T0, true)
  assert.ok(claim(svc, session.code).ok)
  const rejected = svc.decide({ pairingId: session.id, nonce: session.nonce, approve: false, reason: '不是我的手机' }, T0)
  assert.ok(rejected.ok && rejected.status === 'rejected')
  const poll = svc.poll({ pairingId: session.id, pairSecret: 'phone-secret-value-1234' }, T0)
  assert.equal(poll.ok, false)
  if (!poll.ok) {
    assert.equal(poll.reason, 'rejected')
    assert.equal(poll.message, '不是我的手机')
  }
})

test('failed claims are rate limited per source address', () => {
  const svc = service({ maxAttemptsPerIp: 3, attemptWindowSeconds: 300 })
  const session = svc.issue(T0, true)
  const bad = '111111' === session.code ? '222222' : '111111'
  assert.equal(claim(svc, bad).ok, false)
  assert.equal(claim(svc, bad).ok, false)
  assert.equal(claim(svc, bad).ok, false)
  const limited = claim(svc, bad)
  assert.equal(limited.ok, false)
  if (!limited.ok) assert.equal(limited.reason, 'rate-limited')

  // Even the correct code is refused from that address while the window is open,
  // and a different address is unaffected.
  const alsoLimited = claim(svc, session.code)
  assert.equal(alsoLimited.ok, false)
  assert.ok(claim(svc, session.code, 'phone-secret-value-1234', '192.168.1.21').ok)
})

test('issued tokens differ between pairings and cannot be re-issued', () => {
  const svc = service()
  const a = svc.issue(T0, true)
  assert.ok(claim(svc, a.code, 'phone-secret-value-aaaa').ok)
  const approvedA = svc.decide({ pairingId: a.id, nonce: a.nonce, approve: true }, T0)
  assert.ok(approvedA.ok && approvedA.status === 'approved')
  const tokenA = svc.poll({ pairingId: a.id, pairSecret: 'phone-secret-value-aaaa' }, T0)
  assert.ok(tokenA.ok && tokenA.state === 'approved')

  const b = svc.issue(T0 + 5_000, true)
  assert.notEqual(b.code === a.code, true, 'a new code should normally differ')
  assert.ok(claim(svc, b.code, 'phone-secret-value-bbbb').ok)
  const approvedB = svc.decide({ pairingId: b.id, nonce: b.nonce, approve: true }, T0 + 5_000)
  assert.ok(approvedB.ok && approvedB.status === 'approved')
  if (approvedA.ok && approvedA.status === 'approved' && approvedB.ok && approvedB.status === 'approved') {
    assert.notEqual(approvedA.token, approvedB.token)
  }

  const after = svc.poll({ pairingId: b.id, pairSecret: 'phone-secret-value-bbbb' }, T0 + 5_000)
  assert.ok(after.ok && after.state === 'approved')
  const again = svc.poll({ pairingId: b.id, pairSecret: 'phone-secret-value-bbbb' }, T0 + 5_000)
  assert.equal(again.ok, false, 'a token is handed over at most once')
})

test('invalidate and revokeAll drop every live pairing artefact', () => {
  const svc = service()
  const session = svc.issue(T0, true)
  assert.ok(claim(svc, session.code).ok)
  svc.revokeAll()
  assert.equal(svc.hasActiveCode(T0), false)
  assert.equal(svc.currentView(T0), undefined)
  assert.equal(svc.decide({ pairingId: session.id, nonce: session.nonce, approve: true }, T0).ok, false)

  const fresh = svc.issue(T0 + 10_000, true)
  svc.invalidate()
  assert.equal(svc.currentView(T0 + 10_000), undefined)
  assert.equal(fresh.code.length, 6)
})

// ── retention: inactivity expiry and cleanup ─────────────────────────────────

const DAY = 86_400_000

test('inactive devices expire, and their token stops working', async () => {
  const dir = await tempDir('dpm-expiry-')
  try {
    const store = new DeviceStore(dir, { inactivityDays: 30 })
    await store.load()
    const token = generateToken()
    const device = await store.create({ name: 'iPhone', token, now: T0 })

    // Fresh device: usable.
    assert.equal(store.classify(device, T0), 'active')
    assert.equal((await store.authenticate(token, T0))?.id, device.id)
    assert.equal(store.listActive(T0).length, 1)

    // Just before the deadline it still works; just after, the token is dead.
    // The window is measured from the latest successful use, which is exactly
    // what an inactivity policy means.
    const lastUse = store.get(device.id)?.lastSeenAt ?? T0
    assert.equal(store.classify(device, lastUse + 30 * DAY - 1_000), 'active')
    assert.equal(store.classify(device, lastUse + 30 * DAY + 1_000), 'expired')
    assert.equal(await store.authenticate(token, lastUse + 30 * DAY + 1_000), undefined, '过期后 token 必须失效')
    assert.equal(store.listActive(lastUse + 30 * DAY + 1_000).length, 0)
    // The first rejection records when the expiry was observed (audit trail).
    assert.equal(store.get(device.id)?.expiredAt, lastUse + 30 * DAY + 1_000)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a device is usable right up to its deadline, and dead after it', async () => {
  const dir = await tempDir('dpm-revive-')
  try {
    const store = new DeviceStore(dir, { inactivityDays: 10, revokedRetentionDays: 30 })
    await store.load()
    const token = generateToken()
    const device = await store.create({ name: 'iPhone', token, now: T0 })

    // Just inside the window: still usable, and using it moves the deadline.
    const nearDeadline = T0 + 10 * DAY - 1_000
    assert.equal((await store.authenticate(token, nearDeadline))?.id, device.id)
    assert.equal(store.get(device.id)?.lastSeenAt, nearDeadline)
    assert.equal(store.get(device.id)?.expiredAt, undefined, '窗口内使用不该留下过期标记')

    // Past the window: the token is dead. The record survives for the retention
    // period so the operator can see what happened, but coming back does NOT
    // revive it — an expired token must be re-paired (that is the point of a TTL).
    const afterDeadline = nearDeadline + 10 * DAY + 1_000
    assert.equal(await store.authenticate(token, afterDeadline), undefined)
    assert.equal(store.get(device.id)?.expiredAt, afterDeadline, '第一次观察到过期要记录下来')
    assert.equal(store.classify(store.get(device.id) as NonNullable<ReturnType<typeof store.get>>, afterDeadline), 'expired')

    // Even much later, while the record is still listed, the token stays dead.
    assert.equal(await store.authenticate(token, afterDeadline + 5 * DAY), undefined)
    assert.equal(store.list().length, 1, '保留期内记录仍可查看')

    // Once the retention window (started when it expired) elapses, the record is
    // removed by the sweep.
    const sweep = await store.sweep(afterDeadline + 30 * DAY + 1_000)
    assert.equal(sweep.removed, 1)
    assert.equal(store.list().length, 0)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('expiry can be disabled, and an observed expiry is recorded once', async () => {
  const dir = await tempDir('dpm-expiry-off-')
  try {
    const forever = new DeviceStore(dir, { inactivityDays: 0 })
    await forever.load()
    const longToken = generateToken()
    const longDevice = await forever.create({ name: 'iPhone', token: longToken, now: T0 })
    assert.equal(forever.expiryOf(longDevice, T0), undefined)
    assert.equal(forever.classify(longDevice, T0 + 3_650 * DAY), 'active')
    assert.equal((await forever.authenticate(longToken, T0 + 3_650 * DAY))?.id, longDevice.id)

    // With expiry on, the first rejected attempt records `expiredAt` so the
    // audit list can explain why the token stopped working.
    const strict = new DeviceStore(dir, { inactivityDays: 7 })
    await strict.load()
    const token = generateToken()
    const device = await strict.create({ name: 'iPad', token, now: T0 })
    assert.equal(device.expiredAt, undefined)
    assert.equal(await strict.authenticate(token, T0 + 8 * DAY), undefined)
    const after = strict.get(device.id)
    assert.ok(after?.expiredAt !== undefined, '观察到的过期要被记录下来')
    assert.equal(strict.classify(after, T0 + 8 * DAY), 'expired')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('sweep drops dead records only after their retention window', async () => {
  const dir = await tempDir('dpm-sweep-')
  try {
    // Inactivity 10 days, dead-record retention 30 days: a stale record stays
    // listed for 30 days *after it went stale*, so the operator can see it, and
    // is removed only once it is both expired and past that window.
    const store = new DeviceStore(dir, { inactivityDays: 10, revokedRetentionDays: 30 })
    await store.load()

    // Live device last used day 41 (so it is fresh at day 42); idle device last
    // used day 25 (so it went stale at day 35 — day 42 is inside retention);
    // revoked device at day 41.
    await store.create({ name: '在用的手机', token: generateToken(), now: T0 + 41 * DAY })
    await store.create({ name: '闲置的手机', token: generateToken(), now: T0 + 25 * DAY })
    const revoked = await store.create({ name: '刚撤销的手机', token: generateToken(), now: T0 + 41 * DAY })
    await store.revoke(revoked.id, T0 + 41 * DAY)

    // Day 42: the idle device is expired but well inside its retention window.
    const first = await store.sweep(T0 + 42 * DAY)
    assert.equal(first.expired, 1)
    assert.equal(first.removed, 0, '保留期内不该删')
    assert.equal(store.list().length, 3)
    assert.equal(store.listActive(T0 + 42 * DAY).length, 1, '只有在用的那台可用')

    // Day 80: the idle record went stale at day 35, so 30 days of retention are
    // up; the revoked record (day 41 + 30 = day 71) is past its window too.
    const second = await store.sweep(T0 + 80 * DAY)
    assert.equal(second.removed, 2, '过期/撤销且超过保留期的记录应被移除')
    const names = store.list().map((device) => device.name)
    assert.ok(!names.includes('闲置的手机'))
    assert.ok(!names.includes('刚撤销的手机'))
    assert.ok(names.includes('在用的手机'), '在用的设备不能被清掉')

    // Idempotent right away.
    assert.equal((await store.sweep(T0 + 80 * DAY)).removed, 0)
    assert.equal(store.list().length, 1)

    // Persisted across a reload.
    const reloaded = new DeviceStore(dir, { inactivityDays: 10, revokedRetentionDays: 30 })
    await reloaded.load()
    assert.equal(reloaded.list().length, 1)
    assert.equal(reloaded.list()[0]?.name, '在用的手机')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('batched last-seen updates stay off the per-request write path', async () => {
  const dir = await tempDir('dpm-touch-')
  try {
    const store = new DeviceStore(dir, { inactivityDays: 30, touchFlushMs: 60_000 })
    await store.load()
    const token = generateToken()
    const device = await store.create({ name: 'iPhone', token, now: T0 })

    // Many requests inside the flush window still update the in-memory value…
    for (let i = 1; i <= 5; i += 1) await store.authenticate(token, T0 + i * 1_000)
    assert.equal(store.get(device.id)?.lastSeenAt, T0 + 5_000)

    // …and the flush (also done on shutdown) makes it durable.
    await store.flushTouches(T0 + 5_500)
    const reloaded = new DeviceStore(dir, { inactivityDays: 30 })
    await reloaded.load()
    assert.equal(reloaded.get(device.id)?.lastSeenAt, T0 + 5_000)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
