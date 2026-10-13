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
