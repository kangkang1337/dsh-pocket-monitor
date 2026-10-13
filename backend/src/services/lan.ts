/**
 * Local IPv4 address detection for LAN mode.
 *
 * Binding `0.0.0.0` does not by itself restrict anything — the README explains
 * why the monitor still checks Host/Origin and authentication. This module only
 * answers "which addresses could a phone on the same Wi-Fi reach".
 *
 * @module dsh-pocket-monitor/services/lan
 */

import { networkInterfaces, type NetworkInterfaceInfo } from 'node:os'

/** One candidate LAN address. */
export interface LanAddress {
  readonly address: string
  readonly iface: string
  readonly netmask: string
  /** Interface-level classification for the operator. */
  readonly kind: 'ethernet' | 'wifi' | 'virtual' | 'other'
}

/** Guess the interface kind from its Windows/Unix name. */
export function classifyInterface(name: string): LanAddress['kind'] {
  const lower = name.toLowerCase()
  if (/wi-?fi|wlan|wireless/.test(lower)) return 'wifi'
  if (/ethernet|eth\d|en\d|local area connection/.test(lower)) return 'ethernet'
  if (/vethernet|hyper-v|vmware|virtualbox|loopback|docker|wsl|tailscale|zerotier|tap|tun/.test(lower)) return 'virtual'
  return 'other'
}

/**
 * Enumerate non-internal IPv4 addresses.
 *
 * @param interfaces - interface table (injected for tests).
 * @returns candidates, virtual adapters last and stable by address.
 */
export function listLanAddresses(
  interfaces: NodeJS.Dict<NetworkInterfaceInfo[]> = networkInterfaces(),
): LanAddress[] {
  const candidates: LanAddress[] = []
  for (const [name, entries] of Object.entries(interfaces)) {
    if (entries === undefined) continue
    for (const entry of entries) {
      if (entry.family !== 'IPv4' || entry.internal) continue
      candidates.push({ address: entry.address, iface: name, netmask: entry.netmask, kind: classifyInterface(name) })
    }
  }
  const rank: Record<LanAddress['kind'], number> = { wifi: 0, ethernet: 1, other: 2, virtual: 3 }
  candidates.sort((a, b) => rank[a.kind] - rank[b.kind] || a.address.localeCompare(b.address))
  return candidates
}

/**
 * Pick the address most likely reachable from a phone.
 *
 * @param candidates - address list.
 * @returns the preferred address, or undefined when the machine has none.
 */
export function preferredLanAddress(candidates: readonly LanAddress[]): LanAddress | undefined {
  return candidates[0]
}

/** Whether an IP literal is a private (RFC1918/CGNAT) address. */
export function isPrivateAddress(address: string): boolean {
  const parts = address.split('.').map(Number)
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false
  const [a, b] = parts
  if (a === 10) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  return false
}
