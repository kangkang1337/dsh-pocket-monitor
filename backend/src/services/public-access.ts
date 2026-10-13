/**
 * Public-access mode B: reserved interface, deliberately not implemented.
 *
 * The first release is LAN-only. These functions exist so the architecture has a
 * single seam for a future opt-in tunnel, and so every caller gets an explicit,
 * honest "not implemented" answer instead of a fake success. They never install,
 * download, start or configure anything, and they never touch the firewall.
 *
 * @module dsh-pocket-monitor/services/public-access
 */

import type { PublicAccessStatus } from '../../../shared/types/index.ts'

/** The one status this build can ever report. */
const DISABLED_STATUS: PublicAccessStatus = {
  mode: 'disabled',
  configured: false,
  active: false,
  url: null,
  reason:
    '首期只支持 LAN 局域网访问：公网模式 B 仅预留接口，未实现，也不会自动安装或启动任何隧道客户端，不会修改防火墙或路由器配置。',
}

/**
 * Read the current public-access status.
 *
 * @returns always the disabled/not-configured status in this build.
 */
export function getPublicAccessStatus(): PublicAccessStatus {
  return DISABLED_STATUS
}

/** Error thrown by the reserved mode-B entry points. */
export class PublicAccessNotImplementedError extends Error {
  readonly code = 'public_access_not_implemented'

  constructor(operation: string) {
    super(`${operation} 尚未实现：本版本只支持 LAN 局域网访问（模式 B 仅预留接口）。`)
    this.name = 'PublicAccessNotImplementedError'
  }
}

/**
 * Reserved mode-B entry point.
 *
 * @param _options - future tunnel options; ignored by this build.
 * @throws always, with an explicit not-implemented error.
 */
export function startPublicAccess(_options?: unknown): never {
  throw new PublicAccessNotImplementedError('startPublicAccess')
}

/**
 * Reserved mode-B entry point.
 *
 * @throws always, with an explicit not-implemented error.
 */
export function stopPublicAccess(): never {
  throw new PublicAccessNotImplementedError('stopPublicAccess')
}
