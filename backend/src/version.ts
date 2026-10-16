/**
 * Version resolution for this project.
 *
 * The version lives in `package.json`; nothing should hard-code it, because a
 * stale string is exactly the kind of quiet lie this project avoids elsewhere.
 *
 * @module dsh-pocket-monitor/version
 */

import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/** Fallback when `package.json` cannot be read (e.g. a repackaged build). */
const FALLBACK_VERSION = '0.0.0'

let cached: string | undefined

/**
 * Read this project's version from `package.json`.
 *
 * @returns the version string, or a `0.0.0` fallback.
 */
export async function readVersion(): Promise<string> {
  if (cached !== undefined) return cached
  const here = dirname(fileURLToPath(import.meta.url))
  // `backend/src/version.ts` → project root is two levels up; tolerate a built
  // layout by also trying three levels.
  for (const candidate of [resolve(here, '../../package.json'), resolve(here, '../../../package.json')]) {
    try {
      const parsed: unknown = JSON.parse(await readFile(candidate, 'utf8'))
      if (typeof parsed === 'object' && parsed !== null) {
        const version = (parsed as { version?: unknown }).version
        if (typeof version === 'string' && version !== '') {
          cached = version
          return version
        }
      }
    } catch {
      /* try the next candidate */
    }
  }
  cached = FALLBACK_VERSION
  return cached
}
