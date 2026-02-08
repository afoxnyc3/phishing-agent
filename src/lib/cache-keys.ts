/**
 * Cache Key Versioning
 * Provides versioned key prefixes for all cache entries.
 * Bump CACHE_SCHEMA_VERSION when cache key computation changes
 * to prevent stale data issues during rolling deployments.
 */

/** Current cache schema version */
const CACHE_SCHEMA_VERSION = 1;

/** Build a versioned cache key */
export function versionedKey(namespace: string, key: string): string {
  return `v${CACHE_SCHEMA_VERSION}:${namespace}:${key}`;
}

/** Specific key builders for each subsystem */
export const CacheKeys = {
  dedup: {
    hash: (hash: string) => versionedKey('dedup', `hash:${hash}`),
    sender: (sender: string) => versionedKey('dedup', `sender:${sender}`),
  },
  rateLimit: {
    timestamps: (key: string) => versionedKey('rate', `timestamps:${key}`),
    circuit: (key: string) => versionedKey('rate', `circuit:${key}`),
  },
  circuitBreaker: {
    state: (name: string) => versionedKey('cb', `state:${name}`),
    failures: (name: string) => versionedKey('cb', `failures:${name}`),
  },
} as const;
