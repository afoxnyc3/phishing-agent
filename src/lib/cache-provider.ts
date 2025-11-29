/**
 * Cache Provider Abstraction
 * Provides a unified interface for in-memory and Redis-backed caching.
 * Redis is optional - falls back to in-memory for single-instance deployments.
 */

import { securityLogger } from './logger.js';
import { config } from './config.js';

/**
 * Pipeline interface for batch operations (reduces round trips)
 */
export interface CachePipeline {
  zadd(key: string, score: number, member: string): this;
  zcount(key: string, min: number | string, max: number | string): this;
  zremrangebyscore(key: string, min: number | string, max: number | string): this;
  expire(key: string, seconds: number): this;
  set(key: string, value: string, ...options: string[]): this;
  get(key: string): this;
  exists(...keys: string[]): this;
  exec(): Promise<Array<[Error | null, unknown]>>;
}

/**
 * Cache provider interface for rate limiting and deduplication
 */
export interface CacheProvider {
  // Basic operations
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlMs?: number): Promise<void>;
  exists(key: string): Promise<boolean>;
  delete(key: string): Promise<void>;
  increment(key: string, ttlMs?: number): Promise<number>;
  isReady(): boolean;
  shutdown(): Promise<void>;

  // Sorted set operations (for sliding window rate limiting)
  zadd(key: string, score: number, member: string): Promise<number>;
  zcount(key: string, min: number | '-inf', max: number | '+inf'): Promise<number>;
  zremrangebyscore(key: string, min: number | '-inf', max: number): Promise<number>;

  // Atomic set-if-not-exists (for deduplication)
  setNX(key: string, value: string, ttlMs?: number): Promise<boolean>;

  // Key expiration
  expire(key: string, ttlSeconds: number): Promise<boolean>;

  // Pipeline for batch operations
  pipeline(): CachePipeline;
}

// Re-export implementations for backward compatibility
export { MemoryCacheProvider } from './memory-cache-provider.js';
export { RedisCacheProvider } from './redis-cache-provider.js';

// Singleton cache provider instance
let cacheProvider: CacheProvider | null = null;

/**
 * Create or return the cache provider instance (async)
 * Uses in-memory cache. For Redis, use createResilientCacheProvider() instead.
 */
export async function createCacheProvider(): Promise<CacheProvider> {
  if (cacheProvider) {
    return cacheProvider;
  }

  const redisUrl = config.redis.url;

  if (redisUrl) {
    securityLogger.info('Redis configured - use createResilientCacheProvider() for resilient mode');
  } else {
    securityLogger.info('Creating in-memory cache provider (Redis not configured)');
  }

  const { MemoryCacheProvider } = await import('./memory-cache-provider.js');
  cacheProvider = new MemoryCacheProvider();
  return cacheProvider;
}

/**
 * Create resilient cache provider (async initialization for Redis)
 * Returns ResilientCacheProvider if Redis configured, otherwise MemoryCacheProvider
 * @param redisUrl - Optional Redis URL (defaults to config.redis.url)
 * @param keyPrefix - Optional key prefix (defaults to config.redis.keyPrefix)
 */
export async function createResilientCacheProvider(
  redisUrl?: string,
  keyPrefix?: string
): Promise<CacheProvider> {
  if (cacheProvider) {
    return cacheProvider;
  }

  const url = redisUrl || config.redis.url;
  const prefix = keyPrefix || config.redis.keyPrefix;

  if (url) {
    const { ResilientCacheProvider } = await import('./resilient-cache-provider.js');
    securityLogger.info('Creating resilient cache provider (Redis with fallback)', { keyPrefix: prefix });
    cacheProvider = new ResilientCacheProvider(url, prefix);
  } else {
    const { MemoryCacheProvider } = await import('./memory-cache-provider.js');
    securityLogger.info('Creating in-memory cache provider (Redis not configured)');
    cacheProvider = new MemoryCacheProvider();
  }

  return cacheProvider;
}

/**
 * Get the current cache provider (must call createCacheProvider first)
 */
export async function getCacheProvider(): Promise<CacheProvider> {
  if (!cacheProvider) {
    return createCacheProvider();
  }
  return cacheProvider;
}

/**
 * Shutdown the cache provider gracefully
 */
export async function shutdownCacheProvider(): Promise<void> {
  if (cacheProvider) {
    await cacheProvider.shutdown();
    cacheProvider = null;
  }
}
