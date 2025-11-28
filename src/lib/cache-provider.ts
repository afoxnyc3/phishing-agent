/**
 * Cache Provider Abstraction
 * Provides a unified interface for in-memory and Redis-backed caching.
 * Redis is optional - falls back to in-memory for single-instance deployments.
 */

import { Redis } from 'ioredis';
import { securityLogger } from './logger.js';
import { config } from './config.js';

/**
 * Cache provider interface for rate limiting and deduplication
 */
export interface CacheProvider {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttlMs?: number): Promise<void>;
  exists(key: string): Promise<boolean>;
  delete(key: string): Promise<void>;
  increment(key: string, ttlMs?: number): Promise<number>;
  isReady(): boolean;
  shutdown(): Promise<void>;
}

/**
 * In-memory cache with TTL support
 * Default implementation for single-instance deployments
 */
export class MemoryCacheProvider implements CacheProvider {
  private cache: Map<string, { value: string; expiresAt: number | null }> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Cleanup expired entries every 60 seconds
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000).unref();
    securityLogger.info('Initialized in-memory cache provider');
  }

  async get(key: string): Promise<string | null> {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(key: string, value: string, ttlMs?: number): Promise<void> {
    const expiresAt = ttlMs ? Date.now() + ttlMs : null;
    this.cache.set(key, { value, expiresAt });
  }

  async exists(key: string): Promise<boolean> {
    const value = await this.get(key);
    return value !== null;
  }

  async delete(key: string): Promise<void> {
    this.cache.delete(key);
  }

  async increment(key: string, ttlMs?: number): Promise<number> {
    const current = await this.get(key);
    const newValue = (parseInt(current || '0', 10) || 0) + 1;
    await this.set(key, String(newValue), ttlMs);
    return newValue;
  }

  isReady(): boolean {
    return true;
  }

  async shutdown(): Promise<void> {
    clearInterval(this.cleanupInterval);
    this.cache.clear();
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (entry.expiresAt && now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  getStats(): { size: number } {
    return { size: this.cache.size };
  }
}

/**
 * Redis-backed cache provider for multi-instance deployments
 * Requires REDIS_URL environment variable
 */
export class RedisCacheProvider implements CacheProvider {
  private client: Redis;
  private keyPrefix: string;
  private ready: boolean = false;

  constructor(redisUrl: string, keyPrefix: string = 'phishing-agent:') {
    this.keyPrefix = keyPrefix;
    this.client = new Redis(redisUrl, {
      enableReadyCheck: true,
      maxRetriesPerRequest: 3,
      lazyConnect: true,
      tls: redisUrl.startsWith('rediss://') ? {} : undefined,
    });

    this.client.on('ready', () => {
      this.ready = true;
      securityLogger.info('Redis cache provider connected', { keyPrefix });
    });

    this.client.on('error', (error: Error) => {
      securityLogger.error('Redis cache provider error', { error: error.message });
    });

    this.client.on('close', () => {
      this.ready = false;
      securityLogger.warn('Redis cache provider disconnected');
    });

    // Connect immediately
    this.client.connect().catch((error: Error) => {
      securityLogger.error('Failed to connect to Redis', { error: error.message });
    });
  }

  private prefixKey(key: string): string {
    return `${this.keyPrefix}${key}`;
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(this.prefixKey(key));
  }

  async set(key: string, value: string, ttlMs?: number): Promise<void> {
    const prefixedKey = this.prefixKey(key);
    if (ttlMs) {
      await this.client.set(prefixedKey, value, 'PX', ttlMs);
    } else {
      await this.client.set(prefixedKey, value);
    }
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.client.exists(this.prefixKey(key));
    return result === 1;
  }

  async delete(key: string): Promise<void> {
    await this.client.del(this.prefixKey(key));
  }

  async increment(key: string, ttlMs?: number): Promise<number> {
    const prefixedKey = this.prefixKey(key);
    const value = await this.client.incr(prefixedKey);
    if (ttlMs && value === 1) {
      // Set TTL only on first increment
      await this.client.pexpire(prefixedKey, ttlMs);
    }
    return value;
  }

  isReady(): boolean {
    return this.ready;
  }

  async shutdown(): Promise<void> {
    await this.client.quit();
  }
}

// Singleton cache provider instance
let cacheProvider: CacheProvider | null = null;

/**
 * Create or return the cache provider instance
 * Uses Redis if REDIS_URL is configured, otherwise falls back to in-memory
 */
export function createCacheProvider(): CacheProvider {
  if (cacheProvider) {
    return cacheProvider;
  }

  const redisUrl = config.redis.url;
  const keyPrefix = config.redis.keyPrefix;

  if (redisUrl) {
    securityLogger.info('Creating Redis cache provider', { keyPrefix });
    cacheProvider = new RedisCacheProvider(redisUrl, keyPrefix);
  } else {
    securityLogger.info('Creating in-memory cache provider (Redis not configured)');
    cacheProvider = new MemoryCacheProvider();
  }

  return cacheProvider;
}

/**
 * Get the current cache provider (must call createCacheProvider first)
 */
export function getCacheProvider(): CacheProvider {
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
