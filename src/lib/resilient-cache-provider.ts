/**
 * Resilient Cache Provider
 * Wraps RedisCacheProvider with circuit breaker and memory fallback.
 * Ensures cache operations never fail - falls back to in-memory when Redis unavailable.
 */

import CircuitBreaker from 'opossum';
import { CacheProvider, CachePipeline } from './cache-provider.js';
import { MemoryCacheProvider } from './memory-cache-provider.js';
import { RedisCacheProvider } from './redis-cache-provider.js';
import { securityLogger } from './logger.js';

/** Circuit breaker configuration for Redis operations */
const CIRCUIT_BREAKER_OPTIONS = {
  timeout: 500, // 500ms per operation (fast fail)
  errorThresholdPercentage: 50, // Open if 50% fail
  resetTimeout: 30000, // Try again after 30 seconds
  volumeThreshold: 5, // Need 5 requests before calculating %
};

/** Status for health checks */
export interface CacheStatus {
  degraded: boolean;
  mode: 'redis' | 'memory' | 'fallback';
  circuitState: 'closed' | 'open' | 'half-open';
  lastError?: string;
  redisReady: boolean;
}

/**
 * Resilient cache provider with circuit breaker and memory fallback
 */
export class ResilientCacheProvider implements CacheProvider {
  private redis: RedisCacheProvider;
  private memory: MemoryCacheProvider;
  private breaker: CircuitBreaker;
  private degraded: boolean = false;
  private lastError?: string;

  constructor(redisUrl: string, keyPrefix: string = 'phishing-agent:') {
    this.redis = new RedisCacheProvider(redisUrl, keyPrefix);
    this.memory = new MemoryCacheProvider();

    // Create circuit breaker for Redis operations
    this.breaker = new CircuitBreaker(async (fn: () => Promise<unknown>) => fn(), CIRCUIT_BREAKER_OPTIONS);
    this.setupBreakerEvents();

    securityLogger.info('Resilient cache provider initialized', {
      mode: 'redis with memory fallback',
      circuitBreakerTimeout: CIRCUIT_BREAKER_OPTIONS.timeout,
    });
  }

  private setupBreakerEvents(): void {
    this.breaker.on('open', () => {
      this.degraded = true;
      securityLogger.warn('Redis circuit OPEN - falling back to in-memory cache', {
        lastError: this.lastError,
      });
    });

    this.breaker.on('halfOpen', () => {
      securityLogger.info('Redis circuit HALF-OPEN - testing recovery');
    });

    this.breaker.on('close', () => {
      this.degraded = false;
      securityLogger.info('Redis circuit CLOSED - using Redis cache');
    });

    this.breaker.on('fallback', () => {
      securityLogger.debug('Redis operation fallback triggered');
    });
  }

  /** Execute operation via circuit breaker with memory fallback */
  private async execute<T>(redisOp: () => Promise<T>, memoryOp: () => Promise<T>, operationName: string): Promise<T> {
    // If Redis not ready, use memory directly
    if (!this.redis.isReady()) {
      return memoryOp();
    }

    try {
      const result = await this.breaker.fire(redisOp);
      return result as T;
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      this.lastError = msg;
      securityLogger.debug(`Redis ${operationName} failed, using memory`, { error: msg });
      return memoryOp();
    }
  }

  // Basic operations with fallback
  async get(key: string): Promise<string | null> {
    return this.execute(
      () => this.redis.get(key),
      () => this.memory.get(key),
      'get'
    );
  }

  async set(key: string, value: string, ttlMs?: number): Promise<void> {
    // Write to both Redis and memory for consistency during degradation
    await this.memory.set(key, value, ttlMs);
    await this.execute(
      () => this.redis.set(key, value, ttlMs),
      async () => {}, // Already written to memory
      'set'
    );
  }

  async exists(key: string): Promise<boolean> {
    return this.execute(
      () => this.redis.exists(key),
      () => this.memory.exists(key),
      'exists'
    );
  }

  async delete(key: string): Promise<void> {
    await this.memory.delete(key);
    await this.execute(
      () => this.redis.delete(key),
      async () => {},
      'delete'
    );
  }

  async increment(key: string, ttlMs?: number): Promise<number> {
    // For distributed counting, try Redis first
    return this.execute(
      () => this.redis.increment(key, ttlMs),
      () => this.memory.increment(key, ttlMs),
      'increment'
    );
  }

  // Sorted set operations with fallback
  async zadd(key: string, score: number, member: string): Promise<number> {
    await this.memory.zadd(key, score, member);
    return this.execute(
      () => this.redis.zadd(key, score, member),
      async () => 1,
      'zadd'
    );
  }

  async zcount(key: string, min: number | '-inf', max: number | '+inf'): Promise<number> {
    return this.execute(
      () => this.redis.zcount(key, min, max),
      () => this.memory.zcount(key, min, max),
      'zcount'
    );
  }

  async zremrangebyscore(key: string, min: number | '-inf', max: number): Promise<number> {
    await this.memory.zremrangebyscore(key, min, max);
    return this.execute(
      () => this.redis.zremrangebyscore(key, min, max),
      async () => 0,
      'zremrangebyscore'
    );
  }

  async setNX(key: string, value: string, ttlMs?: number): Promise<boolean> {
    return this.execute(
      () => this.redis.setNX(key, value, ttlMs),
      () => this.memory.setNX(key, value, ttlMs),
      'setNX'
    );
  }

  async expire(key: string, ttlSeconds: number): Promise<boolean> {
    return this.execute(
      () => this.redis.expire(key, ttlSeconds),
      () => this.memory.expire(key, ttlSeconds),
      'expire'
    );
  }

  pipeline(): CachePipeline {
    // For pipeline, we use Redis if available, otherwise memory
    if (this.redis.isReady() && !this.degraded) {
      return this.redis.pipeline();
    }
    return this.memory.pipeline();
  }

  isReady(): boolean {
    // Resilient provider is always ready (has fallback)
    return true;
  }

  async shutdown(): Promise<void> {
    await this.redis.shutdown();
    await this.memory.shutdown();
  }

  /** Get status for health checks */
  getStatus(): CacheStatus {
    const redisReady = this.redis.isReady();
    let mode: 'redis' | 'memory' | 'fallback';

    if (redisReady && !this.degraded) {
      mode = 'redis';
    } else if (redisReady && this.degraded) {
      mode = 'fallback';
    } else {
      mode = 'memory';
    }

    let circuitState: 'closed' | 'open' | 'half-open';
    if (this.breaker.opened) {
      circuitState = 'open';
    } else if (this.breaker.halfOpen) {
      circuitState = 'half-open';
    } else {
      circuitState = 'closed';
    }

    return {
      degraded: this.degraded || !redisReady,
      mode,
      circuitState,
      lastError: this.lastError,
      redisReady,
    };
  }
}
