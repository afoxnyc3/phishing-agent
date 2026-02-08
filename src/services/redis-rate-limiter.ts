/**
 * Redis-Backed Rate Limiter Service
 * Uses sorted sets for optimal sliding window rate limiting.
 * All operations use pipelining to minimize round trips.
 */

import { CacheProvider } from '../lib/cache-provider.js';
import { CacheKeys } from '../lib/cache-keys.js';
import { securityLogger } from '../lib/logger.js';
import { RateLimiterConfig } from './rate-limiter.js';

/** Versioned Redis key builders */
const KEYS = {
  timestamps: CacheKeys.rateLimit.timestamps('global'),
  circuit: CacheKeys.rateLimit.circuit('global'),
};

/** Stats returned by getStats() */
export interface RateLimiterStats {
  lastHour: number;
  lastDay: number;
  last10Min: number;
  circuitBreakerTripped: boolean;
  hourlyLimit: number;
  dailyLimit: number;
}

/**
 * Redis-backed rate limiter using sorted sets for sliding window
 */
export class RedisRateLimiter {
  private cache: CacheProvider;
  private config: RateLimiterConfig;

  constructor(cacheProvider: CacheProvider, config: RateLimiterConfig) {
    this.cache = cacheProvider;
    this.config = config;

    securityLogger.info('Redis rate limiter initialized', {
      maxPerHour: config.maxEmailsPerHour,
      maxPerDay: config.maxEmailsPerDay,
      circuitBreakerThreshold: config.circuitBreakerThreshold,
      mode: 'distributed (Redis)',
    });
  }

  /**
   * Check if sending is allowed (single pipeline round trip)
   */
  async canSendEmail(): Promise<{ allowed: boolean; reason?: string }> {
    if (!this.config.enabled) {
      return { allowed: true };
    }

    // Check circuit breaker first
    const cbValue = await this.cache.get(KEYS.circuit);
    if (cbValue) {
      return { allowed: false, reason: `Circuit breaker tripped until ${cbValue}` };
    }

    const now = Date.now();
    const hourAgo = now - 60 * 60 * 1000;
    const dayAgo = now - 24 * 60 * 60 * 1000;
    const burstAgo = now - this.config.circuitBreakerWindowMs;

    // Pipeline: get all counts in ONE round trip
    const pipeline = this.cache.pipeline();
    pipeline.zcount(KEYS.timestamps, hourAgo, '+inf');
    pipeline.zcount(KEYS.timestamps, dayAgo, '+inf');
    pipeline.zcount(KEYS.timestamps, burstAgo, '+inf');

    const results = await pipeline.exec();
    const hourlyCount = (results[0][1] as number) || 0;
    const dailyCount = (results[1][1] as number) || 0;
    const burstCount = (results[2][1] as number) || 0;

    // Check limits
    if (hourlyCount >= this.config.maxEmailsPerHour) {
      return this.limitReached('Hourly', hourlyCount, this.config.maxEmailsPerHour);
    }

    if (dailyCount >= this.config.maxEmailsPerDay) {
      return this.limitReached('Daily', dailyCount, this.config.maxEmailsPerDay);
    }

    if (burstCount >= this.config.circuitBreakerThreshold) {
      await this.tripCircuitBreaker();
      return { allowed: false, reason: 'Circuit breaker tripped due to burst sending' };
    }

    return { allowed: true };
  }

  private limitReached(type: string, count: number, limit: number): { allowed: false; reason: string } {
    return { allowed: false, reason: `${type} limit reached (${count}/${limit})` };
  }

  /**
   * Record email send (single pipeline operation)
   */
  async recordEmailSent(): Promise<void> {
    if (!this.config.enabled) return;

    const now = Date.now();
    const uniqueId = `${now}-${Math.random().toString(36).substring(2, 11)}`;
    const dayAgo = now - 24 * 60 * 60 * 1000;

    // Atomic pipeline: add timestamp, cleanup old, set TTL
    const pipeline = this.cache.pipeline();
    pipeline.zadd(KEYS.timestamps, now, uniqueId);
    pipeline.zremrangebyscore(KEYS.timestamps, '-inf', dayAgo);
    pipeline.expire(KEYS.timestamps, 86400); // 24h TTL

    await pipeline.exec();

    const stats = await this.getStats();
    securityLogger.debug('Email sent recorded (Redis)', stats as unknown as Record<string, unknown>);
  }

  /**
   * Trip circuit breaker (SET NX with TTL)
   */
  private async tripCircuitBreaker(): Promise<void> {
    const resetTime = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    // SET NX - only set if not already tripped (atomic)
    await this.cache.setNX(KEYS.circuit, resetTime, 60 * 60 * 1000);

    securityLogger.error('Circuit breaker tripped (Redis)!', {
      resetTime,
      reason: 'Burst sending detected',
    });
  }

  /**
   * Get rate limiter statistics
   */
  async getStats(): Promise<RateLimiterStats> {
    const now = Date.now();

    const pipeline = this.cache.pipeline();
    pipeline.zcount(KEYS.timestamps, now - 60 * 60 * 1000, '+inf');
    pipeline.zcount(KEYS.timestamps, now - 24 * 60 * 60 * 1000, '+inf');
    pipeline.zcount(KEYS.timestamps, now - this.config.circuitBreakerWindowMs, '+inf');
    pipeline.get(KEYS.circuit);

    const results = await pipeline.exec();

    return {
      lastHour: (results[0][1] as number) || 0,
      lastDay: (results[1][1] as number) || 0,
      last10Min: (results[2][1] as number) || 0,
      circuitBreakerTripped: results[3][1] !== null,
      hourlyLimit: this.config.maxEmailsPerHour,
      dailyLimit: this.config.maxEmailsPerDay,
    };
  }

  /**
   * Reset all counters (for testing/admin)
   */
  async reset(): Promise<void> {
    await this.cache.delete(KEYS.timestamps);
    await this.cache.delete(KEYS.circuit);
    securityLogger.warn('Redis rate limiter reset');
  }
}
