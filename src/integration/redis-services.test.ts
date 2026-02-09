/**
 * Integration Tests: Redis Services
 * Tests Redis-backed rate limiter and deduplication with real Redis.
 * Skips automatically if Redis is not available.
 */

import './setup.js';
import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { Redis } from 'ioredis';
import { isRedisAvailable, REDIS_URL } from './setup.js';
import { RedisCacheProvider } from '../lib/redis-cache-provider.js';
import { RedisRateLimiter } from '../services/redis-rate-limiter.js';
import { RedisEmailDeduplication } from '../services/redis-email-deduplication.js';

let redis: Redis;
let cacheProvider: RedisCacheProvider;
let available = false;

beforeAll(async () => {
  available = await isRedisAvailable();
  if (!available) return;

  redis = new Redis(REDIS_URL);
  cacheProvider = new RedisCacheProvider(REDIS_URL, 'test:integ:');
});

afterAll(async () => {
  if (!available) return;
  // Clean up test keys
  const keys = await redis.keys('test:integ:*');
  if (keys.length > 0) await redis.del(...keys);
  await redis.quit();
  await cacheProvider.shutdown();
});

describe('Redis Rate Limiter Integration', () => {
  let rateLimiter: RedisRateLimiter;

  beforeAll(() => {
    if (!available) return;
    rateLimiter = new RedisRateLimiter(cacheProvider, {
      enabled: true,
      maxEmailsPerHour: 5,
      maxEmailsPerDay: 10,
      circuitBreakerThreshold: 3,
      circuitBreakerWindowMs: 600000,
    });
  });

  beforeEach(async () => {
    if (!available) return;
    await rateLimiter.reset();
  });

  it.skipIf(!available)('should allow sending within limits', async () => {
    const result = await rateLimiter.canSendEmail();
    expect(result.allowed).toBe(true);
  });

  it.skipIf(!available)('should record sends and track counts', async () => {
    await rateLimiter.recordEmailSent();
    await rateLimiter.recordEmailSent();

    const stats = await rateLimiter.getStats();
    expect(stats.lastHour).toBe(2);
    expect(stats.lastDay).toBe(2);
    expect(stats.circuitBreakerTripped).toBe(false);
  });

  it.skipIf(!available)('should enforce hourly limit', async () => {
    for (let i = 0; i < 5; i++) {
      await rateLimiter.recordEmailSent();
    }

    const result = await rateLimiter.canSendEmail();
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Hourly');
  });

  it.skipIf(!available)('should trip circuit breaker on burst', async () => {
    // Create a rate limiter with very low circuit breaker threshold
    const burstLimiter = new RedisRateLimiter(cacheProvider, {
      enabled: true,
      maxEmailsPerHour: 100,
      maxEmailsPerDay: 1000,
      circuitBreakerThreshold: 2,
      circuitBreakerWindowMs: 600000,
    });

    await burstLimiter.recordEmailSent();
    await burstLimiter.recordEmailSent();

    const result = await burstLimiter.canSendEmail();
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Circuit breaker');
  });
});

describe('Redis Email Deduplication Integration', () => {
  let dedup: RedisEmailDeduplication;

  beforeAll(() => {
    if (!available) return;
    dedup = new RedisEmailDeduplication(cacheProvider, {
      enabled: true,
      contentHashTtlMs: 60000,
      senderCooldownMs: 60000,
    });
  });

  beforeEach(async () => {
    if (!available) return;
    // Clean dedup keys before each test
    const keys = await redis.keys('test:integ:*dedup*');
    if (keys.length > 0) await redis.del(...keys);
  });

  it.skipIf(!available)('should allow first email from sender', async () => {
    const result = await dedup.shouldProcess('sender@example.com', 'Test Subject', 'Test body content');
    expect(result.allowed).toBe(true);
  });

  it.skipIf(!available)('should block duplicate content hash', async () => {
    const sender = 'dedup-test@example.com';
    const subject = 'Duplicate Test';
    const body = 'This is duplicate content';

    await dedup.recordProcessed(sender, subject, body);
    const result = await dedup.shouldProcess(sender, subject, body);

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Duplicate');
  });

  it.skipIf(!available)('should enforce sender cooldown', async () => {
    const sender = 'cooldown-test@example.com';

    await dedup.recordProcessed(sender, 'Subject 1', 'Body 1');
    const result = await dedup.shouldProcess(sender, 'Subject 2', 'Body 2');

    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('cooldown');
  });

  it.skipIf(!available)('should allow different content from different sender', async () => {
    await dedup.recordProcessed('sender-a@example.com', 'Subject A', 'Body A');
    const result = await dedup.shouldProcess('sender-b@example.com', 'Subject B', 'Body B');

    expect(result.allowed).toBe(true);
  });
});
