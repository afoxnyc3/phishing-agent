/** Redis Cache Provider - Redis-backed cache for multi-instance deployments */

import { Redis } from 'ioredis';
import { CacheProvider, CachePipeline } from './cache-provider.js';
import { securityLogger } from './logger.js';

/** Redis pipeline wrapper */
export class RedisCachePipeline implements CachePipeline {
  private pipeline: ReturnType<Redis['pipeline']>;
  private keyPrefix: string;

  constructor(client: Redis, keyPrefix: string) {
    this.pipeline = client.pipeline();
    this.keyPrefix = keyPrefix;
  }

  private prefixKey(key: string): string {
    return `${this.keyPrefix}${key}`;
  }

  zadd(key: string, score: number, member: string): this {
    this.pipeline.zadd(this.prefixKey(key), score, member);
    return this;
  }

  zcount(key: string, min: number | string, max: number | string): this {
    this.pipeline.zcount(this.prefixKey(key), min, max);
    return this;
  }

  zremrangebyscore(key: string, min: number | string, max: number | string): this {
    this.pipeline.zremrangebyscore(this.prefixKey(key), min, max);
    return this;
  }

  expire(key: string, seconds: number): this {
    this.pipeline.expire(this.prefixKey(key), seconds);
    return this;
  }

  set(key: string, value: string, ...options: string[]): this {
    const prefixedKey = this.prefixKey(key);
    const pxIndex = options.indexOf('PX');
    const hasNX = options.includes('NX');

    if (pxIndex !== -1 && options[pxIndex + 1]) {
      const ttlMs = parseInt(options[pxIndex + 1], 10);
      if (hasNX) {
        this.pipeline.set(prefixedKey, value, 'PX', ttlMs, 'NX');
      } else {
        this.pipeline.set(prefixedKey, value, 'PX', ttlMs);
      }
    } else if (hasNX) {
      this.pipeline.set(prefixedKey, value, 'NX');
    } else {
      this.pipeline.set(prefixedKey, value);
    }
    return this;
  }

  get(key: string): this {
    this.pipeline.get(this.prefixKey(key));
    return this;
  }

  exists(...keys: string[]): this {
    this.pipeline.exists(...keys.map((k) => this.prefixKey(k)));
    return this;
  }

  async exec(): Promise<Array<[Error | null, unknown]>> {
    const results = await this.pipeline.exec();
    return (results || []) as Array<[Error | null, unknown]>;
  }
}

/** Redis-backed cache provider for multi-instance deployments */
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
      retryStrategy: (times) => {
        if (times > 10) return null;
        return Math.min(times * 100, 3000);
      },
      tls: redisUrl.startsWith('rediss://') ? {} : undefined,
    });

    this.setupEventHandlers();
    this.client.connect().catch((error: Error) => {
      securityLogger.error('Failed to connect to Redis', { error: error.message });
    });
  }

  private setupEventHandlers(): void {
    this.client.on('ready', () => {
      this.ready = true;
      securityLogger.info('Redis cache provider connected', { keyPrefix: this.keyPrefix });
    });
    this.client.on('error', (error: Error) => {
      securityLogger.error('Redis cache provider error', { error: error.message });
    });
    this.client.on('close', () => {
      this.ready = false;
      securityLogger.warn('Redis cache provider disconnected');
    });
    this.client.on('reconnecting', (delay: number) => {
      securityLogger.info('Redis reconnecting', { delayMs: delay });
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
      await this.client.pexpire(prefixedKey, ttlMs);
    }
    return value;
  }

  async zadd(key: string, score: number, member: string): Promise<number> {
    return this.client.zadd(this.prefixKey(key), score, member);
  }

  async zcount(key: string, min: number | '-inf', max: number | '+inf'): Promise<number> {
    return this.client.zcount(this.prefixKey(key), min, max);
  }

  async zremrangebyscore(key: string, min: number | '-inf', max: number): Promise<number> {
    return this.client.zremrangebyscore(this.prefixKey(key), min, max);
  }

  async setNX(key: string, value: string, ttlMs?: number): Promise<boolean> {
    const prefixedKey = this.prefixKey(key);
    let result: string | null;
    if (ttlMs) {
      result = await this.client.set(prefixedKey, value, 'PX', ttlMs, 'NX');
    } else {
      result = await this.client.set(prefixedKey, value, 'NX');
    }
    return result === 'OK';
  }

  async expire(key: string, ttlSeconds: number): Promise<boolean> {
    const result = await this.client.expire(this.prefixKey(key), ttlSeconds);
    return result === 1;
  }

  pipeline(): CachePipeline {
    return new RedisCachePipeline(this.client, this.keyPrefix);
  }

  isReady(): boolean {
    return this.ready;
  }

  async shutdown(): Promise<void> {
    await this.client.quit();
  }
}
