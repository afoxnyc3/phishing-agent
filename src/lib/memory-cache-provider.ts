/** In-Memory Cache Provider - Default for single-instance deployments */

import { CacheProvider, CachePipeline } from './cache-provider.js';
import { securityLogger } from './logger.js';

interface SortedSetEntry { score: number; member: string; }

/** In-memory pipeline implementation */
export class MemoryCachePipeline implements CachePipeline {
  private operations: Array<() => Promise<unknown>> = [];
  private provider: MemoryCacheProvider;

  constructor(provider: MemoryCacheProvider) {
    this.provider = provider;
  }

  zadd(key: string, score: number, member: string): this {
    this.operations.push(() => this.provider.zadd(key, score, member));
    return this;
  }

  zcount(key: string, min: number | string, max: number | string): this {
    const minVal = min === '-inf' ? -Infinity : Number(min);
    const maxVal = max === '+inf' ? Infinity : Number(max);
    this.operations.push(() => this.provider.zcount(key, minVal as number | '-inf', maxVal as number | '+inf'));
    return this;
  }

  zremrangebyscore(key: string, min: number | string, max: number | string): this {
    const minVal = min === '-inf' ? -Infinity : Number(min);
    const maxVal = max === '+inf' ? Infinity : Number(max);
    this.operations.push(() => this.provider.zremrangebyscore(key, minVal as number | '-inf', maxVal as number));
    return this;
  }

  expire(key: string, seconds: number): this {
    this.operations.push(() => this.provider.expire(key, seconds));
    return this;
  }

  set(key: string, value: string, ...options: string[]): this {
    let ttlMs: number | undefined;
    const pxIndex = options.indexOf('PX');
    if (pxIndex !== -1 && options[pxIndex + 1]) {
      ttlMs = parseInt(options[pxIndex + 1], 10);
    }
    this.operations.push(() => this.provider.set(key, value, ttlMs));
    return this;
  }

  get(key: string): this {
    this.operations.push(() => this.provider.get(key));
    return this;
  }

  exists(...keys: string[]): this {
    this.operations.push(async () => {
      let count = 0;
      for (const key of keys) {
        if (await this.provider.exists(key)) count++;
      }
      return count;
    });
    return this;
  }

  async exec(): Promise<Array<[Error | null, unknown]>> {
    const results: Array<[Error | null, unknown]> = [];
    for (const op of this.operations) {
      try {
        const result = await op();
        results.push([null, result]);
      } catch (error) {
        results.push([error as Error, null]);
      }
    }
    return results;
  }
}

/** In-memory cache with TTL support - Default implementation for single-instance deployments */
export class MemoryCacheProvider implements CacheProvider {
  private cache: Map<string, { value: string; expiresAt: number | null }> = new Map();
  private sortedSets: Map<string, SortedSetEntry[]> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
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
    this.sortedSets.delete(key);
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
    this.sortedSets.clear();
  }

  async zadd(key: string, score: number, member: string): Promise<number> {
    let set = this.sortedSets.get(key);
    if (!set) {
      set = [];
      this.sortedSets.set(key, set);
    }
    const idx = set.findIndex((e) => e.member === member);
    if (idx >= 0) set.splice(idx, 1);
    set.push({ score, member });
    set.sort((a, b) => a.score - b.score);
    return 1;
  }

  async zcount(key: string, min: number | '-inf', max: number | '+inf'): Promise<number> {
    const set = this.sortedSets.get(key) || [];
    const minVal = min === '-inf' ? -Infinity : min;
    const maxVal = max === '+inf' ? Infinity : max;
    return set.filter((e) => e.score >= minVal && e.score <= maxVal).length;
  }

  async zremrangebyscore(key: string, min: number | '-inf', max: number): Promise<number> {
    const set = this.sortedSets.get(key);
    if (!set) return 0;
    const minVal = min === '-inf' ? -Infinity : min;
    const original = set.length;
    const filtered = set.filter((e) => e.score < minVal || e.score > max);
    this.sortedSets.set(key, filtered);
    return original - filtered.length;
  }

  async setNX(key: string, value: string, ttlMs?: number): Promise<boolean> {
    if (await this.exists(key)) return false;
    await this.set(key, value, ttlMs);
    return true;
  }

  async expire(key: string, ttlSeconds: number): Promise<boolean> {
    const entry = this.cache.get(key);
    if (!entry) return false;
    entry.expiresAt = Date.now() + ttlSeconds * 1000;
    return true;
  }

  pipeline(): CachePipeline {
    return new MemoryCachePipeline(this);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.cache.entries()) {
      if (entry.expiresAt && now > entry.expiresAt) {
        this.cache.delete(key);
      }
    }
  }

  getStats(): { size: number; sortedSets: number } {
    return { size: this.cache.size, sortedSets: this.sortedSets.size };
  }
}
