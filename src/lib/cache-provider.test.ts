/**
 * Cache Provider Tests
 * Tests for MemoryCacheProvider and cache factory functions
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';

// Mock the logger before imports
jest.unstable_mockModule('./logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

// Mock config
jest.unstable_mockModule('./config.js', () => ({
  config: {
    redis: {
      url: undefined,
      keyPrefix: 'test:',
    },
  },
}));

const { MemoryCacheProvider, createCacheProvider, getCacheProvider, shutdownCacheProvider } =
  await import('./cache-provider.js');

describe('MemoryCacheProvider', () => {
  let cache: InstanceType<typeof MemoryCacheProvider>;

  beforeEach(() => {
    cache = new MemoryCacheProvider();
  });

  afterEach(async () => {
    await cache.shutdown();
  });

  describe('get/set', () => {
    it('should return null for non-existent key', async () => {
      const result = await cache.get('non-existent');
      expect(result).toBeNull();
    });

    it('should store and retrieve value', async () => {
      await cache.set('key1', 'value1');
      const result = await cache.get('key1');
      expect(result).toBe('value1');
    });

    it('should overwrite existing value', async () => {
      await cache.set('key1', 'value1');
      await cache.set('key1', 'value2');
      const result = await cache.get('key1');
      expect(result).toBe('value2');
    });

    it('should store value without TTL', async () => {
      await cache.set('persistent', 'value');
      const result = await cache.get('persistent');
      expect(result).toBe('value');
    });
  });

  describe('TTL expiration', () => {
    it('should expire value after TTL', async () => {
      await cache.set('expiring', 'value', 50); // 50ms TTL

      // Value should exist immediately
      let result = await cache.get('expiring');
      expect(result).toBe('value');

      // Wait for TTL to expire
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Value should be gone
      result = await cache.get('expiring');
      expect(result).toBeNull();
    });

    it('should not expire value without TTL', async () => {
      await cache.set('permanent', 'value');

      await new Promise((resolve) => setTimeout(resolve, 50));

      const result = await cache.get('permanent');
      expect(result).toBe('value');
    });
  });

  describe('exists', () => {
    it('should return false for non-existent key', async () => {
      const result = await cache.exists('non-existent');
      expect(result).toBe(false);
    });

    it('should return true for existing key', async () => {
      await cache.set('exists-test', 'value');
      const result = await cache.exists('exists-test');
      expect(result).toBe(true);
    });

    it('should return false for expired key', async () => {
      await cache.set('expiring', 'value', 50);
      await new Promise((resolve) => setTimeout(resolve, 100));
      const result = await cache.exists('expiring');
      expect(result).toBe(false);
    });
  });

  describe('delete', () => {
    it('should delete existing key', async () => {
      await cache.set('to-delete', 'value');
      expect(await cache.exists('to-delete')).toBe(true);

      await cache.delete('to-delete');
      expect(await cache.exists('to-delete')).toBe(false);
    });

    it('should not throw when deleting non-existent key', async () => {
      await expect(cache.delete('non-existent')).resolves.not.toThrow();
    });
  });

  describe('increment', () => {
    it('should increment non-existent key from 0', async () => {
      const result = await cache.increment('counter');
      expect(result).toBe(1);
    });

    it('should increment existing numeric value', async () => {
      await cache.set('counter', '5');
      const result = await cache.increment('counter');
      expect(result).toBe(6);
    });

    it('should handle non-numeric values as 0', async () => {
      await cache.set('counter', 'not-a-number');
      const result = await cache.increment('counter');
      expect(result).toBe(1);
    });

    it('should apply TTL on increment', async () => {
      await cache.increment('counter', 50);
      expect(await cache.get('counter')).toBe('1');

      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(await cache.get('counter')).toBeNull();
    });

    it('should increment multiple times', async () => {
      await cache.increment('counter');
      await cache.increment('counter');
      await cache.increment('counter');
      const result = await cache.get('counter');
      expect(result).toBe('3');
    });
  });

  describe('isReady', () => {
    it('should always return true for memory cache', () => {
      expect(cache.isReady()).toBe(true);
    });
  });

  describe('shutdown', () => {
    it('should clear cache on shutdown', async () => {
      await cache.set('key1', 'value1');
      await cache.set('key2', 'value2');

      await cache.shutdown();

      // After shutdown, cache is cleared
      expect(cache.getStats().size).toBe(0);
    });
  });

  describe('getStats', () => {
    it('should return correct cache size', async () => {
      expect(cache.getStats().size).toBe(0);

      await cache.set('key1', 'value1');
      expect(cache.getStats().size).toBe(1);

      await cache.set('key2', 'value2');
      expect(cache.getStats().size).toBe(2);

      await cache.delete('key1');
      expect(cache.getStats().size).toBe(1);
    });
  });
});

describe('Cache Factory Functions', () => {
  afterEach(async () => {
    await shutdownCacheProvider();
  });

  describe('createCacheProvider', () => {
    it('should create memory cache when Redis not configured', () => {
      const provider = createCacheProvider();
      expect(provider).toBeDefined();
      expect(provider.isReady()).toBe(true);
    });

    it('should return same instance on multiple calls', () => {
      const provider1 = createCacheProvider();
      const provider2 = createCacheProvider();
      expect(provider1).toBe(provider2);
    });
  });

  describe('getCacheProvider', () => {
    it('should create provider if not exists', () => {
      const provider = getCacheProvider();
      expect(provider).toBeDefined();
    });

    it('should return existing provider', () => {
      const provider1 = createCacheProvider();
      const provider2 = getCacheProvider();
      expect(provider1).toBe(provider2);
    });
  });

  describe('shutdownCacheProvider', () => {
    it('should shutdown and clear provider', async () => {
      createCacheProvider();
      await shutdownCacheProvider();

      // After shutdown, a new call should create a new instance
      const newProvider = createCacheProvider();
      expect(newProvider).toBeDefined();
    });

    it('should handle multiple shutdown calls', async () => {
      createCacheProvider();
      await shutdownCacheProvider();
      await expect(shutdownCacheProvider()).resolves.not.toThrow();
    });
  });
});
