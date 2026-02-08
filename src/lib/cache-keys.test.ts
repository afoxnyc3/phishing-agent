/**
 * Cache Key Versioning Tests
 */

import { describe, it, expect } from 'vitest';
import { versionedKey, CacheKeys } from './cache-keys.js';

describe('versionedKey', () => {
  it('should produce versioned key with v1 prefix', () => {
    expect(versionedKey('ns', 'mykey')).toBe('v1:ns:mykey');
  });

  it('should include namespace and key segments', () => {
    const key = versionedKey('dedup', 'hash:abc');
    expect(key).toBe('v1:dedup:hash:abc');
  });

  it('should be deterministic for same inputs', () => {
    const a = versionedKey('rate', 'window:x');
    const b = versionedKey('rate', 'window:x');
    expect(a).toBe(b);
  });

  it('should produce different keys for different namespaces', () => {
    const a = versionedKey('dedup', 'key');
    const b = versionedKey('rate', 'key');
    expect(a).not.toBe(b);
  });

  it('should produce different keys for different values', () => {
    const a = versionedKey('ns', 'key1');
    const b = versionedKey('ns', 'key2');
    expect(a).not.toBe(b);
  });
});

describe('CacheKeys.dedup', () => {
  it('should build versioned hash key', () => {
    expect(CacheKeys.dedup.hash('abc123')).toBe('v1:dedup:hash:abc123');
  });

  it('should build versioned sender key', () => {
    expect(CacheKeys.dedup.sender('user@example.com')).toBe('v1:dedup:sender:user@example.com');
  });
});

describe('CacheKeys.rateLimit', () => {
  it('should build versioned timestamps key', () => {
    expect(CacheKeys.rateLimit.timestamps('global')).toBe('v1:rate:timestamps:global');
  });

  it('should build versioned circuit key', () => {
    expect(CacheKeys.rateLimit.circuit('global')).toBe('v1:rate:circuit:global');
  });
});

describe('CacheKeys.circuitBreaker', () => {
  it('should build versioned state key', () => {
    expect(CacheKeys.circuitBreaker.state('threatIntel')).toBe('v1:cb:state:threatIntel');
  });

  it('should build versioned failures key', () => {
    expect(CacheKeys.circuitBreaker.failures('threatIntel')).toBe('v1:cb:failures:threatIntel');
  });
});

describe('key uniqueness', () => {
  it('should produce unique keys across namespaces', () => {
    const keys = new Set([
      CacheKeys.dedup.hash('x'),
      CacheKeys.dedup.sender('x'),
      CacheKeys.rateLimit.timestamps('x'),
      CacheKeys.rateLimit.circuit('x'),
      CacheKeys.circuitBreaker.state('x'),
      CacheKeys.circuitBreaker.failures('x'),
    ]);
    expect(keys.size).toBe(6);
  });
});
