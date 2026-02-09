/**
 * Integration Test Setup
 * Sets required env vars before any module imports, and provides
 * Redis connectivity helpers.
 */

// Must set env vars BEFORE any modules that import config are loaded
process.env.AZURE_TENANT_ID = process.env.AZURE_TENANT_ID || 'test-tenant-id';
process.env.AZURE_CLIENT_ID = process.env.AZURE_CLIENT_ID || 'test-client-id';
process.env.AZURE_CLIENT_SECRET = process.env.AZURE_CLIENT_SECRET || 'test-secret';
process.env.PHISHING_MAILBOX_ADDRESS = process.env.PHISHING_MAILBOX_ADDRESS || 'test@example.com';
process.env.NODE_ENV = 'test';

import { Redis } from 'ioredis';

const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379';

/** Check if Redis is reachable */
export async function isRedisAvailable(): Promise<boolean> {
  const client = new Redis(REDIS_URL, { lazyConnect: true, connectTimeout: 2000 });
  try {
    await client.connect();
    await client.ping();
    await client.quit();
    return true;
  } catch {
    await client.quit().catch(() => {});
    return false;
  }
}

/** Create a Redis client for tests */
export function createTestRedis(): Redis {
  return new Redis(REDIS_URL, { keyPrefix: 'test:integration:' });
}

/** Flush test keys from Redis */
export async function cleanupTestKeys(client: Redis): Promise<void> {
  const keys = await client.keys('test:integration:*');
  if (keys.length > 0) {
    // Strip prefix since ioredis auto-adds it
    const rawKeys = keys.map((k) => k.replace('test:integration:', ''));
    await client.del(...rawKeys);
  }
}

export { REDIS_URL };
