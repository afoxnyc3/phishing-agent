/**
 * Configuration management for phishing agent
 * Uses Zod for runtime validation of environment variables
 */

import { config as dotenvConfig } from 'dotenv';
import { EnvConfigSchema } from './schemas.js';

// Load environment variables
dotenvConfig();

/**
 * Get environment variable with type safety
 */
export function getEnv(key: string, defaultValue?: string): string {
  const value = process.env[key];
  if (value === undefined) {
    if (defaultValue !== undefined) {
      return defaultValue;
    }
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

/**
 * Get number from environment
 */
export function getEnvNumber(key: string, defaultValue?: number): number {
  const value = process.env[key];
  if (value === undefined) {
    if (defaultValue !== undefined) {
      return defaultValue;
    }
    throw new Error(`Missing required environment variable: ${key}`);
  }
  const num = parseInt(value, 10);
  if (isNaN(num)) {
    throw new Error(`Invalid number for ${key}: ${value}`);
  }
  return num;
}

/**
 * Get boolean from environment
 */
export function getEnvBoolean(key: string, defaultValue: boolean = false): boolean {
  const value = process.env[key];
  if (value === undefined) {
    return defaultValue;
  }
  return value.toLowerCase() === 'true';
}

/**
 * Validate environment variables with Zod
 */
function validateEnvironment(): ReturnType<typeof EnvConfigSchema.parse> {
  try {
    const validated = EnvConfigSchema.parse(process.env);
    return validated;
  } catch (error) {
    // Use console.error to avoid circular dependency with logger
    console.error('Environment validation failed:', (error as Error).message);
    throw new Error(`Invalid environment configuration: ${(error as Error).message}`);
  }
}

// Validate environment on module load
const env = validateEnvironment();

/**
 * Application configuration (validated with Zod)
 */
export const config = {
  // Azure configuration
  azure: {
    tenantId: env.AZURE_TENANT_ID,
    clientId: env.AZURE_CLIENT_ID,
    clientSecret: env.AZURE_CLIENT_SECRET,
  },

  // Mailbox monitoring
  mailbox: {
    enabled: env.MAILBOX_MONITOR_ENABLED,
    address: env.PHISHING_MAILBOX_ADDRESS,
    checkIntervalMs: env.MAILBOX_CHECK_INTERVAL_MS,
  },

  // Threat intelligence
  threatIntel: {
    enabled: env.THREAT_INTEL_ENABLED,
    timeoutMs: env.THREAT_INTEL_TIMEOUT_MS,
    cacheTtlMs: env.THREAT_INTEL_CACHE_TTL_MS,
    virusTotalApiKey: env.VIRUSTOTAL_API_KEY,
    abuseIpDbApiKey: env.ABUSEIPDB_API_KEY,
    urlScanApiKey: env.URLSCAN_API_KEY,
  },

  // Rate limiting
  rateLimit: {
    enabled: env.RATE_LIMIT_ENABLED,
    maxEmailsPerHour: env.MAX_EMAILS_PER_HOUR,
    maxEmailsPerDay: env.MAX_EMAILS_PER_DAY,
    circuitBreakerThreshold: env.CIRCUIT_BREAKER_THRESHOLD,
    circuitBreakerWindowMs: env.CIRCUIT_BREAKER_WINDOW_MS,
  },

  // Email deduplication
  deduplication: {
    enabled: env.DEDUPLICATION_ENABLED,
    contentHashTtlMs: env.DEDUPLICATION_TTL_MS,
    senderCooldownMs: env.SENDER_COOLDOWN_MS,
  },

  // Server
  server: {
    port: env.PORT,
    environment: env.NODE_ENV,
  },
};

/**
 * Check if running in production
 */
export function isProduction(): boolean {
  return config.server.environment === 'production';
}
