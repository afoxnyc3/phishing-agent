/**
 * Configuration management for phishing agent
 */

import { config as dotenvConfig } from 'dotenv';

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
 * Application configuration
 */
export const config = {
  // Azure configuration
  azure: {
    tenantId: getEnv('AZURE_TENANT_ID'),
    clientId: getEnv('AZURE_CLIENT_ID'),
    clientSecret: process.env.AZURE_CLIENT_SECRET, // Optional - not needed for MSI
  },

  // Mailbox monitoring
  mailbox: {
    enabled: getEnvBoolean('MAILBOX_MONITOR_ENABLED', true),
    address: getEnv('PHISHING_MAILBOX_ADDRESS'),
    checkIntervalMs: getEnvNumber('MAILBOX_CHECK_INTERVAL_MS', 60000),
  },

  // Threat intelligence
  threatIntel: {
    enabled: getEnvBoolean('THREAT_INTEL_ENABLED', true),
    timeoutMs: getEnvNumber('THREAT_INTEL_TIMEOUT_MS', 5000),
    cacheTtlMs: getEnvNumber('THREAT_INTEL_CACHE_TTL_MS', 300000),
    virusTotalApiKey: process.env.VIRUSTOTAL_API_KEY,
    abuseIpDbApiKey: process.env.ABUSEIPDB_API_KEY,
    urlScanApiKey: process.env.URLSCAN_API_KEY,
  },

  // Server
  server: {
    port: getEnvNumber('PORT', 3000),
    environment: getEnv('NODE_ENV', 'development'),
  },
};

/**
 * Check if running in production
 */
export function isProduction(): boolean {
  return config.server.environment === 'production';
}
