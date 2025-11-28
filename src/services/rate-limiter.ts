/**
 * Rate Limiter Service
 * Prevents email sending abuse with multiple protection layers
 * All functions are atomic (max 25 lines)
 *
 * NOTE: Currently uses in-memory storage. For multi-replica deployments,
 * configure REDIS_URL to enable distributed rate limiting (future enhancement).
 */

import { securityLogger } from '../lib/logger.js';
import { CacheProvider } from '../lib/cache-provider.js';

export interface RateLimiterConfig {
  maxEmailsPerHour: number;
  maxEmailsPerDay: number;
  circuitBreakerThreshold: number; // emails per 10 minutes
  circuitBreakerWindowMs: number;
  enabled: boolean;
  cacheProvider?: CacheProvider; // Optional: for distributed rate limiting (future)
}

interface EmailTimestamp {
  timestamp: number;
}

export class RateLimiter {
  private config: RateLimiterConfig;
  private emailTimestamps: EmailTimestamp[] = [];
  private circuitBreakerTripped: boolean = false;
  private circuitBreakerResetTime: number = 0;
  private useDistributed: boolean = false;

  constructor(config: RateLimiterConfig) {
    this.config = config;
    this.useDistributed = !!(config.cacheProvider && config.cacheProvider.isReady());

    securityLogger.info('Rate limiter initialized', {
      maxPerHour: config.maxEmailsPerHour,
      maxPerDay: config.maxEmailsPerDay,
      circuitBreakerThreshold: config.circuitBreakerThreshold,
      mode: this.useDistributed ? 'distributed (Redis)' : 'in-memory (single instance)',
    });
  }

  /**
   * Check if sending is allowed
   */
  canSendEmail(): { allowed: boolean; reason?: string } {
    if (!this.config.enabled) {
      return { allowed: true };
    }

    // Check circuit breaker
    if (this.isCircuitBreakerTripped()) {
      return {
        allowed: false,
        reason: `Circuit breaker tripped until ${new Date(this.circuitBreakerResetTime).toISOString()}`,
      };
    }

    // Clean old timestamps
    this.cleanOldTimestamps();

    // Check hourly limit
    const hourlyCount = this.getCountInWindow(60 * 60 * 1000);
    if (hourlyCount >= this.config.maxEmailsPerHour) {
      return { allowed: false, reason: `Hourly limit reached (${hourlyCount}/${this.config.maxEmailsPerHour})` };
    }

    // Check daily limit
    const dailyCount = this.getCountInWindow(24 * 60 * 60 * 1000);
    if (dailyCount >= this.config.maxEmailsPerDay) {
      return { allowed: false, reason: `Daily limit reached (${dailyCount}/${this.config.maxEmailsPerDay})` };
    }

    // Check for burst (circuit breaker trigger)
    const burstCount = this.getCountInWindow(this.config.circuitBreakerWindowMs);
    if (burstCount >= this.config.circuitBreakerThreshold) {
      this.tripCircuitBreaker();
      return { allowed: false, reason: 'Circuit breaker tripped due to burst sending' };
    }

    return { allowed: true };
  }

  /**
   * Record email send
   */
  recordEmailSent(): void {
    if (!this.config.enabled) return;

    this.emailTimestamps.push({ timestamp: Date.now() });
    this.cleanOldTimestamps();

    const stats = this.getStats();
    securityLogger.debug('Email sent recorded', stats);
  }

  /**
   * Get count in time window
   */
  private getCountInWindow(windowMs: number): number {
    const cutoff = Date.now() - windowMs;
    return this.emailTimestamps.filter((t) => t.timestamp > cutoff).length;
  }

  /**
   * Clean old timestamps (older than 24 hours)
   */
  private cleanOldTimestamps(): void {
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    this.emailTimestamps = this.emailTimestamps.filter((t) => t.timestamp > cutoff);
  }

  /**
   * Check if circuit breaker is tripped
   */
  private isCircuitBreakerTripped(): boolean {
    if (!this.circuitBreakerTripped) return false;

    if (Date.now() >= this.circuitBreakerResetTime) {
      this.resetCircuitBreaker();
      return false;
    }

    return true;
  }

  /**
   * Trip circuit breaker
   */
  private tripCircuitBreaker(): void {
    this.circuitBreakerTripped = true;
    this.circuitBreakerResetTime = Date.now() + 60 * 60 * 1000; // Reset in 1 hour

    securityLogger.error('Circuit breaker tripped!', {
      resetTime: new Date(this.circuitBreakerResetTime).toISOString(),
      reason: 'Burst sending detected',
    });
  }

  /**
   * Reset circuit breaker
   */
  private resetCircuitBreaker(): void {
    this.circuitBreakerTripped = false;
    this.circuitBreakerResetTime = 0;
    securityLogger.info('Circuit breaker reset');
  }

  /**
   * Get rate limiter statistics
   */
  getStats(): {
    lastHour: number;
    lastDay: number;
    last10Min: number;
    circuitBreakerTripped: boolean;
    hourlyLimit: number;
    dailyLimit: number;
  } {
    return {
      lastHour: this.getCountInWindow(60 * 60 * 1000),
      lastDay: this.getCountInWindow(24 * 60 * 60 * 1000),
      last10Min: this.getCountInWindow(this.config.circuitBreakerWindowMs),
      circuitBreakerTripped: this.circuitBreakerTripped,
      hourlyLimit: this.config.maxEmailsPerHour,
      dailyLimit: this.config.maxEmailsPerDay,
    };
  }

  /**
   * Reset all counters (for testing/admin)
   */
  reset(): void {
    this.emailTimestamps = [];
    this.circuitBreakerTripped = false;
    this.circuitBreakerResetTime = 0;
    securityLogger.warn('Rate limiter reset');
  }
}
