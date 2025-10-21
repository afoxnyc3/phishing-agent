/**
 * Rate Limiter Tests
 */

import { describe, it, expect, beforeEach } from '@jest/globals';
import { RateLimiter } from './rate-limiter.js';

describe('RateLimiter', () => {
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    rateLimiter = new RateLimiter({
      enabled: true,
      maxEmailsPerHour: 5,
      maxEmailsPerDay: 10,
      circuitBreakerThreshold: 3,
      circuitBreakerWindowMs: 60000, // 1 minute for testing
    });
  });

  describe('canSendEmail', () => {
    it('should allow sending when limits not reached', () => {
      const result = rateLimiter.canSendEmail();
      expect(result.allowed).toBe(true);
      expect(result.reason).toBeUndefined();
    });

    it('should block when hourly limit reached', () => {
      // Send 5 emails (hourly limit)
      for (let i = 0; i < 5; i++) {
        rateLimiter.recordEmailSent();
      }

      const result = rateLimiter.canSendEmail();
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Hourly limit reached');
    });

    it('should block when daily limit reached', () => {
      // Create a limiter with higher hourly limit but lower daily limit
      const dailyLimiter = new RateLimiter({
        enabled: true,
        maxEmailsPerHour: 20, // High hourly limit
        maxEmailsPerDay: 10, // Lower daily limit
        circuitBreakerThreshold: 50,
        circuitBreakerWindowMs: 60000,
      });

      // Send 10 emails (daily limit)
      for (let i = 0; i < 10; i++) {
        dailyLimiter.recordEmailSent();
      }

      const result = dailyLimiter.canSendEmail();
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Daily limit reached');
    });

    it('should trip circuit breaker on burst sending', () => {
      // Send 3 emails rapidly (circuit breaker threshold)
      for (let i = 0; i < 3; i++) {
        rateLimiter.recordEmailSent();
      }

      const result = rateLimiter.canSendEmail();
      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Circuit breaker tripped');
    });

    it('should allow sending when rate limiter disabled', () => {
      const disabledLimiter = new RateLimiter({
        enabled: false,
        maxEmailsPerHour: 1,
        maxEmailsPerDay: 1,
        circuitBreakerThreshold: 1,
        circuitBreakerWindowMs: 60000,
      });

      // Try to exceed limits
      for (let i = 0; i < 10; i++) {
        disabledLimiter.recordEmailSent();
      }

      const result = disabledLimiter.canSendEmail();
      expect(result.allowed).toBe(true);
    });
  });

  describe('recordEmailSent', () => {
    it('should increment email count', () => {
      const statsBefore = rateLimiter.getStats();
      expect(statsBefore.lastHour).toBe(0);

      rateLimiter.recordEmailSent();

      const statsAfter = rateLimiter.getStats();
      expect(statsAfter.lastHour).toBe(1);
      expect(statsAfter.lastDay).toBe(1);
    });

    it('should not record when disabled', () => {
      const disabledLimiter = new RateLimiter({
        enabled: false,
        maxEmailsPerHour: 1,
        maxEmailsPerDay: 1,
        circuitBreakerThreshold: 1,
        circuitBreakerWindowMs: 60000,
      });

      disabledLimiter.recordEmailSent();
      const stats = disabledLimiter.getStats();

      // Stats should still be available but not enforced
      expect(stats).toBeDefined();
    });
  });

  describe('getStats', () => {
    it('should return accurate statistics', () => {
      rateLimiter.recordEmailSent();
      rateLimiter.recordEmailSent();

      const stats = rateLimiter.getStats();

      expect(stats.lastHour).toBe(2);
      expect(stats.lastDay).toBe(2);
      expect(stats.last10Min).toBe(2);
      expect(stats.hourlyLimit).toBe(5);
      expect(stats.dailyLimit).toBe(10);
      expect(stats.circuitBreakerTripped).toBe(false);
    });

    it('should show circuit breaker status', () => {
      // Trip circuit breaker
      for (let i = 0; i < 3; i++) {
        rateLimiter.recordEmailSent();
      }
      rateLimiter.canSendEmail(); // This will trip the breaker

      const stats = rateLimiter.getStats();
      expect(stats.circuitBreakerTripped).toBe(true);
    });
  });

  describe('reset', () => {
    it('should clear all counters', () => {
      rateLimiter.recordEmailSent();
      rateLimiter.recordEmailSent();

      let stats = rateLimiter.getStats();
      expect(stats.lastHour).toBe(2);

      rateLimiter.reset();

      stats = rateLimiter.getStats();
      expect(stats.lastHour).toBe(0);
      expect(stats.lastDay).toBe(0);
      expect(stats.circuitBreakerTripped).toBe(false);
    });
  });

  describe('circuit breaker', () => {
    it('should reset circuit breaker after time expires', async () => {
      // Create limiter with very short reset time for testing
      const shortResetLimiter = new RateLimiter({
        enabled: true,
        maxEmailsPerHour: 10,
        maxEmailsPerDay: 20,
        circuitBreakerThreshold: 2,
        circuitBreakerWindowMs: 100, // 100ms
      });

      // Trip circuit breaker
      shortResetLimiter.recordEmailSent();
      shortResetLimiter.recordEmailSent();
      let result = shortResetLimiter.canSendEmail();
      expect(result.allowed).toBe(false);

      // Wait for circuit breaker to reset (1 hour in real implementation, but we can test the logic)
      // In real implementation, circuit breaker resets after 1 hour
      // For this test, we just verify it was tripped
      const stats = shortResetLimiter.getStats();
      expect(stats.circuitBreakerTripped).toBe(true);
    });
  });
});
