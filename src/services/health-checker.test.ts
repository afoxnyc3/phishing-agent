import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { HealthChecker } from './health-checker.js';
import { PhishingAgent } from '../agents/phishing-agent.js';
import { MailboxMonitor } from './mailbox-monitor.js';
import { RateLimiter } from './rate-limiter.js';
import { EmailDeduplication } from './email-deduplication.js';

describe('HealthChecker', () => {
  let checker: HealthChecker;
  let mockAgent: jest.Mocked<PhishingAgent>;
  let mockMonitor: jest.Mocked<MailboxMonitor>;
  let mockRateLimiter: jest.Mocked<RateLimiter>;
  let mockDeduplication: jest.Mocked<EmailDeduplication>;

  beforeEach(() => {
    checker = new HealthChecker();

    // Mock process.memoryUsage to return predictable, healthy values
    jest.spyOn(process, 'memoryUsage').mockReturnValue({
      rss: 100 * 1024 * 1024, // 100 MB
      heapTotal: 50 * 1024 * 1024, // 50 MB
      heapUsed: 30 * 1024 * 1024, // 30 MB (60% of heap - healthy)
      external: 5 * 1024 * 1024,
      arrayBuffers: 1 * 1024 * 1024,
    });

    mockAgent = {
      healthCheck: jest.fn(),
    } as unknown as jest.Mocked<PhishingAgent>;

    mockMonitor = {
      healthCheck: jest.fn(),
      getStatus: jest.fn(),
    } as unknown as jest.Mocked<MailboxMonitor>;

    mockRateLimiter = {
      getStats: jest.fn(),
    } as unknown as jest.Mocked<RateLimiter>;

    mockDeduplication = {
      getStats: jest.fn(),
    } as unknown as jest.Mocked<EmailDeduplication>;
  });

  describe('checkHealth', () => {
    it('should return healthy when all components are healthy', async () => {
      mockAgent.healthCheck.mockResolvedValue(true);
      mockMonitor.healthCheck.mockResolvedValue(true);
      (mockMonitor.getStatus as jest.Mock).mockReturnValue({
        isRunning: true,
        lastCheckTime: new Date(),
      });
      (mockRateLimiter.getStats as jest.Mock).mockReturnValue({
        circuitBreakerTripped: false,
        lastHour: 5,
        lastDay: 10,
        last10Min: 1,
        hourlyLimit: 100,
        dailyLimit: 1000,
      });
      (mockDeduplication.getStats as jest.Mock).mockReturnValue({
        processedEmailsCount: 10,
        uniqueSendersCount: 5,
        enabled: true,
      });

      checker.setPhishingAgent(mockAgent);
      checker.setMailboxMonitor(mockMonitor);
      checker.setRateLimiter(mockRateLimiter);
      checker.setDeduplication(mockDeduplication);

      const health = await checker.checkHealth();

      expect(health.healthy).toBe(true);
      expect(health.components.phishingAgent.healthy).toBe(true);
      expect(health.components.mailboxMonitor.healthy).toBe(true);
      expect(health.components.rateLimiter.healthy).toBe(true);
      expect(health.components.deduplication.healthy).toBe(true);
      expect(health.components.memory.healthy).toBe(true);
    });

    it('should return unhealthy when phishing agent is unhealthy', async () => {
      mockAgent.healthCheck.mockResolvedValue(false);
      checker.setPhishingAgent(mockAgent);

      const health = await checker.checkHealth();

      expect(health.healthy).toBe(false);
      expect(health.components.phishingAgent.healthy).toBe(false);
    });

    it('should return unhealthy when circuit breaker is tripped', async () => {
      (mockRateLimiter.getStats as jest.Mock).mockReturnValue({
        circuitBreakerTripped: true,
        lastHour: 100,
        lastDay: 500,
        last10Min: 50,
        hourlyLimit: 100,
        dailyLimit: 1000,
      });

      checker.setRateLimiter(mockRateLimiter);

      const health = await checker.checkHealth();

      expect(health.healthy).toBe(false);
      expect(health.components.rateLimiter.healthy).toBe(false);
      expect(health.components.rateLimiter.message).toContain('Circuit breaker tripped');
    });

    it('should handle missing components gracefully', async () => {
      const health = await checker.checkHealth();

      expect(health.components.phishingAgent.healthy).toBe(false);
      expect(health.components.mailboxMonitor.healthy).toBe(false);
      expect(health.components.rateLimiter.healthy).toBe(true); // Optional
      expect(health.components.deduplication.healthy).toBe(true); // Optional
    });

    it('should include component details', async () => {
      mockAgent.healthCheck.mockResolvedValue(true);
      mockMonitor.healthCheck.mockResolvedValue(true);
      (mockMonitor.getStatus as jest.Mock).mockReturnValue({
        isRunning: true,
        lastCheckTime: new Date('2025-01-01T00:00:00Z'),
      });

      checker.setPhishingAgent(mockAgent);
      checker.setMailboxMonitor(mockMonitor);

      const health = await checker.checkHealth();

      expect(health.components.mailboxMonitor.details).toHaveProperty('isRunning');
      expect(health.components.mailboxMonitor.details).toHaveProperty('lastCheckTime');
      expect(health.components.memory.details).toHaveProperty('heapUsedMB');
      expect(health.components.memory.details).toHaveProperty('percentUsed');
    });
  });

  describe('Memory Health', () => {
    it('should report memory usage', async () => {
      const health = await checker.checkHealth();

      expect(health.components.memory.healthy).toBe(true);
      expect(health.components.memory.details).toHaveProperty('heapUsedMB');
      expect(health.components.memory.details).toHaveProperty('heapTotalMB');
      expect(health.components.memory.details).toHaveProperty('percentUsed');
      expect(health.components.memory.details).toHaveProperty('rss');
    });
  });

  describe('Component Details', () => {
    it('should include rate limiter stats', async () => {
      (mockRateLimiter.getStats as jest.Mock).mockReturnValue({
        circuitBreakerTripped: false,
        lastHour: 25,
        lastDay: 100,
        last10Min: 5,
        hourlyLimit: 100,
        dailyLimit: 1000,
      });

      checker.setRateLimiter(mockRateLimiter);

      const health = await checker.checkHealth();

      expect(health.components.rateLimiter.details?.emailsSentLastHour).toBe(25);
      expect(health.components.rateLimiter.details?.emailsSentLastDay).toBe(100);
      expect(health.components.rateLimiter.details?.emailsSentLast10Min).toBe(5);
    });

    it('should include deduplication stats', async () => {
      (mockDeduplication.getStats as jest.Mock).mockReturnValue({
        processedEmailsCount: 42,
        uniqueSendersCount: 15,
        enabled: true,
      });

      checker.setDeduplication(mockDeduplication);

      const health = await checker.checkHealth();

      expect(health.components.deduplication.details?.processedEmailsCount).toBe(42);
      expect(health.components.deduplication.details?.uniqueSendersCount).toBe(15);
    });
  });

  describe('Error Handling', () => {
    it('should handle phishing agent health check errors', async () => {
      mockAgent.healthCheck.mockRejectedValue(new Error('Connection failed'));
      checker.setPhishingAgent(mockAgent);

      const health = await checker.checkHealth();

      expect(health.components.phishingAgent.healthy).toBe(false);
      expect(health.components.phishingAgent.message).toContain('Connection failed');
    });

    it('should handle mailbox monitor health check errors', async () => {
      mockMonitor.healthCheck.mockRejectedValue(new Error('API error'));
      (mockMonitor.getStatus as jest.Mock).mockReturnValue({
        isRunning: false,
        lastCheckTime: new Date(),
      });
      checker.setMailboxMonitor(mockMonitor);

      const health = await checker.checkHealth();

      expect(health.components.mailboxMonitor.healthy).toBe(false);
      expect(health.components.mailboxMonitor.message).toContain('API error');
    });
  });
});
