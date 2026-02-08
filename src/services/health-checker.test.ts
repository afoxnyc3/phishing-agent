import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import type { PhishingAgent } from '../agents/phishing-agent.js';
import type { MailboxMonitor } from './mailbox-monitor.js';
import type { IRateLimiter } from './rate-limiter.js';
import type { IEmailDeduplication } from './email-deduplication.js';

// Mock dependencies using unstable_mockModule for ESM compatibility
jest.unstable_mockModule('../lib/config.js', () => ({
  config: {
    llm: { apiKey: undefined, demoMode: false, timeoutMs: 10000,
      retryAttempts: 3, circuitBreakerThreshold: 5, circuitBreakerResetMs: 60000 },
    threatIntel: { enabled: false, timeoutMs: 5000, cacheTtlMs: 300000 },
  },
}));

jest.unstable_mockModule('../lib/logger.js', () => ({
  securityLogger: {
    info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(),
  },
}));

jest.unstable_mockModule('./llm-analyzer.js', () => ({
  getLlmServiceStatus: jest.fn<any>().mockReturnValue({
    enabled: false, circuitBreakerState: 'not-initialized', consecutiveFailures: 0,
  }),
  healthCheck: jest.fn<any>().mockResolvedValue(true),
}));

// Import after mocks are set up
const { HealthChecker } = await import('./health-checker.js');

describe('HealthChecker', () => {
  let checker: InstanceType<typeof HealthChecker>;
  let mockAgent: jest.Mocked<PhishingAgent>;
  let mockMonitor: jest.Mocked<MailboxMonitor>;
  let mockRateLimiter: jest.Mocked<IRateLimiter>;
  let mockDeduplication: jest.Mocked<IEmailDeduplication>;

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
      healthCheck: jest.fn<() => Promise<boolean>>(),
      getStatus: jest.fn<() => Promise<{
        isRunning: boolean;
        mailbox: string;
        lastCheckTime: Date;
        checkInterval: number;
        rateLimitStats: unknown;
        deduplicationStats: unknown;
      }>>(),
    } as unknown as jest.Mocked<MailboxMonitor>;

    // Mock rate limiter with async methods (interfaces are async)
    mockRateLimiter = {
      canSendEmail: jest.fn<() => Promise<{ allowed: boolean; reason?: string }>>(),
      recordEmailSent: jest.fn<() => Promise<void>>(),
      getStats: jest.fn<() => Promise<{
        lastHour: number;
        lastDay: number;
        last10Min: number;
        circuitBreakerTripped: boolean;
        hourlyLimit: number;
        dailyLimit: number;
      }>>(),
      reset: jest.fn<() => Promise<void>>(),
    } as jest.Mocked<IRateLimiter>;

    // Mock deduplication with async methods (interfaces are async)
    mockDeduplication = {
      shouldProcess: jest.fn<() => Promise<{ allowed: boolean; reason?: string }>>(),
      recordProcessed: jest.fn<() => Promise<void>>(),
      getStats: jest.fn<() => Promise<{
        processedEmailsCount: number;
        uniqueSendersCount: number;
        enabled: boolean;
      }>>(),
      reset: jest.fn<() => Promise<void>>(),
    } as jest.Mocked<IEmailDeduplication>;
  });

  describe('checkHealth', () => {
    it('should return healthy when all components are healthy', async () => {
      mockAgent.healthCheck.mockResolvedValue(true);
      mockMonitor.healthCheck.mockResolvedValue(true);
      mockMonitor.getStatus.mockResolvedValue({
        isRunning: true,
        mailbox: 'test@example.com',
        lastCheckTime: new Date(),
        checkInterval: 60000,
        rateLimitStats: {
          lastHour: 0,
          lastDay: 0,
          last10Min: 0,
          circuitBreakerTripped: false,
          hourlyLimit: 100,
          dailyLimit: 1000,
        },
        deduplicationStats: {
          processedEmailsCount: 0,
          uniqueSendersCount: 0,
          enabled: true,
        },
      });
      mockRateLimiter.getStats.mockResolvedValue({
        circuitBreakerTripped: false,
        lastHour: 5,
        lastDay: 10,
        last10Min: 1,
        hourlyLimit: 100,
        dailyLimit: 1000,
      });
      mockDeduplication.getStats.mockResolvedValue({
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
      mockRateLimiter.getStats.mockResolvedValue({
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
      mockRateLimiter.getStats.mockResolvedValue({
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
      mockDeduplication.getStats.mockResolvedValue({
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
