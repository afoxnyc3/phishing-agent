/**
 * Mail Monitor Timer Fallback Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// Mock logger
vi.mock('../lib/logger.js', () => ({
  securityLogger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    security: vi.fn(),
  },
}));

// Hoist mock functions for email-fetcher and email-processor
const { mockFetchNewEmails, mockProcessEmail } = vi.hoisted(() => ({
  mockFetchNewEmails: vi.fn<any>(),
  mockProcessEmail: vi.fn<any>(),
}));

vi.mock('./email-fetcher.js', () => ({
  fetchNewEmails: mockFetchNewEmails,
}));

vi.mock('./email-processor.js', () => ({
  processEmail: mockProcessEmail,
  evaluateEmailGuards: vi.fn(),
  __testResetMessageIdCache: vi.fn(),
}));

const { MailMonitor } = await import('./mail-monitor.js');
const { securityLogger } = await import('../lib/logger.js');

// Helper to create mock dependencies
function createMockDeps() {
  return {
    graphClient: {} as any,
    phishingAgent: { analyzeEmail: vi.fn(), initialize: vi.fn(), shutdown: vi.fn(), healthCheck: vi.fn() } as any,
    rateLimiter: { canSendEmail: vi.fn(), recordEmailSent: vi.fn(), getStats: vi.fn() } as any,
    deduplication: {
      shouldProcess: vi.fn().mockResolvedValue({ allowed: true }),
      recordProcessed: vi.fn(),
      getStats: vi.fn(),
      reset: vi.fn(),
    } as any,
  };
}

function createDefaultConfig(overrides: Record<string, unknown> = {}) {
  return {
    enabled: true,
    intervalMs: 3600000,
    lookbackMs: 7200000,
    mailboxAddress: 'phishing@test.com',
    maxPages: 5,
    ...overrides,
  };
}

function createMockEmail(id: string, subject: string = 'Test Subject') {
  return {
    id,
    internetMessageId: `<${id}@example.com>`,
    subject,
    from: { emailAddress: { address: 'sender@example.com' } },
    toRecipients: [{ emailAddress: { address: 'phishing@test.com' } }],
    receivedDateTime: new Date().toISOString(),
    body: { content: `Body for ${id}` },
  };
}

describe('MailMonitor', () => {
  let monitor: InstanceType<typeof MailMonitor>;
  let deps: ReturnType<typeof createMockDeps>;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    deps = createMockDeps();
    monitor = new MailMonitor(createDefaultConfig(), deps);
  });

  afterEach(() => {
    monitor.stop();
    vi.useRealTimers();
  });

  describe('Constructor', () => {
    it('should initialize with default metrics', () => {
      const metrics = monitor.getMetrics();
      expect(metrics.pollCount).toBe(0);
      expect(metrics.emailsFoundByTimer).toBe(0);
      expect(metrics.emailsAlreadyProcessed).toBe(0);
      expect(metrics.lastPollTime).toBeNull();
      expect(metrics.lastPollDurationMs).toBe(0);
      expect(metrics.errors).toBe(0);
    });

    it('should not be running initially', () => {
      expect(monitor.getIsRunning()).toBe(false);
    });

    it('should report enabled status from config', () => {
      expect(monitor.isEnabled()).toBe(true);
    });
  });

  describe('start()', () => {
    it('should set running to true when enabled', () => {
      monitor.start();
      expect(monitor.getIsRunning()).toBe(true);
    });

    it('should log startup message', () => {
      monitor.start();
      expect(securityLogger.info).toHaveBeenCalledWith(
        'Mail monitor timer started',
        expect.objectContaining({ intervalMs: 3600000, lookbackMs: 7200000 })
      );
    });

    it('should not start when disabled', () => {
      const disabled = new MailMonitor(createDefaultConfig({ enabled: false }), deps);
      disabled.start();
      expect(disabled.getIsRunning()).toBe(false);
      expect(securityLogger.info).toHaveBeenCalledWith('Mail monitor timer disabled via config');
    });

    it('should not start twice', () => {
      monitor.start();
      monitor.start();
      expect(monitor.getIsRunning()).toBe(true);
      expect(securityLogger.warn).toHaveBeenCalledWith('Mail monitor timer already running');
    });

    it('should schedule first poll after intervalMs', async () => {
      mockFetchNewEmails.mockResolvedValue([]);
      monitor.start();

      // Before interval, no poll should have happened
      expect(mockFetchNewEmails).not.toHaveBeenCalled();

      // Advance past the interval
      await vi.advanceTimersByTimeAsync(3600000);
      expect(mockFetchNewEmails).toHaveBeenCalledTimes(1);
    });
  });

  describe('stop()', () => {
    it('should set running to false', () => {
      monitor.start();
      expect(monitor.getIsRunning()).toBe(true);
      monitor.stop();
      expect(monitor.getIsRunning()).toBe(false);
    });

    it('should log stop message', () => {
      monitor.start();
      monitor.stop();
      expect(securityLogger.info).toHaveBeenCalledWith('Mail monitor timer stopped');
    });

    it('should be safe to call when not running', () => {
      monitor.stop();
      expect(monitor.getIsRunning()).toBe(false);
    });

    it('should prevent further polls after stop', async () => {
      mockFetchNewEmails.mockResolvedValue([]);
      monitor.start();

      await vi.advanceTimersByTimeAsync(3600000);
      expect(mockFetchNewEmails).toHaveBeenCalledTimes(1);

      monitor.stop();

      // Advance time further - should not poll again
      await vi.advanceTimersByTimeAsync(3600000);
      expect(mockFetchNewEmails).toHaveBeenCalledTimes(1);
    });
  });

  describe('poll()', () => {
    it('should return 0 when no emails found', async () => {
      mockFetchNewEmails.mockResolvedValue([]);
      const result = await monitor.poll();
      expect(result).toBe(0);
    });

    it('should fetch emails with correct lookback window', async () => {
      mockFetchNewEmails.mockResolvedValue([]);
      const now = Date.now();

      await monitor.poll();

      expect(mockFetchNewEmails).toHaveBeenCalledWith(
        deps.graphClient,
        { mailboxAddress: 'phishing@test.com', maxPages: 5 },
        expect.any(String)
      );

      // Verify the lookback date is approximately 2 hours ago
      const callArgs = mockFetchNewEmails.mock.calls[0];
      const lookbackDate = new Date(callArgs[2]);
      const expectedDate = new Date(now - 7200000);
      expect(Math.abs(lookbackDate.getTime() - expectedDate.getTime())).toBeLessThan(1000);
    });

    it('should process found emails via processEmail', async () => {
      const email1 = createMockEmail('email-1');
      const email2 = createMockEmail('email-2', 'Different Subject');
      mockFetchNewEmails.mockResolvedValue([email1, email2]);
      mockProcessEmail.mockResolvedValue(undefined);

      const result = await monitor.poll();

      expect(result).toBe(2);
      expect(mockProcessEmail).toHaveBeenCalledTimes(2);
    });

    it('should pass correct config to processEmail', async () => {
      const email = createMockEmail('email-1');
      mockFetchNewEmails.mockResolvedValue([email]);
      mockProcessEmail.mockResolvedValue(undefined);

      await monitor.poll();

      expect(mockProcessEmail).toHaveBeenCalledWith(email, {
        mailboxAddress: 'phishing@test.com',
        graphClient: deps.graphClient,
        phishingAgent: deps.phishingAgent,
        rateLimiter: deps.rateLimiter,
        deduplication: deps.deduplication,
      });
    });

    it('should increment pollCount on each poll', async () => {
      mockFetchNewEmails.mockResolvedValue([]);
      await monitor.poll();
      await monitor.poll();
      await monitor.poll();
      expect(monitor.getMetrics().pollCount).toBe(3);
    });

    it('should track emailsFoundByTimer for processed emails', async () => {
      mockFetchNewEmails.mockResolvedValue([createMockEmail('e1'), createMockEmail('e2', 'Diff')]);
      mockProcessEmail.mockResolvedValue(undefined);

      await monitor.poll();

      expect(monitor.getMetrics().emailsFoundByTimer).toBe(2);
    });

    it('should track emailsAlreadyProcessed when processEmail throws', async () => {
      const email1 = createMockEmail('e1');
      const email2 = createMockEmail('e2', 'Different');
      mockFetchNewEmails.mockResolvedValue([email1, email2]);
      mockProcessEmail.mockRejectedValueOnce(new Error('Already processed')).mockResolvedValueOnce(undefined);

      await monitor.poll();

      const metrics = monitor.getMetrics();
      expect(metrics.emailsFoundByTimer).toBe(1);
      expect(metrics.emailsAlreadyProcessed).toBe(1);
    });

    it('should update lastPollTime after poll', async () => {
      mockFetchNewEmails.mockResolvedValue([]);
      expect(monitor.getMetrics().lastPollTime).toBeNull();

      await monitor.poll();

      expect(monitor.getMetrics().lastPollTime).toBeInstanceOf(Date);
    });

    it('should track lastPollDurationMs', async () => {
      mockFetchNewEmails.mockImplementation(async () => {
        await new Promise((r) => setTimeout(r, 50));
        return [];
      });

      await vi.advanceTimersByTimeAsync(0);
      const pollPromise = monitor.poll();
      await vi.advanceTimersByTimeAsync(50);
      await pollPromise;

      expect(monitor.getMetrics().lastPollDurationMs).toBeGreaterThanOrEqual(0);
    });

    it('should accumulate metrics across multiple polls', async () => {
      mockFetchNewEmails.mockResolvedValue([createMockEmail('e1')]);
      mockProcessEmail.mockResolvedValue(undefined);

      await monitor.poll();
      await monitor.poll();

      const metrics = monitor.getMetrics();
      expect(metrics.pollCount).toBe(2);
      expect(metrics.emailsFoundByTimer).toBe(2);
    });
  });

  describe('Error handling', () => {
    it('should handle fetchNewEmails errors gracefully', async () => {
      mockFetchNewEmails.mockRejectedValue(new Error('Graph API failure'));

      const result = await monitor.poll();

      expect(result).toBe(0);
      expect(monitor.getMetrics().errors).toBe(1);
      expect(securityLogger.error).toHaveBeenCalledWith(
        'Mail monitor poll failed',
        expect.objectContaining({ error: 'Graph API failure' })
      );
    });

    it('should continue processing remaining emails if one fails', async () => {
      const emails = [createMockEmail('e1'), createMockEmail('e2', 'Different Subject')];
      mockFetchNewEmails.mockResolvedValue(emails);
      mockProcessEmail.mockRejectedValueOnce(new Error('Failed')).mockResolvedValueOnce(undefined);

      const result = await monitor.poll();

      expect(result).toBe(1);
      expect(mockProcessEmail).toHaveBeenCalledTimes(2);
    });

    it('should log errors for individual email processing failures', async () => {
      mockFetchNewEmails.mockResolvedValue([createMockEmail('e1')]);
      mockProcessEmail.mockRejectedValue(new Error('Process failed'));

      await monitor.poll();

      expect(securityLogger.error).toHaveBeenCalledWith(
        'Mail monitor: failed to process email',
        expect.objectContaining({ emailId: 'e1', error: 'Process failed' })
      );
    });

    it('should increment error counter on fetch failure', async () => {
      mockFetchNewEmails.mockRejectedValue(new Error('Network error'));

      await monitor.poll();
      await monitor.poll();

      expect(monitor.getMetrics().errors).toBe(2);
    });

    it('should still update lastPollTime on error', async () => {
      mockFetchNewEmails.mockRejectedValue(new Error('Error'));

      await monitor.poll();

      expect(monitor.getMetrics().lastPollTime).toBeInstanceOf(Date);
    });
  });

  describe('Timer scheduling', () => {
    it('should schedule recurring polls at configured interval', async () => {
      mockFetchNewEmails.mockResolvedValue([]);
      monitor.start();

      // First poll at 1 hour
      await vi.advanceTimersByTimeAsync(3600000);
      expect(mockFetchNewEmails).toHaveBeenCalledTimes(1);

      // Second poll at 2 hours
      await vi.advanceTimersByTimeAsync(3600000);
      expect(mockFetchNewEmails).toHaveBeenCalledTimes(2);
    });

    it('should use custom interval', async () => {
      mockFetchNewEmails.mockResolvedValue([]);
      const custom = new MailMonitor(createDefaultConfig({ intervalMs: 60000 }), deps);
      custom.start();

      await vi.advanceTimersByTimeAsync(60000);
      expect(mockFetchNewEmails).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(60000);
      expect(mockFetchNewEmails).toHaveBeenCalledTimes(2);

      custom.stop();
    });

    it('should continue polling even after an error', async () => {
      mockFetchNewEmails.mockRejectedValueOnce(new Error('Temporary error')).mockResolvedValue([]);

      monitor.start();

      await vi.advanceTimersByTimeAsync(3600000);
      expect(mockFetchNewEmails).toHaveBeenCalledTimes(1);

      await vi.advanceTimersByTimeAsync(3600000);
      expect(mockFetchNewEmails).toHaveBeenCalledTimes(2);
    });
  });

  describe('getMetrics()', () => {
    it('should return a copy of metrics (not a reference)', async () => {
      mockFetchNewEmails.mockResolvedValue([]);
      await monitor.poll();

      const metrics1 = monitor.getMetrics();
      const metrics2 = monitor.getMetrics();

      expect(metrics1).toEqual(metrics2);
      expect(metrics1).not.toBe(metrics2);
    });
  });

  describe('isEnabled()', () => {
    it('should return true when enabled', () => {
      expect(monitor.isEnabled()).toBe(true);
    });

    it('should return false when disabled', () => {
      const disabled = new MailMonitor(createDefaultConfig({ enabled: false }), deps);
      expect(disabled.isEnabled()).toBe(false);
    });
  });

  describe('Logging', () => {
    it('should log when no emails found', async () => {
      mockFetchNewEmails.mockResolvedValue([]);
      await monitor.poll();
      expect(securityLogger.debug).toHaveBeenCalledWith('Mail monitor poll: no emails in lookback window');
    });

    it('should log when emails are found', async () => {
      mockFetchNewEmails.mockResolvedValue([createMockEmail('e1')]);
      mockProcessEmail.mockResolvedValue(undefined);
      await monitor.poll();
      expect(securityLogger.info).toHaveBeenCalledWith(
        'Mail monitor poll: found emails',
        expect.objectContaining({ count: 1 })
      );
    });

    it('should log poll completion with dedup stats', async () => {
      const emails = [createMockEmail('e1'), createMockEmail('e2', 'Different')];
      mockFetchNewEmails.mockResolvedValue(emails);
      mockProcessEmail.mockRejectedValueOnce(new Error('Dedup')).mockResolvedValueOnce(undefined);

      await monitor.poll();

      expect(securityLogger.info).toHaveBeenCalledWith(
        'Mail monitor poll completed',
        expect.objectContaining({
          emailsFound: 2,
          newEmailsProcessed: 1,
          dedupFiltered: 1,
        })
      );
    });
  });
});
