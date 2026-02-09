/**
 * Notification Queue Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../lib/logger.js', () => ({
  securityLogger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const mockFetchEmailById = vi.fn();
vi.mock('./email-fetcher.js', () => ({
  fetchEmailById: (...args: unknown[]) => mockFetchEmailById(...args),
}));

const mockProcessEmail = vi.fn();
vi.mock('./email-processor.js', () => ({
  processEmail: (...args: unknown[]) => mockProcessEmail(...args),
}));

const { NotificationQueue } = await import('./notification-queue.js');
import type { NotificationQueueConfig, QueueDeps } from './notification-queue.js';

const mockGraphClient = { api: vi.fn() };
const mockEmail = { id: 'msg-1', subject: 'Test Email' };

function createConfig(overrides: Partial<NotificationQueueConfig> = {}): NotificationQueueConfig {
  return {
    enabled: true,
    maxRetries: 3,
    backoffMs: 50,
    maxBackoffMs: 500,
    concurrency: 2,
    drainIntervalMs: 25,
    ...overrides,
  };
}

function createDeps(): QueueDeps {
  return {
    processorConfig: {
      mailboxAddress: 'test@example.com',
      graphClient: mockGraphClient as any,
      phishingAgent: {} as any,
      rateLimiter: {} as any,
      deduplication: {} as any,
    },
  };
}

describe('NotificationQueue', () => {
  let queue: InstanceType<typeof NotificationQueue>;

  beforeEach(() => {
    vi.clearAllMocks();
    mockFetchEmailById.mockResolvedValue(mockEmail);
    mockProcessEmail.mockResolvedValue(undefined);
  });

  afterEach(() => {
    queue?.stop();
  });

  describe('enqueue', () => {
    it('should add items to the queue', () => {
      queue = new NotificationQueue(createConfig(), createDeps());
      queue.start();
      queue.enqueue(['msg-1', 'msg-2']);
      const metrics = queue.getMetrics();
      expect(metrics.pending).toBe(2);
      expect(metrics.totalEnqueued).toBe(2);
    });

    it('should deduplicate message IDs', () => {
      queue = new NotificationQueue(createConfig(), createDeps());
      queue.start();
      queue.enqueue(['msg-1', 'msg-1', 'msg-2']);
      expect(queue.getMetrics().pending).toBe(2);
      expect(queue.getMetrics().totalEnqueued).toBe(2);
    });

    it('should not re-enqueue pending items', () => {
      queue = new NotificationQueue(createConfig(), createDeps());
      queue.start();
      queue.enqueue(['msg-1']);
      queue.enqueue(['msg-1']);
      expect(queue.getMetrics().totalEnqueued).toBe(1);
    });

    it('should reject enqueue when stopped', () => {
      queue = new NotificationQueue(createConfig(), createDeps());
      queue.enqueue(['msg-1']);
      expect(queue.getMetrics().pending).toBe(0);
      expect(queue.getMetrics().totalEnqueued).toBe(0);
    });
  });

  describe('processing', () => {
    it('should process enqueued items on drain', async () => {
      queue = new NotificationQueue(createConfig(), createDeps());
      queue.start();
      queue.enqueue(['msg-1']);

      await vi.waitFor(() => {
        expect(queue.getMetrics().totalProcessed).toBe(1);
      });

      expect(queue.getMetrics().pending).toBe(0);
      expect(mockFetchEmailById).toHaveBeenCalledWith(mockGraphClient, 'test@example.com', 'msg-1');
      expect(mockProcessEmail).toHaveBeenCalledWith(
        mockEmail,
        expect.objectContaining({ mailboxAddress: 'test@example.com' })
      );
    });

    it('should process multiple items concurrently', async () => {
      queue = new NotificationQueue(createConfig({ concurrency: 3 }), createDeps());
      queue.start();
      queue.enqueue(['msg-1', 'msg-2', 'msg-3']);

      await vi.waitFor(() => {
        expect(queue.getMetrics().totalProcessed).toBe(3);
      });

      expect(queue.getMetrics().pending).toBe(0);
    });
  });

  describe('retry and dead letter', () => {
    it('should retry failed items', async () => {
      mockFetchEmailById.mockRejectedValueOnce(new Error('Network error')).mockResolvedValue(mockEmail);

      queue = new NotificationQueue(createConfig({ backoffMs: 10 }), createDeps());
      queue.start();
      queue.enqueue(['msg-1']);

      await vi.waitFor(() => {
        expect(queue.getMetrics().totalProcessed).toBe(1);
      });

      expect(mockFetchEmailById).toHaveBeenCalledTimes(2);
    });

    it('should move to dead letter after max retries', async () => {
      mockFetchEmailById.mockRejectedValue(new Error('Permanent failure'));

      queue = new NotificationQueue(createConfig({ maxRetries: 2, backoffMs: 10 }), createDeps());
      queue.start();
      queue.enqueue(['msg-1']);

      await vi.waitFor(() => {
        expect(queue.getMetrics().totalFailed).toBe(1);
      });

      expect(queue.getMetrics().pending).toBe(0);
      expect(queue.getMetrics().deadLetterCount).toBe(1);
      expect(queue.getDeadLetterItems()).toHaveLength(1);
      expect(queue.getDeadLetterItems()[0].messageId).toBe('msg-1');
    });
  });

  describe('backoff calculation', () => {
    it('should calculate exponential backoff', () => {
      queue = new NotificationQueue(createConfig({ backoffMs: 100, maxBackoffMs: 5000 }), createDeps());
      expect(queue.calculateBackoff(1)).toBe(100);
      expect(queue.calculateBackoff(2)).toBe(200);
      expect(queue.calculateBackoff(3)).toBe(400);
    });

    it('should cap backoff at maxBackoffMs', () => {
      queue = new NotificationQueue(createConfig({ backoffMs: 1000, maxBackoffMs: 5000 }), createDeps());
      expect(queue.calculateBackoff(10)).toBe(5000);
    });
  });

  describe('lifecycle', () => {
    it('should not process after stop', async () => {
      queue = new NotificationQueue(createConfig(), createDeps());
      queue.start();
      queue.stop();
      queue.enqueue(['msg-1']);
      // Enqueue after stop should be rejected
      await new Promise((r) => setTimeout(r, 100));
      expect(queue.getMetrics().totalProcessed).toBe(0);
      expect(queue.getMetrics().pending).toBe(0);
    });

    it('should stop cleanly', () => {
      queue = new NotificationQueue(createConfig(), createDeps());
      queue.start();
      queue.stop();
      // Should not throw on double stop
      queue.stop();
    });

    it('should report metrics accurately', async () => {
      mockFetchEmailById
        .mockResolvedValueOnce(mockEmail)
        .mockRejectedValueOnce(new Error('fail'))
        .mockRejectedValueOnce(new Error('fail'));

      queue = new NotificationQueue(createConfig({ maxRetries: 1, backoffMs: 10 }), createDeps());
      queue.start();
      queue.enqueue(['msg-ok', 'msg-fail']);

      await vi.waitFor(() => {
        const m = queue.getMetrics();
        return expect(m.totalProcessed + m.totalFailed).toBe(2);
      });

      const metrics = queue.getMetrics();
      expect(metrics.totalEnqueued).toBe(2);
      expect(metrics.totalProcessed).toBe(1);
      expect(metrics.totalFailed).toBe(1);
    });
  });
});
