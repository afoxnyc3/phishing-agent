/**
 * Subscription Lifecycle Handler Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../lib/logger.js', () => ({
  securityLogger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { handleLifecycleEvent, setCatchUpPollCallback, getCatchUpPollCallback } =
  await import('./subscription-lifecycle.js');
const { securityLogger } = await import('../lib/logger.js');

function createMockManager() {
  return {
    createSubscription: vi.fn<any>().mockResolvedValue(undefined),
    renewSubscription: vi.fn<any>().mockResolvedValue(undefined),
  };
}

describe('handleLifecycleEvent', () => {
  let manager: ReturnType<typeof createMockManager>;

  beforeEach(() => {
    vi.clearAllMocks();
    manager = createMockManager();
    setCatchUpPollCallback(null as any);
  });

  describe('subscriptionRemoved', () => {
    it('should recreate the subscription', async () => {
      await handleLifecycleEvent('subscriptionRemoved', manager);

      expect(manager.createSubscription).toHaveBeenCalledTimes(1);
      expect(securityLogger.warn).toHaveBeenCalledWith('Subscription removed by Graph API, recreating');
      expect(securityLogger.info).toHaveBeenCalledWith('Subscription recreated after removal');
    });

    it('should log error when recreation fails', async () => {
      manager.createSubscription.mockRejectedValue(new Error('API error'));

      await handleLifecycleEvent('subscriptionRemoved', manager);

      expect(securityLogger.error).toHaveBeenCalledWith(
        'Failed to recreate subscription after removal',
        expect.objectContaining({ error: 'API error' })
      );
    });
  });

  describe('missed', () => {
    it('should trigger catch-up poll when callback is set', async () => {
      const mockPoll = vi.fn<any>().mockResolvedValue(undefined);
      setCatchUpPollCallback(mockPoll);

      await handleLifecycleEvent('missed', manager);

      expect(mockPoll).toHaveBeenCalledTimes(1);
      expect(securityLogger.info).toHaveBeenCalledWith('Catch-up poll completed after missed notifications');
    });

    it('should log warning when no callback is registered', async () => {
      setCatchUpPollCallback(null as any);

      await handleLifecycleEvent('missed', manager);

      expect(securityLogger.warn).toHaveBeenCalledWith('No catch-up poll callback registered');
    });

    it('should log error when catch-up poll fails', async () => {
      const mockPoll = vi.fn<any>().mockRejectedValue(new Error('Poll failed'));
      setCatchUpPollCallback(mockPoll);

      await handleLifecycleEvent('missed', manager);

      expect(securityLogger.error).toHaveBeenCalledWith(
        'Catch-up poll failed',
        expect.objectContaining({ error: 'Poll failed' })
      );
    });
  });

  describe('reauthorizationRequired', () => {
    it('should renew the subscription', async () => {
      await handleLifecycleEvent('reauthorizationRequired', manager);

      expect(manager.renewSubscription).toHaveBeenCalledTimes(1);
      expect(securityLogger.info).toHaveBeenCalledWith('Subscription renewed after reauthorization request');
    });

    it('should log error when renewal fails', async () => {
      manager.renewSubscription.mockRejectedValue(new Error('Auth error'));

      await handleLifecycleEvent('reauthorizationRequired', manager);

      expect(securityLogger.error).toHaveBeenCalledWith(
        'Failed to renew subscription after reauthorization request',
        expect.objectContaining({ error: 'Auth error' })
      );
    });
  });

  describe('unknown event type', () => {
    it('should log warning for unknown event type', async () => {
      await handleLifecycleEvent('unknown' as any, manager);

      expect(securityLogger.warn).toHaveBeenCalledWith(
        'Unknown lifecycle event type',
        expect.objectContaining({ eventType: 'unknown' })
      );
    });
  });

  describe('logging', () => {
    it('should log lifecycle event reception for all types', async () => {
      await handleLifecycleEvent('subscriptionRemoved', manager);

      expect(securityLogger.warn).toHaveBeenCalledWith(
        'Subscription lifecycle event received',
        expect.objectContaining({ eventType: 'subscriptionRemoved' })
      );
    });
  });
});

describe('setCatchUpPollCallback', () => {
  beforeEach(() => {
    setCatchUpPollCallback(null as any);
  });

  it('should register a callback', () => {
    const callback = vi.fn<any>();
    setCatchUpPollCallback(callback);
    expect(getCatchUpPollCallback()).toBe(callback);
  });

  it('should overwrite existing callback', () => {
    const callback1 = vi.fn<any>();
    const callback2 = vi.fn<any>();
    setCatchUpPollCallback(callback1);
    setCatchUpPollCallback(callback2);
    expect(getCatchUpPollCallback()).toBe(callback2);
  });
});
