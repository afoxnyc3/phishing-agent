/**
 * Subscription Manager Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../lib/logger.js', () => ({
  securityLogger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock('./subscription-lifecycle.js', () => ({
  handleLifecycleEvent: vi.fn(),
}));

const { SubscriptionManager } = await import('./subscription-manager.js');
const { handleLifecycleEvent } = await import('./subscription-lifecycle.js');
const { securityLogger } = await import('../lib/logger.js');

function createMockGraphClient() {
  return {
    api: vi.fn<any>().mockReturnThis(),
    post: vi.fn<any>(),
    patch: vi.fn<any>(),
    get: vi.fn<any>(),
  } as any;
}

function createDefaultConfig() {
  return {
    notificationUrl: 'https://app.example.com/webhooks/mail',
    clientState: 'test-secret-state',
    resource: 'users/phishing@test.com/messages',
    renewalMarginMs: 7200000,
  };
}

function mockSubscriptionResponse(id = 'sub-123', minutesFromNow = 4230) {
  const expiry = new Date(Date.now() + minutesFromNow * 60 * 1000);
  return { id, expirationDateTime: expiry.toISOString() };
}

describe('SubscriptionManager', () => {
  let client: ReturnType<typeof createMockGraphClient>;
  let manager: InstanceType<typeof SubscriptionManager>;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    client = createMockGraphClient();
    manager = new SubscriptionManager(client, createDefaultConfig());
  });

  afterEach(() => {
    manager.stop();
    vi.useRealTimers();
  });

  describe('Constructor', () => {
    it('should initialize with inactive state', () => {
      const state = manager.getState();
      expect(state.subscriptionId).toBeNull();
      expect(state.expirationDateTime).toBeNull();
      expect(state.isActive).toBe(false);
    });
  });

  describe('initialize()', () => {
    it('should create a new subscription when none exists', async () => {
      client.api.mockReturnValue({
        get: vi.fn<any>().mockResolvedValue({ value: [] }),
        post: vi.fn<any>().mockResolvedValue(mockSubscriptionResponse()),
      });

      await manager.initialize();

      const state = manager.getState();
      expect(state.subscriptionId).toBe('sub-123');
      expect(state.isActive).toBe(true);
    });

    it('should reuse an existing subscription', async () => {
      const existingSub = {
        id: 'existing-sub',
        resource: 'users/phishing@test.com/messages',
        notificationUrl: 'https://app.example.com/webhooks/mail',
        expirationDateTime: new Date(Date.now() + 86400000).toISOString(),
      };
      client.api.mockReturnValue({
        get: vi.fn<any>().mockResolvedValue({ value: [existingSub] }),
        post: vi.fn<any>(),
      });

      await manager.initialize();

      const state = manager.getState();
      expect(state.subscriptionId).toBe('existing-sub');
      expect(state.isActive).toBe(true);
    });

    it('should log error and schedule retry when initialization fails', async () => {
      client.api.mockReturnValue({
        get: vi.fn<any>().mockRejectedValue(new Error('Network error')),
      });

      await expect(manager.initialize()).resolves.toBeUndefined();
      expect(securityLogger.error).toHaveBeenCalledWith(
        'Subscription initialization failed',
        expect.objectContaining({ error: 'Network error' })
      );
      expect(securityLogger.warn).toHaveBeenCalledWith(
        'Scheduling subscription retry',
        expect.objectContaining({ retryMs: 60000 })
      );
    });

    it('should not match subscriptions with different resource', async () => {
      const otherSub = {
        id: 'other-sub',
        resource: 'users/other@test.com/messages',
        notificationUrl: 'https://app.example.com/webhooks/mail',
        expirationDateTime: new Date(Date.now() + 86400000).toISOString(),
      };
      const mockApi = {
        get: vi.fn<any>().mockResolvedValue({ value: [otherSub] }),
        post: vi.fn<any>().mockResolvedValue(mockSubscriptionResponse('new-sub')),
      };
      client.api.mockReturnValue(mockApi);

      await manager.initialize();

      expect(manager.getState().subscriptionId).toBe('new-sub');
    });
  });

  describe('createSubscription()', () => {
    it('should create subscription with correct parameters', async () => {
      const mockPost = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse());
      client.api.mockReturnValue({ post: mockPost });

      await manager.createSubscription();

      expect(client.api).toHaveBeenCalledWith('/subscriptions');
      expect(mockPost).toHaveBeenCalledWith(
        expect.objectContaining({
          changeType: 'created',
          notificationUrl: 'https://app.example.com/webhooks/mail',
          resource: 'users/phishing@test.com/messages',
          clientState: 'test-secret-state',
          expirationDateTime: expect.any(String),
        })
      );
    });

    it('should return true and set active state after creation', async () => {
      const mockPost = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse());
      client.api.mockReturnValue({ post: mockPost });

      const result = await manager.createSubscription();

      expect(result).toBe(true);
      const state = manager.getState();
      expect(state.subscriptionId).toBe('sub-123');
      expect(state.isActive).toBe(true);
      expect(state.expirationDateTime).toBeInstanceOf(Date);
    });

    it('should return false and log error when creation fails', async () => {
      client.api.mockReturnValue({
        post: vi.fn<any>().mockRejectedValue(new Error('Forbidden')),
      });

      const result = await manager.createSubscription();

      expect(result).toBe(false);
      expect(securityLogger.error).toHaveBeenCalledWith(
        'Failed to create subscription',
        expect.objectContaining({ error: 'Forbidden' })
      );
      expect(manager.getState().isActive).toBe(false);
    });
  });

  describe('renewSubscription()', () => {
    it('should renew an existing subscription', async () => {
      // First create
      const mockPost = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse('sub-1'));
      client.api.mockReturnValue({ post: mockPost });
      await manager.createSubscription();

      // Then renew
      const renewed = mockSubscriptionResponse('sub-1', 4230);
      const mockPatch = vi.fn<any>().mockResolvedValue(renewed);
      client.api.mockReturnValue({ patch: mockPatch });

      await manager.renewSubscription();

      expect(client.api).toHaveBeenCalledWith('/subscriptions/sub-1');
      expect(mockPatch).toHaveBeenCalledWith(expect.objectContaining({ expirationDateTime: expect.any(String) }));
    });

    it('should create new subscription when no existing subscription to renew', async () => {
      const mockPost = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse('new-sub'));
      client.api.mockReturnValue({ post: mockPost });

      await manager.renewSubscription();

      expect(securityLogger.warn).toHaveBeenCalledWith('No subscription to renew, creating new one');
      expect(manager.getState().subscriptionId).toBe('new-sub');
    });

    it('should recreate subscription when renewal fails', async () => {
      // First create
      const mockPost = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse('sub-1'));
      client.api.mockReturnValue({ post: mockPost });
      await manager.createSubscription();

      // Renewal fails, then recreate succeeds
      const mockPatch = vi.fn<any>().mockRejectedValue(new Error('Not found'));
      const mockPostNew = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse('sub-2'));
      let callCount = 0;
      client.api.mockImplementation(() => {
        callCount++;
        if (callCount === 1) return { patch: mockPatch };
        return { post: mockPostNew };
      });

      await manager.renewSubscription();

      expect(securityLogger.error).toHaveBeenCalledWith('Failed to renew subscription', expect.any(Object));
      expect(securityLogger.warn).toHaveBeenCalledWith('Renewal failed, attempting to recreate subscription');
    });

    it('should schedule retry when both renewal and recreation fail', async () => {
      // First create
      const mockPost = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse('sub-1'));
      client.api.mockReturnValue({ post: mockPost });
      await manager.createSubscription();

      // Both renewal and recreation fail
      client.api.mockReturnValue({
        patch: vi.fn<any>().mockRejectedValue(new Error('Not found')),
        post: vi.fn<any>().mockRejectedValue(new Error('Service unavailable')),
      });

      await manager.renewSubscription();

      expect(securityLogger.warn).toHaveBeenCalledWith(
        'Scheduling subscription retry',
        expect.objectContaining({ retryMs: 60000 })
      );
    });
  });

  describe('Auto-renewal scheduling', () => {
    it('should schedule renewal after subscription creation', async () => {
      const mockPost = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse('sub-1'));
      client.api.mockReturnValue({ post: mockPost });

      await manager.createSubscription();

      expect(securityLogger.debug).toHaveBeenCalledWith(
        'Scheduling subscription renewal',
        expect.objectContaining({ renewInMs: expect.any(Number) })
      );
    });

    it('should trigger renewal before expiry', async () => {
      // Create with short expiry for testing
      const shortExpiry = new Date(Date.now() + 3 * 60 * 60 * 1000); // 3 hours
      const mockPost = vi.fn<any>().mockResolvedValue({
        id: 'sub-1',
        expirationDateTime: shortExpiry.toISOString(),
      });
      client.api.mockReturnValue({ post: mockPost });
      await manager.createSubscription();

      // Renewal should happen at (3h - 2h margin) = 1h from now
      const mockPatch = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse('sub-1'));
      client.api.mockReturnValue({ patch: mockPatch });

      // Advance just past the 1-hour mark
      await vi.advanceTimersByTimeAsync(1 * 60 * 60 * 1000 + 1000);

      expect(mockPatch).toHaveBeenCalled();
    });

    it('should renew immediately if expiry is within margin', async () => {
      // Create with expiry within the renewal margin (30 min, margin is 2h)
      const shortExpiry = new Date(Date.now() + 30 * 60 * 1000);
      const mockPost = vi.fn<any>().mockResolvedValue({
        id: 'sub-1',
        expirationDateTime: shortExpiry.toISOString(),
      });
      client.api.mockReturnValue({ post: mockPost });
      await manager.createSubscription();

      // Should renew immediately (renewInMs = 0)
      const mockPatch = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse('sub-1'));
      client.api.mockReturnValue({ patch: mockPatch });

      await vi.advanceTimersByTimeAsync(100);

      expect(mockPatch).toHaveBeenCalled();
    });
  });

  describe('handleLifecycleNotification()', () => {
    it('should delegate to handleLifecycleEvent', async () => {
      await manager.handleLifecycleNotification('subscriptionRemoved');

      expect(handleLifecycleEvent).toHaveBeenCalledWith('subscriptionRemoved', manager);
    });

    it('should pass missed event type', async () => {
      await manager.handleLifecycleNotification('missed');

      expect(handleLifecycleEvent).toHaveBeenCalledWith('missed', manager);
    });

    it('should pass reauthorizationRequired event type', async () => {
      await manager.handleLifecycleNotification('reauthorizationRequired');

      expect(handleLifecycleEvent).toHaveBeenCalledWith('reauthorizationRequired', manager);
    });
  });

  describe('stop()', () => {
    it('should set isActive to false', async () => {
      const mockPost = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse());
      client.api.mockReturnValue({ post: mockPost });
      await manager.createSubscription();
      expect(manager.getState().isActive).toBe(true);

      manager.stop();

      expect(manager.getState().isActive).toBe(false);
    });

    it('should clear renewal timer', async () => {
      const mockPost = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse());
      client.api.mockReturnValue({ post: mockPost });
      await manager.createSubscription();

      manager.stop();

      // Advancing time should not trigger renewal
      const mockPatch = vi.fn<any>();
      client.api.mockReturnValue({ patch: mockPatch });
      await vi.advanceTimersByTimeAsync(86400000);
      expect(mockPatch).not.toHaveBeenCalled();
    });

    it('should be safe to call when not initialized', () => {
      expect(() => manager.stop()).not.toThrow();
    });

    it('should log stop message', () => {
      manager.stop();
      expect(securityLogger.info).toHaveBeenCalledWith('Subscription manager stopped');
    });
  });

  describe('getState()', () => {
    it('should return a copy of the state', async () => {
      const mockPost = vi.fn<any>().mockResolvedValue(mockSubscriptionResponse());
      client.api.mockReturnValue({ post: mockPost });
      await manager.createSubscription();

      const state1 = manager.getState();
      const state2 = manager.getState();

      expect(state1).toEqual(state2);
      expect(state1).not.toBe(state2);
    });
  });

  describe('Default renewal margin', () => {
    it('should use default margin when not specified', () => {
      const mgr = new SubscriptionManager(client, {
        notificationUrl: 'https://app.example.com/webhooks/mail',
        clientState: 'test',
        resource: 'users/test@test.com/messages',
      });
      expect(mgr).toBeDefined();
    });
  });
});
