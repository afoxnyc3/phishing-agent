/**
 * Subscription Factory Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../lib/logger.js', () => ({
  securityLogger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { mockInitialize } = vi.hoisted(() => ({
  mockInitialize: vi.fn<any>(),
}));

vi.mock('./subscription-manager.js', () => {
  return {
    SubscriptionManager: class MockSubscriptionManager {
      initialize = mockInitialize;
      stop = vi.fn();
      getState = vi.fn();
    },
  };
});

vi.mock('./subscription-lifecycle.js', () => ({
  setCatchUpPollCallback: vi.fn(),
}));

const { isSubscriptionConfigured, buildSubscriptionConfig, createSubscriptionManager } =
  await import('./subscription-factory.js');
const { setCatchUpPollCallback } = await import('./subscription-lifecycle.js');
const { securityLogger } = await import('../lib/logger.js');

function createWebhookConfig(overrides: Record<string, unknown> = {}) {
  return {
    enabled: true,
    notificationUrl: 'https://app.example.com/webhooks/mail',
    clientState: 'test-secret',
    resource: 'users/test@test.com/messages',
    renewalMarginMs: 7200000,
    ...overrides,
  };
}

describe('isSubscriptionConfigured', () => {
  it('should return true when fully configured', () => {
    expect(isSubscriptionConfigured(createWebhookConfig())).toBe(true);
  });

  it('should return false when disabled', () => {
    expect(isSubscriptionConfigured(createWebhookConfig({ enabled: false }))).toBe(false);
  });

  it('should return false when notificationUrl is missing', () => {
    expect(isSubscriptionConfigured(createWebhookConfig({ notificationUrl: undefined }))).toBe(false);
  });

  it('should return false when clientState is missing', () => {
    expect(isSubscriptionConfigured(createWebhookConfig({ clientState: undefined }))).toBe(false);
  });
});

describe('buildSubscriptionConfig', () => {
  it('should build config from webhook settings', () => {
    const config = buildSubscriptionConfig(createWebhookConfig(), 'mailbox@test.com');

    expect(config).toEqual({
      notificationUrl: 'https://app.example.com/webhooks/mail',
      clientState: 'test-secret',
      resource: 'users/test@test.com/messages',
      renewalMarginMs: 7200000,
    });
  });

  it('should use default resource when not specified', () => {
    const config = buildSubscriptionConfig(createWebhookConfig({ resource: undefined }), 'phishing@company.com');

    expect(config.resource).toBe('users/phishing@company.com/messages');
  });
});

describe('createSubscriptionManager', () => {
  const mockClient = {} as any;
  const mockCatchUpPoll = vi.fn<any>().mockResolvedValue(undefined);

  beforeEach(() => {
    vi.clearAllMocks();
    mockInitialize.mockResolvedValue(undefined);
  });

  it('should return undefined when not configured', async () => {
    const result = await createSubscriptionManager(
      mockClient,
      createWebhookConfig({ enabled: false }),
      'test@test.com',
      mockCatchUpPoll
    );

    expect(result).toBeUndefined();
    expect(securityLogger.info).toHaveBeenCalledWith('Webhook subscription disabled or not configured');
  });

  it('should create and initialize manager when configured', async () => {
    const result = await createSubscriptionManager(mockClient, createWebhookConfig(), 'test@test.com', mockCatchUpPoll);

    expect(result).toBeDefined();
    expect(mockInitialize).toHaveBeenCalled();
  });

  it('should register catch-up poll callback', async () => {
    await createSubscriptionManager(mockClient, createWebhookConfig(), 'test@test.com', mockCatchUpPoll);

    expect(setCatchUpPollCallback).toHaveBeenCalledWith(mockCatchUpPoll);
  });

  it('should return undefined when notificationUrl is missing', async () => {
    const result = await createSubscriptionManager(
      mockClient,
      createWebhookConfig({ notificationUrl: undefined }),
      'test@test.com',
      mockCatchUpPoll
    );

    expect(result).toBeUndefined();
  });
});
