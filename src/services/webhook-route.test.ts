/**
 * Webhook Route Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../lib/logger.js', () => ({
  securityLogger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

const { createWebhookRouter } = await import('./webhook-route.js');

function mockReq(overrides: Record<string, unknown> = {}) {
  return { query: {}, body: {}, ...overrides } as any;
}

function mockRes() {
  const res = {
    status: vi.fn<any>().mockReturnThis(),
    type: vi.fn<any>().mockReturnThis(),
    send: vi.fn<any>().mockReturnThis(),
    json: vi.fn<any>().mockReturnThis(),
  };
  return res;
}

function getRouteHandler(clientState: string, onNotification?: (ids: string[]) => void) {
  const router = createWebhookRouter(clientState, onNotification);
  // Extract the POST /webhooks/mail handler from the router stack
  const layer = router.stack.find((l: any) => l.route?.path === '/webhooks/mail' && l.route?.methods?.post);
  return layer?.route?.stack?.[0]?.handle;
}

const CLIENT_STATE = 'test-webhook-secret';

function validPayload(clientState = CLIENT_STATE) {
  return {
    value: [
      {
        subscriptionId: 'sub-1',
        clientState,
        changeType: 'created',
        resource: 'users/mailbox/messages/msg-1',
        resourceData: { '@odata.id': 'odata-1', id: 'msg-1' },
      },
    ],
  };
}

describe('Webhook Route', () => {
  let handler: any;

  beforeEach(() => {
    vi.clearAllMocks();
    handler = getRouteHandler(CLIENT_STATE);
  });

  it('should create a router with POST /webhooks/mail', () => {
    expect(handler).toBeDefined();
  });

  it('should handle validation handshake', () => {
    const req = mockReq({ query: { validationToken: 'my-token' } });
    const res = mockRes();

    handler(req, res);

    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.type).toHaveBeenCalledWith('text/plain');
    expect(res.send).toHaveBeenCalledWith('my-token');
  });

  it('should return 400 for invalid payload', () => {
    const req = mockReq({ body: { invalid: true } });
    const res = mockRes();

    handler(req, res);

    expect(res.status).toHaveBeenCalledWith(400);
    expect(res.json).toHaveBeenCalledWith({ error: 'Invalid payload' });
  });

  it('should return 403 for wrong clientState', () => {
    const req = mockReq({ body: validPayload('wrong-state') });
    const res = mockRes();

    handler(req, res);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'Forbidden' });
  });

  it('should return 202 for valid notification', () => {
    const req = mockReq({ body: validPayload() });
    const res = mockRes();

    handler(req, res);

    expect(res.status).toHaveBeenCalledWith(202);
    expect(res.json).toHaveBeenCalledWith({ status: 'accepted' });
  });

  it('should accept multiple notifications', () => {
    const payload = {
      value: [
        {
          subscriptionId: 's1',
          clientState: CLIENT_STATE,
          changeType: 'created',
          resource: 'r1',
          resourceData: { '@odata.id': 'o1', id: 'msg-1' },
        },
        {
          subscriptionId: 's1',
          clientState: CLIENT_STATE,
          changeType: 'created',
          resource: 'r2',
          resourceData: { '@odata.id': 'o2', id: 'msg-2' },
        },
      ],
    };
    const req = mockReq({ body: payload });
    const res = mockRes();

    handler(req, res);

    expect(res.status).toHaveBeenCalledWith(202);
  });

  describe('notification callback', () => {
    it('should call onNotification with message IDs', () => {
      const callback = vi.fn();
      const cbHandler = getRouteHandler(CLIENT_STATE, callback);
      const req = mockReq({ body: validPayload() });
      const res = mockRes();

      cbHandler(req, res);

      expect(callback).toHaveBeenCalledWith(['msg-1']);
      expect(res.status).toHaveBeenCalledWith(202);
    });

    it('should not call onNotification for empty message IDs', () => {
      const callback = vi.fn();
      const cbHandler = getRouteHandler(CLIENT_STATE, callback);
      const payload = {
        value: [
          {
            subscriptionId: 's1',
            clientState: CLIENT_STATE,
            changeType: 'updated',
            resource: 'r1',
            resourceData: { '@odata.id': 'o1', id: 'msg-1' },
          },
        ],
      };
      const req = mockReq({ body: payload });
      const res = mockRes();

      cbHandler(req, res);

      expect(callback).not.toHaveBeenCalled();
    });

    it('should not fail when no callback is provided', () => {
      const noCallbackHandler = getRouteHandler(CLIENT_STATE);
      const req = mockReq({ body: validPayload() });
      const res = mockRes();

      noCallbackHandler(req, res);

      expect(res.status).toHaveBeenCalledWith(202);
    });
  });
});
