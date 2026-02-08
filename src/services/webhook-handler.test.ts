/**
 * Webhook Handler Tests
 */

import { describe, it, expect, jest, beforeEach } from '@jest/globals';

jest.unstable_mockModule('../lib/logger.js', () => ({
  securityLogger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() },
}));

const { extractMessageIds, validateClientState, handleValidationHandshake, isValidPayload } =
  await import('./webhook-handler.js');

function mockRes() {
  return {
    status: jest.fn<any>().mockReturnThis(),
    type: jest.fn<any>().mockReturnThis(),
    send: jest.fn<any>().mockReturnThis(),
    json: jest.fn<any>().mockReturnThis(),
  } as any;
}

describe('extractMessageIds', () => {
  it('should extract IDs from created notifications', () => {
    const payload = {
      value: [
        {
          subscriptionId: 's1',
          clientState: 'x',
          changeType: 'created',
          resource: 'r1',
          resourceData: { '@odata.id': 'o1', id: 'msg-1' },
        },
        {
          subscriptionId: 's1',
          clientState: 'x',
          changeType: 'created',
          resource: 'r2',
          resourceData: { '@odata.id': 'o2', id: 'msg-2' },
        },
      ],
    };
    expect(extractMessageIds(payload)).toEqual(['msg-1', 'msg-2']);
  });

  it('should filter out non-created changeTypes', () => {
    const payload = {
      value: [
        {
          subscriptionId: 's1',
          clientState: 'x',
          changeType: 'updated',
          resource: 'r1',
          resourceData: { '@odata.id': 'o1', id: 'msg-1' },
        },
        {
          subscriptionId: 's1',
          clientState: 'x',
          changeType: 'created',
          resource: 'r2',
          resourceData: { '@odata.id': 'o2', id: 'msg-2' },
        },
      ],
    };
    expect(extractMessageIds(payload)).toEqual(['msg-2']);
  });

  it('should return empty array when no created notifications', () => {
    const payload = {
      value: [
        {
          subscriptionId: 's1',
          clientState: 'x',
          changeType: 'deleted',
          resource: 'r1',
          resourceData: { '@odata.id': 'o1', id: 'msg-1' },
        },
      ],
    };
    expect(extractMessageIds(payload)).toEqual([]);
  });
});

describe('validateClientState', () => {
  it('should return true when all notifications match', () => {
    const notifications = [
      {
        subscriptionId: 's1',
        clientState: 'secret-123',
        changeType: 'created',
        resource: 'r1',
        resourceData: { '@odata.id': 'o1', id: 'm1' },
      },
      {
        subscriptionId: 's1',
        clientState: 'secret-123',
        changeType: 'created',
        resource: 'r2',
        resourceData: { '@odata.id': 'o2', id: 'm2' },
      },
    ];
    expect(validateClientState(notifications, 'secret-123')).toBe(true);
  });

  it('should return false when any notification mismatches', () => {
    const notifications = [
      {
        subscriptionId: 's1',
        clientState: 'secret-123',
        changeType: 'created',
        resource: 'r1',
        resourceData: { '@odata.id': 'o1', id: 'm1' },
      },
      {
        subscriptionId: 's1',
        clientState: 'wrong',
        changeType: 'created',
        resource: 'r2',
        resourceData: { '@odata.id': 'o2', id: 'm2' },
      },
    ];
    expect(validateClientState(notifications, 'secret-123')).toBe(false);
  });

  it('should return true for empty array', () => {
    expect(validateClientState([], 'secret')).toBe(true);
  });
});

describe('handleValidationHandshake', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should respond with validation token when present', () => {
    const req = { query: { validationToken: 'abc-token' } } as any;
    const res = mockRes();

    const handled = handleValidationHandshake(req, res);

    expect(handled).toBe(true);
    expect(res.status).toHaveBeenCalledWith(200);
    expect(res.type).toHaveBeenCalledWith('text/plain');
    expect(res.send).toHaveBeenCalledWith('abc-token');
  });

  it('should return false when no validation token', () => {
    const req = { query: {} } as any;
    const res = mockRes();

    const handled = handleValidationHandshake(req, res);

    expect(handled).toBe(false);
    expect(res.status).not.toHaveBeenCalled();
  });
});

describe('isValidPayload', () => {
  it('should accept valid payload', () => {
    expect(isValidPayload({ value: [{ id: 1 }] })).toBe(true);
  });

  it('should reject null', () => {
    expect(isValidPayload(null)).toBe(false);
  });

  it('should reject non-object', () => {
    expect(isValidPayload('string')).toBe(false);
  });

  it('should reject missing value', () => {
    expect(isValidPayload({ other: 'data' })).toBe(false);
  });

  it('should reject empty value array', () => {
    expect(isValidPayload({ value: [] })).toBe(false);
  });

  it('should reject non-array value', () => {
    expect(isValidPayload({ value: 'not-array' })).toBe(false);
  });
});
