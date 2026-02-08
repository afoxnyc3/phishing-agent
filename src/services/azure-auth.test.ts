/**
 * Azure Authentication Tests
 * Tests for Azure credential creation and Graph client initialization
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// Mock the logger
vi.mock('../lib/logger.js', () => ({
  securityLogger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  },
}));

// Create hoisted mock functions for use inside vi.mock factories
const { mockDefaultAzureCredential, mockClientSecretCredential, mockInitWithMiddleware } = vi.hoisted(() => ({
  mockDefaultAzureCredential: vi.fn<any>(),
  mockClientSecretCredential: vi.fn<any>(),
  mockInitWithMiddleware: vi.fn<any>().mockReturnValue({
    api: vi.fn().mockReturnThis(),
    get: vi.fn<any>().mockResolvedValue({}),
  }),
}));

// Mock Azure Identity
vi.mock('@azure/identity', () => ({
  DefaultAzureCredential: class MockDefaultAzureCredential {
    getToken = vi.fn<any>().mockResolvedValue({ token: 'mock-managed-identity-token' });
    constructor(...args: any[]) {
      mockDefaultAzureCredential(...args);
    }
  },
  ClientSecretCredential: class MockClientSecretCredential {
    getToken = vi.fn<any>().mockResolvedValue({ token: 'mock-client-secret-token' });
    constructor(...args: any[]) {
      mockClientSecretCredential(...args);
    }
  },
}));

// Mock Microsoft Graph Client
vi.mock('@microsoft/microsoft-graph-client', () => ({
  Client: {
    initWithMiddleware: mockInitWithMiddleware,
  },
}));

const { createAzureCredential, createGraphClient } = await import('./azure-auth.js');

describe('Azure Authentication', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('createAzureCredential', () => {
    const baseConfig = {
      tenantId: 'test-tenant',
      clientId: 'test-client',
      clientSecret: 'test-secret',
    };

    describe('auth method selection', () => {
      it('should use Managed Identity in production by default', () => {
        process.env.NODE_ENV = 'production';

        createAzureCredential({ ...baseConfig, authMethod: undefined });

        expect(mockDefaultAzureCredential).toHaveBeenCalled();
        expect(mockClientSecretCredential).not.toHaveBeenCalled();
      });

      it('should use Client Secret in development by default', () => {
        process.env.NODE_ENV = 'development';

        createAzureCredential({ ...baseConfig, authMethod: undefined });

        expect(mockClientSecretCredential).toHaveBeenCalled();
      });

      it('should use Managed Identity when explicitly specified', () => {
        process.env.NODE_ENV = 'development';

        createAzureCredential({ ...baseConfig, authMethod: 'managed-identity' });

        expect(mockDefaultAzureCredential).toHaveBeenCalled();
      });

      it('should use Client Secret when explicitly specified', () => {
        process.env.NODE_ENV = 'production';

        createAzureCredential({ ...baseConfig, authMethod: 'secret' });

        expect(mockClientSecretCredential).toHaveBeenCalled();
      });
    });

    describe('Client Secret authentication', () => {
      it('should create credential with correct parameters', () => {
        process.env.NODE_ENV = 'development';

        createAzureCredential(baseConfig);

        expect(mockClientSecretCredential).toHaveBeenCalledWith('test-tenant', 'test-client', 'test-secret');
      });

      it('should throw error when client secret is missing', () => {
        process.env.NODE_ENV = 'development';

        expect(() =>
          createAzureCredential({
            tenantId: 'test-tenant',
            clientId: 'test-client',
            authMethod: 'secret',
          })
        ).toThrow('AZURE_CLIENT_SECRET is required');
      });
    });

    describe('Managed Identity authentication', () => {
      it('should create DefaultAzureCredential', () => {
        createAzureCredential({ ...baseConfig, authMethod: 'managed-identity' });

        expect(mockDefaultAzureCredential).toHaveBeenCalled();
      });

      it('should work without client secret', () => {
        expect(() =>
          createAzureCredential({
            tenantId: 'test-tenant',
            clientId: 'test-client',
            authMethod: 'managed-identity',
          })
        ).not.toThrow();
      });
    });
  });

  describe('createGraphClient', () => {
    const baseConfig = {
      tenantId: 'test-tenant',
      clientId: 'test-client',
      clientSecret: 'test-secret',
    };

    beforeEach(() => {
      process.env.NODE_ENV = 'development';
    });

    it('should create Graph client with auth provider', () => {
      createGraphClient(baseConfig);

      expect(mockInitWithMiddleware).toHaveBeenCalledWith({
        authProvider: expect.objectContaining({
          getAccessToken: expect.any(Function),
        }),
      });
    });

    it('should return a Graph client instance', () => {
      const client = createGraphClient(baseConfig);

      expect(client).toBeDefined();
      expect(client.api).toBeDefined();
    });

    it('should use correct auth method based on config', () => {
      createGraphClient({ ...baseConfig, authMethod: 'managed-identity' });

      expect(mockDefaultAzureCredential).toHaveBeenCalled();
    });
  });
});
