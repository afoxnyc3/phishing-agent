/**
 * Azure Authentication Tests
 * Tests for Azure credential creation and Graph client initialization
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';

// Mock the logger
jest.unstable_mockModule('../lib/logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

// Mock Azure Identity
const mockDefaultAzureCredential = jest.fn<() => object>();
const mockClientSecretCredential = jest.fn<() => object>();

jest.unstable_mockModule('@azure/identity', () => ({
  DefaultAzureCredential: mockDefaultAzureCredential.mockImplementation(() => ({
    getToken: jest.fn<() => Promise<{ token: string }>>().mockResolvedValue({ token: 'mock-managed-identity-token' }),
  })),
  ClientSecretCredential: mockClientSecretCredential.mockImplementation(() => ({
    getToken: jest.fn<() => Promise<{ token: string }>>().mockResolvedValue({ token: 'mock-client-secret-token' }),
  })),
}));

// Mock Microsoft Graph Client
const mockInitWithMiddleware = jest.fn<() => object>().mockReturnValue({
  api: jest.fn().mockReturnThis(),
  get: jest.fn<() => Promise<object>>().mockResolvedValue({}),
});

jest.unstable_mockModule('@microsoft/microsoft-graph-client', () => ({
  Client: {
    initWithMiddleware: mockInitWithMiddleware,
  },
}));

const { createAzureCredential, createGraphClient } = await import('./azure-auth.js');

describe('Azure Authentication', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
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

        expect(mockClientSecretCredential).toHaveBeenCalledWith(
          'test-tenant',
          'test-client',
          'test-secret'
        );
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
