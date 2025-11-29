/**
 * Azure Key Vault Tests
 * Tests for secret loading from Azure Key Vault
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';

// Mock the logger
jest.unstable_mockModule('./logger.js', () => ({
  securityLogger: {
    info: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
    debug: jest.fn(),
  },
}));

// Create mock functions that we can control
const mockGetSecret = jest.fn<() => Promise<{ value: string | undefined }>>();

// Mock Azure SDK
jest.unstable_mockModule('@azure/identity', () => ({
  DefaultAzureCredential: jest.fn().mockImplementation(() => ({})),
}));

jest.unstable_mockModule('@azure/keyvault-secrets', () => ({
  SecretClient: jest.fn().mockImplementation(() => ({
    getSecret: mockGetSecret,
  })),
}));

const { loadSecretsFromKeyVault, isKeyVaultConfigured } = await import('./keyvault.js');

describe('Azure Key Vault', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    jest.clearAllMocks();
    process.env = { ...originalEnv };
    // Clear relevant env vars
    delete process.env.AZURE_KEY_VAULT_NAME;
    delete process.env.NODE_ENV;
    delete process.env.AZURE_TENANT_ID;
    delete process.env.AZURE_CLIENT_ID;
    delete process.env.AZURE_CLIENT_SECRET;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe('isKeyVaultConfigured', () => {
    it('should return false when AZURE_KEY_VAULT_NAME is not set', () => {
      delete process.env.AZURE_KEY_VAULT_NAME;
      expect(isKeyVaultConfigured()).toBe(false);
    });

    it('should return true when AZURE_KEY_VAULT_NAME is set', () => {
      process.env.AZURE_KEY_VAULT_NAME = 'my-vault';
      expect(isKeyVaultConfigured()).toBe(true);
    });

    it('should return false for empty string', () => {
      process.env.AZURE_KEY_VAULT_NAME = '';
      expect(isKeyVaultConfigured()).toBe(false);
    });
  });

  describe('loadSecretsFromKeyVault', () => {
    describe('when Key Vault is not configured', () => {
      it('should skip loading in development mode', async () => {
        process.env.NODE_ENV = 'development';
        delete process.env.AZURE_KEY_VAULT_NAME;

        await expect(loadSecretsFromKeyVault()).resolves.not.toThrow();
      });

      it('should skip loading in test mode', async () => {
        process.env.NODE_ENV = 'test';
        delete process.env.AZURE_KEY_VAULT_NAME;

        await expect(loadSecretsFromKeyVault()).resolves.not.toThrow();
      });

      it('should throw error in production mode without Key Vault', async () => {
        process.env.NODE_ENV = 'production';
        delete process.env.AZURE_KEY_VAULT_NAME;

        await expect(loadSecretsFromKeyVault()).rejects.toThrow(
          'SECURITY: AZURE_KEY_VAULT_NAME is required in production'
        );
      });
    });

    describe('when Key Vault is configured', () => {
      beforeEach(() => {
        process.env.AZURE_KEY_VAULT_NAME = 'test-vault';
        process.env.NODE_ENV = 'development';
      });

      it('should load secrets and set environment variables', async () => {
        mockGetSecret
          .mockResolvedValueOnce({ value: 'tenant-123' })
          .mockResolvedValueOnce({ value: 'client-123' })
          .mockResolvedValueOnce({ value: 'secret-123' })
          .mockResolvedValueOnce({ value: 'vt-key' })
          .mockResolvedValueOnce({ value: 'abuse-key' })
          .mockResolvedValueOnce({ value: 'urlscan-key' })
          .mockResolvedValueOnce({ value: 'anthropic-key' });

        await loadSecretsFromKeyVault();

        expect(process.env.AZURE_TENANT_ID).toBe('tenant-123');
        expect(process.env.AZURE_CLIENT_ID).toBe('client-123');
        expect(process.env.AZURE_CLIENT_SECRET).toBe('secret-123');
      });

      it('should handle missing secrets gracefully', async () => {
        mockGetSecret.mockResolvedValue({ value: undefined });

        await expect(loadSecretsFromKeyVault()).resolves.not.toThrow();
      });

      it('should handle individual secret access errors gracefully', async () => {
        // Individual getSecret errors are caught and return undefined
        // This tests that behavior - no error should be thrown
        mockGetSecret.mockImplementation(() => {
          throw new Error('Access denied');
        });

        // The function catches individual errors, so this should not throw
        await expect(loadSecretsFromKeyVault()).resolves.not.toThrow();
      });
    });
  });
});
