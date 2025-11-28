/**
 * Azure Authentication
 * Creates Azure credentials for Microsoft Graph API access
 */

import { Client } from '@microsoft/microsoft-graph-client';
import { ClientSecretCredential, DefaultAzureCredential, TokenCredential } from '@azure/identity';
import { securityLogger } from '../lib/logger.js';

export type AzureAuthMethod = 'secret' | 'managed-identity';

export interface AzureAuthConfig {
  tenantId: string;
  clientId: string;
  clientSecret?: string;
  authMethod?: AzureAuthMethod;
}

/**
 * Create Azure credential based on auth method
 * Production: defaults to Managed Identity for passwordless auth
 * Development: defaults to Client Secret for local testing
 */
export function createAzureCredential(config: AzureAuthConfig): TokenCredential {
  const isProduction = process.env.NODE_ENV === 'production';
  const authMethod = config.authMethod || (isProduction ? 'managed-identity' : 'secret');

  if (authMethod === 'managed-identity') {
    securityLogger.info('Using Managed Identity for Graph API authentication', {
      method: 'DefaultAzureCredential',
      clientId: config.clientId,
    });
    return new DefaultAzureCredential();
  }

  if (!config.clientSecret) {
    throw new Error(
      'AZURE_CLIENT_SECRET is required when using secret-based authentication. ' +
        'Set AZURE_AUTH_METHOD=managed-identity to use passwordless auth.'
    );
  }

  securityLogger.info('Using Client Secret for Graph API authentication', {
    method: 'ClientSecretCredential',
    tenantId: config.tenantId,
    clientId: config.clientId,
  });

  return new ClientSecretCredential(config.tenantId, config.clientId, config.clientSecret);
}

/**
 * Create Microsoft Graph API client with Azure credentials
 */
export function createGraphClient(config: AzureAuthConfig): Client {
  const credential = createAzureCredential(config);

  return Client.initWithMiddleware({
    authProvider: {
      getAccessToken: async () => {
        const token = await credential.getToken('https://graph.microsoft.com/.default');
        return token?.token || '';
      },
    },
  });
}
