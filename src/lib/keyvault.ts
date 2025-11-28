/**
 * Azure Key Vault secrets loader
 * Loads secrets from Key Vault when AZURE_KEY_VAULT_NAME is set
 * Falls back to environment variables for local development
 */

import { DefaultAzureCredential } from '@azure/identity';
import { SecretClient } from '@azure/keyvault-secrets';

/** Secret names in Key Vault (kebab-case) mapped to env var names */
const SECRET_MAPPINGS: Record<string, string> = {
  'azure-tenant-id': 'AZURE_TENANT_ID',
  'azure-client-id': 'AZURE_CLIENT_ID',
  'azure-client-secret': 'AZURE_CLIENT_SECRET',
  'virustotal-api-key': 'VIRUSTOTAL_API_KEY',
  'abuseipdb-api-key': 'ABUSEIPDB_API_KEY',
  'urlscan-api-key': 'URLSCAN_API_KEY',
};

/**
 * Load a single secret from Key Vault
 */
async function getSecret(client: SecretClient, name: string): Promise<string | undefined> {
  try {
    const secret = await client.getSecret(name);
    return secret.value;
  } catch {
    // Secret not found or access denied - return undefined
    return undefined;
  }
}

/**
 * Load all secrets from Key Vault and set them as environment variables
 * This allows the rest of the app to use process.env as usual
 */
export async function loadSecretsFromKeyVault(): Promise<void> {
  const vaultName = process.env.AZURE_KEY_VAULT_NAME;

  if (!vaultName) {
    // No Key Vault configured, use environment variables
    console.log('[KeyVault] No AZURE_KEY_VAULT_NAME set, using environment variables');
    return;
  }

  console.log(`[KeyVault] Loading secrets from ${vaultName}`);

  try {
    const vaultUrl = `https://${vaultName}.vault.azure.net`;
    const credential = new DefaultAzureCredential();
    const client = new SecretClient(vaultUrl, credential);

    // Load all secrets in parallel
    const secretPromises = Object.entries(SECRET_MAPPINGS).map(async ([kvName, envName]) => {
      const value = await getSecret(client, kvName);
      if (value) {
        process.env[envName] = value;
        console.log(`[KeyVault] Loaded ${kvName} -> ${envName}`);
      }
    });

    await Promise.all(secretPromises);
    console.log('[KeyVault] All secrets loaded successfully');
  } catch (error) {
    console.error('[KeyVault] Failed to load secrets:', (error as Error).message);
    throw new Error(`Key Vault initialization failed: ${(error as Error).message}`);
  }
}

/**
 * Check if Key Vault is configured
 */
export function isKeyVaultConfigured(): boolean {
  return !!process.env.AZURE_KEY_VAULT_NAME;
}
