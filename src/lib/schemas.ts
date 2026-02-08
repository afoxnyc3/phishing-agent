/**
 * Zod Runtime Validation Schemas
 * Provides type-safe validation for external data sources
 */

import { z } from 'zod';

// ============================================================================
// Environment Configuration Schemas
// ============================================================================

export const EnvConfigSchema = z
  .object({
    // Azure configuration
    AZURE_TENANT_ID: z.string().min(1, 'Azure Tenant ID is required'),
    AZURE_CLIENT_ID: z.string().min(1, 'Azure Client ID is required'),
    AZURE_CLIENT_SECRET: z.string().optional(),
    AZURE_KEY_VAULT_NAME: z.string().optional(),
    AZURE_AUTH_METHOD: z.enum(['secret', 'managed-identity']).optional().default('secret'),

    // Sender allowlist configuration (fail-closed in production)
    ALLOWED_SENDER_EMAILS: z.string().optional(),
    ALLOWED_SENDER_DOMAINS: z.string().optional(),

    // Mailbox configuration
    PHISHING_MAILBOX_ADDRESS: z.string().email('Invalid mailbox email address'),
    MAILBOX_CHECK_INTERVAL_MS: z.coerce.number().int().positive().default(60000),
    MAILBOX_MONITOR_ENABLED: z.coerce.boolean().default(true),
    MAILBOX_MAX_PAGES: z.coerce.number().int().positive().default(5),
    MAILBOX_PARALLEL_LIMIT: z.coerce.number().int().positive().default(5),

    // Polling control (disable 60s polling when confident in webhooks)
    POLLING_ENABLED: z.coerce.boolean().default(true),

    // Mail monitor timer fallback (safety net for missed webhooks)
    MAIL_MONITOR_ENABLED: z.coerce.boolean().default(true),
    MAIL_MONITOR_INTERVAL_MS: z.coerce.number().int().positive().default(3600000), // 1 hour
    MAIL_MONITOR_LOOKBACK_MS: z.coerce.number().int().positive().default(7200000), // 2 hours

    // Threat Intel configuration
    THREAT_INTEL_ENABLED: z.coerce.boolean().default(true),
    THREAT_INTEL_TIMEOUT_MS: z.coerce.number().int().positive().default(5000),
    THREAT_INTEL_CACHE_TTL_MS: z.coerce.number().int().positive().default(300000),
    VIRUSTOTAL_API_KEY: z.string().optional(),
    ABUSEIPDB_API_KEY: z.string().optional(),
    URLSCAN_API_KEY: z.string().optional(),

    // Rate Limiting configuration
    RATE_LIMIT_ENABLED: z.coerce.boolean().default(true),
    MAX_EMAILS_PER_HOUR: z.coerce.number().int().positive().default(100),
    MAX_EMAILS_PER_DAY: z.coerce.number().int().positive().default(1000),
    CIRCUIT_BREAKER_THRESHOLD: z.coerce.number().int().positive().default(50),
    CIRCUIT_BREAKER_WINDOW_MS: z.coerce.number().int().positive().default(600000), // 10 minutes

    // Email Deduplication configuration
    DEDUPLICATION_ENABLED: z.coerce.boolean().default(true),
    DEDUPLICATION_TTL_MS: z.coerce.number().int().positive().default(86400000), // 24 hours
    SENDER_COOLDOWN_MS: z.coerce.number().int().positive().default(86400000), // 24 hours

    // Redis configuration (optional - enables distributed state)
    REDIS_URL: z.string().url().optional(),
    REDIS_KEY_PREFIX: z.string().default('phishing-agent:'),

    // Webhook subscription configuration
    WEBHOOK_NOTIFICATION_URL: z.string().url().optional(),
    WEBHOOK_CLIENT_STATE: z.string().min(1).optional(),
    WEBHOOK_SUBSCRIPTION_RESOURCE: z.string().optional(),
    WEBHOOK_SUBSCRIPTION_ENABLED: z.coerce.boolean().default(true),
    WEBHOOK_RENEWAL_MARGIN_MS: z.coerce.number().int().positive().default(7200000), // 2 hours

    // HTTP server configuration
    PORT: z.coerce.number().int().positive().default(3000),
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    HTTP_BODY_LIMIT: z.string().default('100kb'),
    HELMET_ENABLED: z.coerce.boolean().default(true),
    HEALTH_CACHE_TTL_MS: z.coerce.number().int().positive().default(30000), // 30 seconds

    // API authentication
    API_KEY: z.string().optional(),
    HEALTH_API_KEY: z.string().optional(),
    METRICS_API_KEY: z.string().optional(),

    // LLM configuration (optional - enables Claude-enhanced analysis)
    ANTHROPIC_API_KEY: z.string().optional(),
    LLM_DEMO_MODE: z.coerce.boolean().default(false),
    LLM_TIMEOUT_MS: z.coerce.number().int().positive().default(10000), // 10 seconds
    LLM_RETRY_ATTEMPTS: z.coerce.number().int().min(0).max(5).default(3),
    LLM_CIRCUIT_BREAKER_THRESHOLD: z.coerce.number().int().positive().default(5),
    LLM_CIRCUIT_BREAKER_RESET_MS: z.coerce.number().int().positive().default(60000), // 1 minute
  })
  .superRefine((data, ctx) => {
    // Production-only validations (fail-fast at startup)
    if (data.NODE_ENV === 'production') {
      // Require Key Vault in production
      if (!data.AZURE_KEY_VAULT_NAME) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'AZURE_KEY_VAULT_NAME is required in production. Secrets must be loaded from Key Vault.',
          path: ['AZURE_KEY_VAULT_NAME'],
        });
      }

      // Require at least one sender allowlist in production
      if (!data.ALLOWED_SENDER_EMAILS && !data.ALLOWED_SENDER_DOMAINS) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            'At least one of ALLOWED_SENDER_EMAILS or ALLOWED_SENDER_DOMAINS is required in production (fail-closed).',
          path: ['ALLOWED_SENDER_EMAILS'],
        });
      }

      // Require API key for ops endpoints in production
      if (!data.API_KEY && !data.HEALTH_API_KEY && !data.METRICS_API_KEY) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'API_KEY is required in production to protect operational endpoints.',
          path: ['API_KEY'],
        });
      }

      // Require either Managed Identity or client secret for Graph auth
      if (data.AZURE_AUTH_METHOD === 'secret' && !data.AZURE_CLIENT_SECRET) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message:
            'AZURE_CLIENT_SECRET is required when AZURE_AUTH_METHOD is "secret". Use AZURE_AUTH_METHOD=managed-identity for passwordless auth.',
          path: ['AZURE_CLIENT_SECRET'],
        });
      }
    }
  });

export type EnvConfig = z.infer<typeof EnvConfigSchema>;

// ============================================================================
// Email Schemas
// ============================================================================

export const EmailAttachmentSchema = z.object({
  filename: z.string(),
  contentType: z.string(),
  size: z.number().int().nonnegative(),
  hash: z.string().optional(),
});

export const EmailHeadersSchema = z
  .object({
    'message-id': z.string(),
    from: z.string(),
    to: z.string(),
    subject: z.string(),
    date: z.string(),
    'received-spf': z.string().optional(),
    'authentication-results': z.string().optional(),
    'dmarc-results': z.string().optional(),
    'x-originating-ip': z.string().optional(),
    'reply-to': z.string().optional(),
    received: z.string().optional(),
  })
  .catchall(z.string().optional());

export const EmailAnalysisRequestSchema = z.object({
  messageId: z.string().min(1, 'Message ID is required'),
  subject: z.string(),
  sender: z.string().email('Invalid sender email'),
  recipient: z.string().email('Invalid recipient email'),
  timestamp: z.date(),
  headers: EmailHeadersSchema,
  body: z.string().optional(),
  attachments: z.array(EmailAttachmentSchema).optional(),
});

export type EmailAnalysisRequest = z.infer<typeof EmailAnalysisRequestSchema>;
export type EmailHeaders = z.infer<typeof EmailHeadersSchema>;
export type EmailAttachment = z.infer<typeof EmailAttachmentSchema>;

// ============================================================================
// Phishing Analysis Schemas
// ============================================================================

export const ThreatIndicatorSchema = z.object({
  type: z.enum(['header', 'content', 'url', 'attachment', 'sender', 'behavioral']),
  description: z.string(),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  evidence: z.string(),
  confidence: z.number().min(0).max(1),
});

export const RecommendedActionSchema = z.object({
  priority: z.enum(['low', 'medium', 'high', 'urgent']),
  action: z.string(),
  description: z.string(),
  automated: z.boolean(),
  requiresApproval: z.boolean(),
});

export const PhishingAnalysisResultSchema = z.object({
  messageId: z.string(),
  isPhishing: z.boolean(),
  confidence: z.number().min(0).max(1),
  riskScore: z.number().min(0).max(10),
  severity: z.enum(['low', 'medium', 'high', 'critical']),
  indicators: z.array(ThreatIndicatorSchema),
  recommendedActions: z.array(RecommendedActionSchema),
  analysisTimestamp: z.date(),
  analysisId: z.string(),
});

export type ThreatIndicator = z.infer<typeof ThreatIndicatorSchema>;
export type RecommendedAction = z.infer<typeof RecommendedActionSchema>;
export type PhishingAnalysisResult = z.infer<typeof PhishingAnalysisResultSchema>;

// ============================================================================
// Microsoft Graph API Schemas
// ============================================================================

export const GraphEmailAddressSchema = z.object({
  emailAddress: z.object({
    address: z.string().email(),
    name: z.string().optional(),
  }),
});

export const GraphEmailBodySchema = z.object({
  content: z.string(),
  contentType: z.enum(['text', 'html']).optional(),
});

export const GraphInternetMessageHeaderSchema = z.object({
  name: z.string().optional(),
  value: z.string().optional(),
});

export const GraphAttachmentSchema = z.object({
  name: z.string().optional(),
  contentType: z.string().optional(),
  size: z.number().int().nonnegative().optional(),
  isInline: z.boolean().optional(),
});

export type GraphAttachment = z.infer<typeof GraphAttachmentSchema>;

export const GraphEmailSchema = z.object({
  id: z.string(),
  internetMessageId: z.string().optional(),
  subject: z.string().optional(),
  from: GraphEmailAddressSchema.optional(),
  toRecipients: z.array(GraphEmailAddressSchema).optional(),
  receivedDateTime: z.string().optional(),
  sentDateTime: z.string().optional(),
  body: GraphEmailBodySchema.optional(),
  bodyPreview: z.string().optional(),
  internetMessageHeaders: z.array(GraphInternetMessageHeaderSchema).optional(),
  attachments: z.array(GraphAttachmentSchema).optional(),
});

export type GraphEmail = z.infer<typeof GraphEmailSchema>;

export const GraphEmailListResponseSchema = z.object({
  value: z.array(GraphEmailSchema),
  '@odata.nextLink': z.string().optional(),
});

export type GraphEmailListResponse = z.infer<typeof GraphEmailListResponseSchema>;

// ============================================================================
// Threat Intelligence API Schemas
// ============================================================================

// VirusTotal URL Analysis Response
export const VirusTotalStatsSchema = z.object({
  malicious: z.number().int().nonnegative(),
  suspicious: z.number().int().nonnegative(),
  undetected: z.number().int().nonnegative(),
  harmless: z.number().int().nonnegative(),
  timeout: z.number().int().nonnegative(),
});

export const VirusTotalUrlResponseSchema = z.object({
  data: z.object({
    id: z.string(),
    type: z.string(),
    attributes: z.object({
      last_analysis_stats: VirusTotalStatsSchema,
      last_analysis_results: z.record(z.string(), z.any()).optional(),
      url: z.string().optional(),
    }),
  }),
});

export type VirusTotalUrlResponse = z.infer<typeof VirusTotalUrlResponseSchema>;

// AbuseIPDB Response
export const AbuseIPDBResponseSchema = z.object({
  data: z.object({
    ipAddress: z.string(),
    abuseConfidenceScore: z.number().int().min(0).max(100),
    totalReports: z.number().int().nonnegative(),
    isWhitelisted: z.boolean().optional(),
    countryCode: z.string().optional(),
  }),
});

export type AbuseIPDBResponse = z.infer<typeof AbuseIPDBResponseSchema>;

// URLScan.io Response
export const URLScanResponseSchema = z.object({
  uuid: z.string(),
  result: z.string().url().optional(),
  api: z.string().url().optional(),
  visibility: z.string().optional(),
  message: z.string().optional(),
});

export type URLScanResponse = z.infer<typeof URLScanResponseSchema>;

// ============================================================================
// Performance Metrics Schema
// ============================================================================

export const PerformanceMetricsSchema = z.object({
  timestamp: z.date(),
  operation: z.string(),
  duration: z.number().nonnegative(),
  success: z.boolean(),
  errorMessage: z.string().optional(),
});

export type PerformanceMetrics = z.infer<typeof PerformanceMetricsSchema>;

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Safely parse data with Zod schema
 * Returns parsed data or throws detailed error
 */
export function safeParse<T>(schema: z.ZodSchema<T>, data: unknown, context?: string): T {
  const result = schema.safeParse(data);

  if (!result.success) {
    const errorMessage = `Validation failed${context ? ` for ${context}` : ''}: ${result.error.message}`;
    throw new Error(errorMessage);
  }

  return result.data;
}

/**
 * Validate data and return result object
 * Non-throwing version for graceful degradation
 */
export function validate<T>(
  schema: z.ZodSchema<T>,
  data: unknown
): { success: true; data: T } | { success: false; error: z.ZodError } {
  const result = schema.safeParse(data);

  if (result.success) {
    return { success: true, data: result.data };
  }

  return { success: false, error: result.error };
}
