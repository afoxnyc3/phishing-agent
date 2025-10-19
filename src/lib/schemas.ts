/**
 * Zod Runtime Validation Schemas
 * Provides type-safe validation for external data sources
 */

import { z } from 'zod';

// ============================================================================
// Environment Configuration Schemas
// ============================================================================

export const EnvConfigSchema = z.object({
  // Azure configuration
  AZURE_TENANT_ID: z.string().min(1, 'Azure Tenant ID is required'),
  AZURE_CLIENT_ID: z.string().min(1, 'Azure Client ID is required'),
  AZURE_CLIENT_SECRET: z.string().optional(),

  // Mailbox configuration
  PHISHING_MAILBOX_ADDRESS: z.string().email('Invalid mailbox email address'),
  MAILBOX_CHECK_INTERVAL_MS: z.coerce.number().int().positive().default(60000),
  MAILBOX_MONITOR_ENABLED: z.coerce.boolean().default(true),

  // Threat Intel configuration
  THREAT_INTEL_ENABLED: z.coerce.boolean().default(true),
  THREAT_INTEL_TIMEOUT_MS: z.coerce.number().int().positive().default(5000),
  THREAT_INTEL_CACHE_TTL_MS: z.coerce.number().int().positive().default(300000),
  VIRUSTOTAL_API_KEY: z.string().optional(),
  ABUSEIPDB_API_KEY: z.string().optional(),
  URLSCAN_API_KEY: z.string().optional(),

  // Server configuration
  PORT: z.coerce.number().int().positive().default(3000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
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

export const EmailHeadersSchema = z.object({
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
}).catchall(z.string().optional());

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
