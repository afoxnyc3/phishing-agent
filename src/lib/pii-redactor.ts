/**
 * PII Redaction - Sanitizes sensitive data from log output
 */

export interface RedactionPattern {
  name: string;
  regex: RegExp;
  replacement: string;
}

const DEFAULT_PATTERNS: RedactionPattern[] = [
  { name: 'email', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, replacement: '[REDACTED-EMAIL]' },
  {
    name: 'ip-address',
    regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    replacement: '[REDACTED-IP]',
  },
  {
    name: 'jwt',
    regex: /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
    replacement: '[REDACTED-JWT]',
  },
  { name: 'bearer-token', regex: /Bearer\s+[a-zA-Z0-9._~+/=-]+/gi, replacement: 'Bearer [REDACTED-TOKEN]' },
  {
    name: 'api-key',
    regex: /(?:api[_-]?key|token|secret|password|credential)['":\s=]+[a-zA-Z0-9._~+/=-]{8,}/gi,
    replacement: '[REDACTED-CREDENTIAL]',
  },
];

/** Fields whose values should be fully redacted */
const REDACTED_FIELDS = new Set([
  'subject',
  'emailSubject',
  'body',
  'emailBody',
  'htmlBody',
  'textBody',
  'attachmentFilename',
  'filename',
  'password',
  'secret',
  'token',
  'apiKey',
  'accessToken',
  'refreshToken',
  'clientSecret',
]);

/** Fields that should never be redacted (safe metadata) */
const SAFE_FIELDS = new Set([
  'analysisId',
  'correlationId',
  'messageId',
  'timestamp',
  'duration',
  'operation',
  'success',
  'riskScore',
  'severity',
  'isPhishing',
  'confidence',
  'indicatorCount',
  'totalIndicators',
  'level',
  'service',
]);

export class PiiRedactor {
  private patterns: RedactionPattern[];
  private enabled: boolean;

  constructor(options: { patterns?: RedactionPattern[]; enabled?: boolean } = {}) {
    this.patterns = options.patterns || DEFAULT_PATTERNS;
    this.enabled = options.enabled ?? true;
  }

  /** Redact PII from a string value */
  redactString(value: string): string {
    if (!this.enabled) return value;
    let result = value;
    for (const pattern of this.patterns) {
      result = result.replace(pattern.regex, pattern.replacement);
    }
    return result;
  }

  /** Redact PII from a metadata object (shallow) */
  redactObject(obj: Record<string, unknown>): Record<string, unknown> {
    if (!this.enabled) return obj;
    const redacted: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj)) {
      redacted[key] = this.redactValue(key, value);
    }
    return redacted;
  }

  private redactValue(key: string, value: unknown): unknown {
    if (SAFE_FIELDS.has(key)) return value;
    if (REDACTED_FIELDS.has(key)) return this.getFieldPlaceholder(key);
    if (typeof value === 'string') return this.redactString(value);
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      return this.redactObject(value as Record<string, unknown>);
    }
    return value;
  }

  private getFieldPlaceholder(key: string): string {
    if (['subject', 'emailSubject'].includes(key)) return '[REDACTED-SUBJECT]';
    if (['body', 'emailBody', 'htmlBody', 'textBody'].includes(key)) return '[REDACTED-BODY]';
    if (['attachmentFilename', 'filename'].includes(key)) return '[REDACTED-FILENAME]';
    return '[REDACTED]';
  }
}

/** Singleton redactor instance */
export const piiRedactor = new PiiRedactor({
  enabled: process.env.PII_REDACTION_ENABLED !== 'false',
});
