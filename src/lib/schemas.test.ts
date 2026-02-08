import { describe, it, expect } from '@jest/globals';
import {
  EnvConfigSchema,
  EmailAttachmentSchema,
  EmailHeadersSchema,
  EmailAnalysisRequestSchema,
  ThreatIndicatorSchema,
  RecommendedActionSchema,
  PhishingAnalysisResultSchema,
  GraphEmailSchema,
  GraphEmailListResponseSchema,
  VirusTotalUrlResponseSchema,
  AbuseIPDBResponseSchema,
  PerformanceMetricsSchema,
  safeParse,
  validate,
} from './schemas.js';

describe('Zod Schemas', () => {
  describe('EnvConfigSchema', () => {
    it('should validate complete valid config', () => {
      const env = {
        AZURE_TENANT_ID: 'test-tenant-id',
        AZURE_CLIENT_ID: 'test-client-id',
        AZURE_CLIENT_SECRET: 'test-secret',
        PHISHING_MAILBOX_ADDRESS: 'phishing@example.com',
        MAILBOX_CHECK_INTERVAL_MS: '60000',
        MAILBOX_MONITOR_ENABLED: 'true',
        THREAT_INTEL_ENABLED: 'true',
        THREAT_INTEL_TIMEOUT_MS: '5000',
        THREAT_INTEL_CACHE_TTL_MS: '300000',
        PORT: '3000',
        NODE_ENV: 'development',
      };

      const result = EnvConfigSchema.safeParse(env);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.AZURE_TENANT_ID).toBe('test-tenant-id');
        expect(result.data.MAILBOX_CHECK_INTERVAL_MS).toBe(60000);
        expect(result.data.MAILBOX_MONITOR_ENABLED).toBe(true);
      }
    });

    it('should use default values for optional fields', () => {
      const env = {
        AZURE_TENANT_ID: 'test-tenant-id',
        AZURE_CLIENT_ID: 'test-client-id',
        PHISHING_MAILBOX_ADDRESS: 'phishing@example.com',
      };

      const result = EnvConfigSchema.safeParse(env);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.MAILBOX_CHECK_INTERVAL_MS).toBe(60000);
        expect(result.data.PORT).toBe(3000);
        expect(result.data.NODE_ENV).toBe('development');
      }
    });

    it('should reject invalid email address', () => {
      const env = {
        AZURE_TENANT_ID: 'test-tenant-id',
        AZURE_CLIENT_ID: 'test-client-id',
        PHISHING_MAILBOX_ADDRESS: 'invalid-email',
      };

      const result = EnvConfigSchema.safeParse(env);
      expect(result.success).toBe(false);
    });

    it('should reject missing required fields', () => {
      const env = {
        AZURE_TENANT_ID: 'test-tenant-id',
      };

      const result = EnvConfigSchema.safeParse(env);
      expect(result.success).toBe(false);
    });

    it('should coerce string numbers to numbers', () => {
      const env = {
        AZURE_TENANT_ID: 'test-tenant-id',
        AZURE_CLIENT_ID: 'test-client-id',
        PHISHING_MAILBOX_ADDRESS: 'phishing@example.com',
        PORT: '8080',
      };

      const result = EnvConfigSchema.safeParse(env);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.PORT).toBe(8080);
        expect(typeof result.data.PORT).toBe('number');
      }
    });
  });

  describe('EmailSchemas', () => {
    it('should validate EmailAttachment', () => {
      const attachment = {
        filename: 'document.pdf',
        contentType: 'application/pdf',
        size: 1024,
      };

      const result = EmailAttachmentSchema.safeParse(attachment);
      expect(result.success).toBe(true);
    });

    it('should reject negative size in EmailAttachment', () => {
      const attachment = {
        filename: 'document.pdf',
        contentType: 'application/pdf',
        size: -1,
      };

      const result = EmailAttachmentSchema.safeParse(attachment);
      expect(result.success).toBe(false);
    });

    it('should validate EmailHeaders with required fields', () => {
      const headers = {
        'message-id': '<test@example.com>',
        from: 'sender@example.com',
        to: 'recipient@example.com',
        subject: 'Test Subject',
        date: '2024-01-01T12:00:00.000Z',
      };

      const result = EmailHeadersSchema.safeParse(headers);
      expect(result.success).toBe(true);
    });

    it('should validate EmailHeaders with optional fields', () => {
      const headers = {
        'message-id': '<test@example.com>',
        from: 'sender@example.com',
        to: 'recipient@example.com',
        subject: 'Test Subject',
        date: '2024-01-01T12:00:00.000Z',
        'received-spf': 'pass',
        'authentication-results': 'spf=pass; dkim=pass',
        'custom-header': 'custom-value',
      };

      const result = EmailHeadersSchema.safeParse(headers);
      expect(result.success).toBe(true);
    });

    it('should validate complete EmailAnalysisRequest', () => {
      const request = {
        messageId: '<test@example.com>',
        subject: 'Test Email',
        sender: 'sender@example.com',
        recipient: 'recipient@example.com',
        timestamp: new Date(),
        headers: {
          'message-id': '<test@example.com>',
          from: 'sender@example.com',
          to: 'recipient@example.com',
          subject: 'Test Email',
          date: '2024-01-01T12:00:00.000Z',
        },
        body: 'Test body content',
        attachments: [
          {
            filename: 'test.pdf',
            contentType: 'application/pdf',
            size: 1024,
          },
        ],
      };

      const result = EmailAnalysisRequestSchema.safeParse(request);
      expect(result.success).toBe(true);
    });

    it('should reject invalid sender email', () => {
      const request = {
        messageId: '<test@example.com>',
        subject: 'Test Email',
        sender: 'invalid-email',
        recipient: 'recipient@example.com',
        timestamp: new Date(),
        headers: {
          'message-id': '<test@example.com>',
          from: 'sender@example.com',
          to: 'recipient@example.com',
          subject: 'Test Email',
          date: '2024-01-01T12:00:00.000Z',
        },
      };

      const result = EmailAnalysisRequestSchema.safeParse(request);
      expect(result.success).toBe(false);
    });
  });

  describe('PhishingAnalysisSchemas', () => {
    it('should validate ThreatIndicator', () => {
      const indicator = {
        type: 'header',
        description: 'SPF validation failed',
        severity: 'high',
        evidence: 'spf=fail',
        confidence: 0.9,
      };

      const result = ThreatIndicatorSchema.safeParse(indicator);
      expect(result.success).toBe(true);
    });

    it('should reject invalid threat indicator type', () => {
      const indicator = {
        type: 'invalid-type',
        description: 'Test',
        severity: 'high',
        evidence: 'evidence',
        confidence: 0.9,
      };

      const result = ThreatIndicatorSchema.safeParse(indicator);
      expect(result.success).toBe(false);
    });

    it('should reject confidence out of range', () => {
      const indicator = {
        type: 'header',
        description: 'Test',
        severity: 'high',
        evidence: 'evidence',
        confidence: 1.5,
      };

      const result = ThreatIndicatorSchema.safeParse(indicator);
      expect(result.success).toBe(false);
    });

    it('should validate RecommendedAction', () => {
      const action = {
        priority: 'urgent',
        action: 'quarantine',
        description: 'Quarantine this email',
        automated: true,
        requiresApproval: false,
      };

      const result = RecommendedActionSchema.safeParse(action);
      expect(result.success).toBe(true);
    });

    it('should validate complete PhishingAnalysisResult', () => {
      const analysis = {
        messageId: '<test@example.com>',
        isPhishing: true,
        confidence: 0.95,
        riskScore: 8.5,
        severity: 'high',
        indicators: [
          {
            type: 'header',
            description: 'SPF failed',
            severity: 'high',
            evidence: 'spf=fail',
            confidence: 0.9,
          },
        ],
        recommendedActions: [
          {
            priority: 'urgent',
            action: 'quarantine',
            description: 'Quarantine email',
            automated: true,
            requiresApproval: false,
          },
        ],
        analysisTimestamp: new Date(),
        analysisId: 'analysis-123',
      };

      const result = PhishingAnalysisResultSchema.safeParse(analysis);
      expect(result.success).toBe(true);
    });

    it('should reject risk score above 10', () => {
      const analysis = {
        messageId: '<test@example.com>',
        isPhishing: true,
        confidence: 0.95,
        riskScore: 11,
        severity: 'critical',
        indicators: [],
        recommendedActions: [],
        analysisTimestamp: new Date(),
        analysisId: 'analysis-123',
      };

      const result = PhishingAnalysisResultSchema.safeParse(analysis);
      expect(result.success).toBe(false);
    });
  });

  describe('GraphEmailSchemas', () => {
    it('should validate complete Graph email', () => {
      const email = {
        id: 'email-123',
        internetMessageId: '<test@example.com>',
        subject: 'Test Email',
        from: {
          emailAddress: {
            address: 'sender@example.com',
            name: 'Sender Name',
          },
        },
        toRecipients: [
          {
            emailAddress: {
              address: 'recipient@example.com',
              name: 'Recipient Name',
            },
          },
        ],
        receivedDateTime: '2024-01-01T12:00:00.000Z',
        sentDateTime: '2024-01-01T11:59:00.000Z',
        body: {
          content: '<html><body>Test</body></html>',
          contentType: 'html',
        },
        bodyPreview: 'Test preview',
        internetMessageHeaders: [
          {
            name: 'Received-SPF',
            value: 'pass',
          },
        ],
        attachments: [
          {
            name: 'document.pdf',
            contentType: 'application/pdf',
            size: 1024,
          },
        ],
      };

      const result = GraphEmailSchema.safeParse(email);
      expect(result.success).toBe(true);
    });

    it('should validate minimal Graph email', () => {
      const email = {
        id: 'email-123',
      };

      const result = GraphEmailSchema.safeParse(email);
      expect(result.success).toBe(true);
    });

    it('should validate Graph email list response', () => {
      const response = {
        value: [
          {
            id: 'email-1',
            subject: 'Test 1',
          },
          {
            id: 'email-2',
            subject: 'Test 2',
          },
        ],
      };

      const result = GraphEmailListResponseSchema.safeParse(response);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.value).toHaveLength(2);
      }
    });

    it('should reject invalid email address in Graph email', () => {
      const email = {
        id: 'email-123',
        from: {
          emailAddress: {
            address: 'invalid-email',
          },
        },
      };

      const result = GraphEmailSchema.safeParse(email);
      expect(result.success).toBe(false);
    });
  });

  describe('ThreatIntelSchemas', () => {
    it('should validate VirusTotal URL response', () => {
      const response = {
        data: {
          id: 'url-id-123',
          type: 'url',
          attributes: {
            last_analysis_stats: {
              malicious: 5,
              suspicious: 2,
              undetected: 50,
              harmless: 10,
              timeout: 0,
            },
            last_analysis_results: {
              Scanner1: { category: 'malicious' },
              Scanner2: { category: 'clean' },
            },
            url: 'https://example.com',
          },
        },
      };

      const result = VirusTotalUrlResponseSchema.safeParse(response);
      expect(result.success).toBe(true);
    });

    it('should reject VirusTotal response with missing fields', () => {
      const response = {
        data: {
          id: 'url-id-123',
          type: 'url',
          attributes: {
            // Missing last_analysis_stats
          },
        },
      };

      const result = VirusTotalUrlResponseSchema.safeParse(response);
      expect(result.success).toBe(false);
    });

    it('should validate AbuseIPDB response', () => {
      const response = {
        data: {
          ipAddress: '192.168.1.1',
          abuseConfidenceScore: 75,
          totalReports: 10,
          isWhitelisted: false,
          countryCode: 'US',
        },
      };

      const result = AbuseIPDBResponseSchema.safeParse(response);
      expect(result.success).toBe(true);
    });

    it('should reject invalid abuse confidence score', () => {
      const response = {
        data: {
          ipAddress: '192.168.1.1',
          abuseConfidenceScore: 150, // Invalid: > 100
          totalReports: 10,
        },
      };

      const result = AbuseIPDBResponseSchema.safeParse(response);
      expect(result.success).toBe(false);
    });

    it('should reject negative total reports', () => {
      const response = {
        data: {
          ipAddress: '192.168.1.1',
          abuseConfidenceScore: 50,
          totalReports: -5, // Invalid: negative
        },
      };

      const result = AbuseIPDBResponseSchema.safeParse(response);
      expect(result.success).toBe(false);
    });
  });

  describe('PerformanceMetricsSchema', () => {
    it('should validate performance metrics', () => {
      const metrics = {
        timestamp: new Date(),
        operation: 'email-analysis',
        duration: 150,
        success: true,
      };

      const result = PerformanceMetricsSchema.safeParse(metrics);
      expect(result.success).toBe(true);
    });

    it('should validate failed operation with error message', () => {
      const metrics = {
        timestamp: new Date(),
        operation: 'email-analysis',
        duration: 500,
        success: false,
        errorMessage: 'Operation failed',
      };

      const result = PerformanceMetricsSchema.safeParse(metrics);
      expect(result.success).toBe(true);
    });

    it('should reject negative duration', () => {
      const metrics = {
        timestamp: new Date(),
        operation: 'email-analysis',
        duration: -100,
        success: true,
      };

      const result = PerformanceMetricsSchema.safeParse(metrics);
      expect(result.success).toBe(false);
    });
  });

  describe('Validation Helpers', () => {
    describe('safeParse', () => {
      it('should parse valid data successfully', () => {
        const data = {
          filename: 'test.pdf',
          contentType: 'application/pdf',
          size: 1024,
        };

        const result = safeParse(EmailAttachmentSchema, data);
        expect(result).toEqual(data);
      });

      it('should throw error for invalid data', () => {
        const data = {
          filename: 'test.pdf',
          contentType: 'application/pdf',
          size: -1, // Invalid
        };

        expect(() => safeParse(EmailAttachmentSchema, data)).toThrow('Validation failed');
      });

      it('should include context in error message', () => {
        const data = { invalid: 'data' };

        expect(() => safeParse(EmailAttachmentSchema, data, 'test context')).toThrow(
          'Validation failed for test context'
        );
      });
    });

    describe('validate', () => {
      it('should return success result for valid data', () => {
        const data = {
          filename: 'test.pdf',
          contentType: 'application/pdf',
          size: 1024,
        };

        const result = validate(EmailAttachmentSchema, data);
        expect(result.success).toBe(true);
        if (result.success) {
          expect(result.data).toEqual(data);
        }
      });

      it('should return failure result for invalid data', () => {
        const data = {
          filename: 'test.pdf',
          size: -1,
        };

        const result = validate(EmailAttachmentSchema, data);
        expect(result.success).toBe(false);
        if (!result.success) {
          expect(result.error).toBeDefined();
        }
      });

      it('should not throw for invalid data', () => {
        const data = { invalid: 'data' };

        expect(() => validate(EmailAttachmentSchema, data)).not.toThrow();
      });
    });
  });
});
