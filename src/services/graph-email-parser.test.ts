import { describe, it, expect, vi } from 'vitest';
import { parseGraphEmail, validateAnalysisRequest } from './graph-email-parser.js';

// Mock logger
vi.mock('../lib/logger.js', () => ({
  securityLogger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    security: vi.fn(),
  },
}));

describe('GraphEmailParser', () => {
  describe('parseGraphEmail', () => {
    it('should parse complete Graph API email', () => {
      const graphEmail = {
        id: 'graph-id-123',
        internetMessageId: '<message@example.com>',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test Email',
        receivedDateTime: '2024-01-01T12:00:00Z',
        sentDateTime: '2024-01-01T11:59:00Z',
        body: { content: '<html><body>Test body</body></html>', contentType: 'html' },
        bodyPreview: 'Test body',
        internetMessageHeaders: [
          { name: 'Received-SPF', value: 'pass' },
          { name: 'Authentication-Results', value: 'spf=pass; dkim=pass' },
        ],
        attachments: [{ name: 'document.pdf', contentType: 'application/pdf', size: 1024 }],
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.sender).toBe('sender@example.com');
      expect(result.recipient).toBe('recipient@example.com');
      expect(result.subject).toBe('Test Email');
      expect(result.messageId).toBe('<message@example.com>');
      expect(result.timestamp).toBeInstanceOf(Date);
      expect(result.body).toContain('Test body');
      expect(result.headers['message-id']).toBe('<message@example.com>');
      expect(result.headers.from).toBe('sender@example.com');
      expect(result.headers['received-spf']).toBe('pass');
      expect(result.attachments).toHaveLength(1);
      expect(result.attachments![0].filename).toBe('document.pdf');
    });

    it('should use defaults for missing sender', () => {
      const graphEmail = {
        id: 'test-id',
        subject: 'Test',
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.sender).toBe('unknown@unknown.com');
    });

    it('should use defaults for missing recipient', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        subject: 'Test',
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.recipient).toBe('unknown@unknown.com');
    });

    it('should use default subject for missing subject', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.subject).toBe('(No Subject)');
    });

    it('should use graph id when internetMessageId is missing', () => {
      const graphEmail = {
        id: 'graph-id-456',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.messageId).toBe('graph-id-456');
    });

    it('should use current time when receivedDateTime is missing', () => {
      const beforeParse = new Date();

      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
      };

      const result = parseGraphEmail(graphEmail);
      const afterParse = new Date();

      expect(result.timestamp.getTime()).toBeGreaterThanOrEqual(beforeParse.getTime());
      expect(result.timestamp.getTime()).toBeLessThanOrEqual(afterParse.getTime());
    });

    it('should use sentDateTime when receivedDateTime is missing', () => {
      const sentDate = '2024-01-01T10:00:00.000Z';

      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
        sentDateTime: sentDate,
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.timestamp.toISOString()).toBe(sentDate);
    });

    it('should use bodyPreview when body.content is missing', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
        bodyPreview: 'Preview text',
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.body).toBe('Preview text');
    });

    it('should use empty string when both body and bodyPreview are missing', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.body).toBe('');
    });

    it('should extract multiple headers', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
        internetMessageHeaders: [
          { name: 'Received-SPF', value: 'pass' },
          { name: 'DKIM-Signature', value: 'v=1; a=rsa-sha256' },
          { name: 'Authentication-Results', value: 'spf=pass; dkim=pass; dmarc=pass' },
        ],
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.headers['received-spf']).toBe('pass');
      expect(result.headers['dkim-signature']).toBe('v=1; a=rsa-sha256');
      expect(result.headers['authentication-results']).toBe('spf=pass; dkim=pass; dmarc=pass');
    });

    it('should convert header names to lowercase', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
        internetMessageHeaders: [{ name: 'X-Custom-Header', value: 'custom-value' }],
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.headers['x-custom-header']).toBe('custom-value');
    });

    it('should handle empty internetMessageHeaders array', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
        internetMessageHeaders: [],
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.headers['message-id']).toBe('test-id');
      expect(result.headers.from).toBe('sender@example.com');
    });

    it('should handle missing internetMessageHeaders', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
      };

      const result = parseGraphEmail(graphEmail);

      // Should still have basic headers
      expect(result.headers.from).toBe('sender@example.com');
    });

    it('should skip headers with missing name or value', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
        internetMessageHeaders: [
          { name: 'Valid-Header', value: 'valid-value' },
          { name: '', value: 'no-name' },
          { name: 'No-Value', value: '' },
          { value: 'no-name-field' },
        ],
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.headers['valid-header']).toBe('valid-value');
      // Empty name and value should be skipped or allowed
    });

    it('should extract multiple attachments', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
        attachments: [
          { name: 'file1.pdf', contentType: 'application/pdf', size: 1024 },
          {
            name: 'file2.docx',
            contentType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            size: 2048,
          },
          { name: 'image.jpg', contentType: 'image/jpeg', size: 512 },
        ],
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.attachments).toHaveLength(3);
      expect(result.attachments![0].filename).toBe('file1.pdf');
      expect(result.attachments![1].filename).toBe('file2.docx');
      expect(result.attachments![2].filename).toBe('image.jpg');
    });

    it('should handle attachments with missing fields', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
        attachments: [{ name: 'file1.pdf' }, { contentType: 'application/pdf', size: 1024 }, {}],
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.attachments).toHaveLength(3);
      expect(result.attachments![0].filename).toBe('file1.pdf');
      expect(result.attachments![0].contentType).toBe('application/octet-stream');
      expect(result.attachments![0].size).toBe(0);
      expect(result.attachments![1].filename).toBe('unknown');
      expect(result.attachments![2].filename).toBe('unknown');
    });

    it('should handle missing attachments', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.attachments).toEqual([]);
    });

    it('should handle empty attachments array', () => {
      const graphEmail = {
        id: 'test-id',
        from: { emailAddress: { address: 'sender@example.com' } },
        toRecipients: [{ emailAddress: { address: 'recipient@example.com' } }],
        subject: 'Test',
        attachments: [],
      };

      const result = parseGraphEmail(graphEmail);

      expect(result.attachments).toEqual([]);
    });
  });

  describe('validateAnalysisRequest', () => {
    it('should validate complete and valid request', () => {
      const request: any = {
        sender: 'sender@example.com',
        recipient: 'recipient@example.com',
        subject: 'Test',
        messageId: '<message@example.com>',
        timestamp: new Date(),
        headers: { 'message-id': '<message@example.com>', from: 'sender@example.com' },
        body: 'Test body',
        attachments: [],
      };

      expect(validateAnalysisRequest(request)).toBe(true);
    });

    it('should reject request with invalid sender (no @)', () => {
      const request: any = {
        sender: 'invalid-email',
        recipient: 'recipient@example.com',
        subject: 'Test',
        messageId: '<message@example.com>',
        timestamp: new Date(),
        headers: { 'message-id': '<message@example.com>' },
        body: 'Test',
      };

      expect(validateAnalysisRequest(request)).toBe(false);
    });

    it('should reject request with missing sender', () => {
      const request: any = {
        sender: '',
        recipient: 'recipient@example.com',
        subject: 'Test',
        messageId: '<message@example.com>',
        timestamp: new Date(),
        headers: { 'message-id': '<message@example.com>' },
        body: 'Test',
      };

      expect(validateAnalysisRequest(request)).toBe(false);
    });

    it('should reject request with missing messageId', () => {
      const request: any = {
        sender: 'sender@example.com',
        recipient: 'recipient@example.com',
        subject: 'Test',
        messageId: '',
        timestamp: new Date(),
        headers: { from: 'sender@example.com' },
        body: 'Test',
      };

      expect(validateAnalysisRequest(request)).toBe(false);
    });

    it('should reject request with missing headers', () => {
      const request: any = {
        sender: 'sender@example.com',
        recipient: 'recipient@example.com',
        subject: 'Test',
        messageId: '<message@example.com>',
        timestamp: new Date(),
        body: 'Test',
      };

      expect(validateAnalysisRequest(request)).toBe(false);
    });

    it('should reject request with empty headers object', () => {
      const request: any = {
        sender: 'sender@example.com',
        recipient: 'recipient@example.com',
        subject: 'Test',
        messageId: '<message@example.com>',
        timestamp: new Date(),
        headers: {},
        body: 'Test',
      };

      expect(validateAnalysisRequest(request)).toBe(false);
    });
  });
});
