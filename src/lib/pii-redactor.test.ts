import { describe, it, expect, beforeEach } from '@jest/globals';
import { PiiRedactor } from './pii-redactor.js';

describe('PiiRedactor', () => {
  let redactor: PiiRedactor;

  beforeEach(() => {
    redactor = new PiiRedactor();
  });

  describe('redactString', () => {
    it('should redact email addresses', () => {
      expect(redactor.redactString('Contact user@example.com for info')).toBe('Contact [REDACTED-EMAIL] for info');
    });

    it('should redact multiple email addresses', () => {
      const input = 'From: alice@evil.com To: bob@company.com';
      const result = redactor.redactString(input);
      expect(result).toBe('From: [REDACTED-EMAIL] To: [REDACTED-EMAIL]');
    });

    it('should redact IP addresses', () => {
      expect(redactor.redactString('Source IP: 192.168.1.100')).toBe('Source IP: [REDACTED-IP]');
    });

    it('should redact JWT tokens', () => {
      const jwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
      expect(redactor.redactString(`Token: ${jwt}`)).toBe('Token: [REDACTED-JWT]');
    });

    it('should redact bearer tokens', () => {
      expect(redactor.redactString('Authorization: Bearer abc123def456')).toBe(
        'Authorization: Bearer [REDACTED-TOKEN]'
      );
    });

    it('should not modify strings without PII', () => {
      expect(redactor.redactString('Analysis completed successfully')).toBe('Analysis completed successfully');
    });

    it('should handle empty strings', () => {
      expect(redactor.redactString('')).toBe('');
    });
  });

  describe('redactObject', () => {
    it('should redact known sensitive fields entirely', () => {
      const obj = { subject: 'Your account is compromised', analysisId: 'abc-123' };
      const result = redactor.redactObject(obj);
      expect(result.subject).toBe('[REDACTED-SUBJECT]');
      expect(result.analysisId).toBe('abc-123');
    });

    it('should redact body fields', () => {
      const result = redactor.redactObject({ body: 'Click this link now!', emailBody: '<html>evil</html>' });
      expect(result.body).toBe('[REDACTED-BODY]');
      expect(result.emailBody).toBe('[REDACTED-BODY]');
    });

    it('should redact filename fields', () => {
      const result = redactor.redactObject({ filename: 'malware.exe', attachmentFilename: 'invoice.pdf.exe' });
      expect(result.filename).toBe('[REDACTED-FILENAME]');
      expect(result.attachmentFilename).toBe('[REDACTED-FILENAME]');
    });

    it('should preserve safe metadata fields', () => {
      const obj = {
        analysisId: 'analysis-123',
        messageId: '<msg@test.com>',
        riskScore: 8.5,
        severity: 'critical',
        isPhishing: true,
        confidence: 0.95,
        indicatorCount: 5,
      };
      const result = redactor.redactObject(obj);
      expect(result).toEqual(obj);
    });

    it('should redact emails in string values of unknown fields', () => {
      const result = redactor.redactObject({ sender: 'phisher@evil.com', action: 'quarantine' });
      expect(result.sender).toBe('[REDACTED-EMAIL]');
      expect(result.action).toBe('quarantine');
    });

    it('should redact nested objects', () => {
      const result = redactor.redactObject({
        details: { sender: 'bad@evil.com', riskScore: 9.0 },
      });
      const details = result.details as Record<string, unknown>;
      expect(details.sender).toBe('[REDACTED-EMAIL]');
      expect(details.riskScore).toBe(9.0);
    });

    it('should not modify non-string, non-object values', () => {
      const result = redactor.redactObject({ count: 42, active: true, tags: ['phishing'] });
      expect(result).toEqual({ count: 42, active: true, tags: ['phishing'] });
    });
  });

  describe('disabled mode', () => {
    it('should pass through all data when disabled', () => {
      const disabled = new PiiRedactor({ enabled: false });
      expect(disabled.redactString('user@example.com')).toBe('user@example.com');
      expect(disabled.redactObject({ subject: 'secret' })).toEqual({ subject: 'secret' });
    });
  });

  describe('custom patterns', () => {
    it('should support custom redaction patterns', () => {
      const custom = new PiiRedactor({
        patterns: [{ name: 'ssn', regex: /\d{3}-\d{2}-\d{4}/g, replacement: '[REDACTED-SSN]' }],
      });
      expect(custom.redactString('SSN: 123-45-6789')).toBe('SSN: [REDACTED-SSN]');
    });
  });
});
