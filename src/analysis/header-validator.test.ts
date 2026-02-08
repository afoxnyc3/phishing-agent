import { describe, it, expect } from 'vitest';
import { HeaderValidator } from './header-validator.js';
import { EmailHeaders } from '../lib/types.js';

describe('HeaderValidator', () => {
  describe('SPF Validation', () => {
    it('should detect SPF pass', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-1',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
        'received-spf': 'pass',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.spfResult.status).toBe('pass');
      expect(result.spfResult.isAuthentic).toBe(true);
    });

    it('should detect SPF fail', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-2',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
        'authentication-results': 'spf=fail',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.spfResult.status).toBe('fail');
      expect(result.spfResult.isAuthentic).toBe(false);
      expect(result.indicators.some((i) => i.description.includes('SPF'))).toBe(true);
    });

    it('should detect SPF softfail', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-3',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
        'received-spf': 'softfail',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.spfResult.status).toBe('softfail');
      expect(result.spfResult.isAuthentic).toBe(false);
    });

    it('should handle missing SPF header', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-4',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.spfResult.status).toBe('none');
      expect(result.spfResult.isAuthentic).toBe(false);
    });
  });

  describe('DKIM Validation', () => {
    it('should detect DKIM pass', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-5',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
        'authentication-results': 'dkim=pass',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.dkimResult.status).toBe('pass');
      expect(result.dkimResult.isAuthentic).toBe(true);
    });

    it('should detect DKIM fail', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-6',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
        'authentication-results': 'dkim=fail',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.dkimResult.status).toBe('fail');
      expect(result.dkimResult.isAuthentic).toBe(false);
      expect(result.indicators.some((i) => i.description.includes('DKIM'))).toBe(true);
    });

    it('should handle missing DKIM results', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-7',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.dkimResult.status).toBe('none');
      expect(result.dkimResult.isAuthentic).toBe(false);
    });
  });

  describe('DMARC Validation', () => {
    it('should detect DMARC pass', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-8',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
        'authentication-results': 'dmarc=pass',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.dmarcResult.status).toBe('pass');
      expect(result.dmarcResult.isAuthentic).toBe(true);
    });

    it('should detect DMARC fail', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-9',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
        'authentication-results': 'dmarc=fail',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.dmarcResult.status).toBe('fail');
      expect(result.dmarcResult.isAuthentic).toBe(false);
      expect(result.indicators.some((i) => i.description.includes('DMARC'))).toBe(true);
    });

    it('should detect DMARC quarantine', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-10',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
        'dmarc-results': 'dmarc=quarantine',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.dmarcResult.status).toBe('quarantine');
      expect(result.dmarcResult.isAuthentic).toBe(false);
    });

    it('should detect DMARC reject with critical severity', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-11',
        from: 'sender@example.com',
        to: 'recipient@test.com',
        subject: 'Test',
        date: '2024-01-01',
        'authentication-results': 'dmarc=reject',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.dmarcResult.status).toBe('reject');
      const dmarcIndicator = result.indicators.find((i) => i.description.includes('DMARC'));
      expect(dmarcIndicator?.severity).toBe('critical');
    });
  });

  describe('Domain Spoofing Detection', () => {
    it('should detect domain spoofing', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-12',
        from: 'paypal@fake-site.com',
        to: 'victim@test.com',
        subject: 'Urgent Account Notice',
        date: '2024-01-01',
        'authentication-results': 'header.from=paypal.com',
      };

      const indicator = HeaderValidator.checkDomainSpoofing(headers);
      expect(indicator).not.toBeNull();
      expect(indicator?.severity).toBe('critical');
      expect(indicator?.type).toBe('header');
      expect(indicator?.confidence).toBeGreaterThan(0.9);
    });

    it('should not flag legitimate emails with matching domains', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-13',
        from: 'notifications@paypal.com',
        to: 'user@test.com',
        subject: 'Receipt',
        date: '2024-01-01',
        'authentication-results': 'header.from=paypal.com',
      };

      const indicator = HeaderValidator.checkDomainSpoofing(headers);
      expect(indicator).toBeNull();
    });

    it('should handle subdomain variations correctly', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-14',
        from: 'noreply@mail.google.com',
        to: 'user@test.com',
        subject: 'Alert',
        date: '2024-01-01',
        'authentication-results': 'header.from=google.com',
      };

      const indicator = HeaderValidator.checkDomainSpoofing(headers);
      expect(indicator).toBeNull();
    });
  });

  describe('Reply-To Mismatch Detection', () => {
    it('should detect reply-to domain mismatch', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-15',
        from: 'support@company.com',
        to: 'user@test.com',
        subject: 'Help Ticket',
        date: '2024-01-01',
        'reply-to': 'scammer@evil.com',
      };

      const indicator = HeaderValidator.checkReplyToMismatch(headers);
      expect(indicator).not.toBeNull();
      expect(indicator?.severity).toBe('medium');
      expect(indicator?.description).toContain('Reply-To');
    });

    it('should not flag matching reply-to addresses', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-16',
        from: 'noreply@company.com',
        to: 'user@test.com',
        subject: 'Newsletter',
        date: '2024-01-01',
        'reply-to': 'support@company.com',
      };

      const indicator = HeaderValidator.checkReplyToMismatch(headers);
      expect(indicator).toBeNull();
    });

    it('should handle missing reply-to header', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-17',
        from: 'sender@example.com',
        to: 'user@test.com',
        subject: 'Test',
        date: '2024-01-01',
      };

      const indicator = HeaderValidator.checkReplyToMismatch(headers);
      expect(indicator).toBeNull();
    });
  });

  describe('Complete Validation', () => {
    it('should validate legitimate email with all checks passing', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-18',
        from: 'noreply@google.com',
        to: 'user@test.com',
        subject: 'Google Alert',
        date: '2024-01-01',
        'received-spf': 'pass',
        'authentication-results': 'spf=pass; dkim=pass; dmarc=pass; header.from=google.com',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.isValid).toBe(true);
      expect(result.indicators.length).toBe(0);
      expect(result.spfResult.isAuthentic).toBe(true);
      expect(result.dkimResult.isAuthentic).toBe(true);
      expect(result.dmarcResult.isAuthentic).toBe(true);
    });

    it('should validate phishing email with multiple failures', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-19',
        from: 'security@paypa1.com',
        to: 'victim@test.com',
        subject: 'URGENT: Verify Your Account',
        date: '2024-01-01',
        'received-spf': 'fail',
        'authentication-results': 'spf=fail; dkim=fail; dmarc=fail',
        'reply-to': 'phisher@evil.ru',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.isValid).toBe(false);
      expect(result.indicators.length).toBeGreaterThan(2);
      expect(result.spfResult.isAuthentic).toBe(false);
      expect(result.dkimResult.isAuthentic).toBe(false);
      expect(result.dmarcResult.isAuthentic).toBe(false);
    });

    it('should calculate confidence correctly from multiple indicators', () => {
      const headers: EmailHeaders = {
        'message-id': 'test-20',
        from: 'fake@example.com',
        to: 'user@test.com',
        subject: 'Test',
        date: '2024-01-01',
        'received-spf': 'fail',
        'authentication-results': 'spf=fail; dkim=fail; dmarc=fail',
      };

      const result = HeaderValidator.validate(headers);
      expect(result.confidence).toBeGreaterThan(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
      expect(result.indicators.length).toBe(3);
    });
  });
});
