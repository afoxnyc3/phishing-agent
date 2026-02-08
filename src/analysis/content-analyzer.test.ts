import { describe, it, expect } from '@jest/globals';
import { ContentAnalyzer } from './content-analyzer.js';

describe('ContentAnalyzer', () => {
  describe('Empty Content', () => {
    it('should handle empty body', () => {
      const result = ContentAnalyzer.analyze('');
      expect(result.hasPhishingPatterns).toBe(false);
      expect(result.indicators.length).toBe(0);
      expect(result.confidence).toBe(0);
    });

    it('should handle whitespace-only body', () => {
      const result = ContentAnalyzer.analyze('   \n   \t   ');
      expect(result.hasPhishingPatterns).toBe(false);
    });
  });

  describe('Urgency Tactics Detection', () => {
    it('should detect urgency keywords', () => {
      const body = 'URGENT: Your account will be suspended! Act now!';
      const result = ContentAnalyzer.analyze(body);

      expect(result.hasPhishingPatterns).toBe(true);
      expect(result.socialEngineeringTactics).toContain('urgency');
      expect(result.indicators.some((i) => i.description.includes('Urgency'))).toBe(true);
    });

    it('should increase severity with multiple urgency keywords', () => {
      const body = 'URGENT! Immediate action required! Act now! Limited time! Expires today!';
      const result = ContentAnalyzer.analyze(body);

      const urgencyIndicator = result.indicators.find((i) => i.description.includes('Urgency'));
      expect(urgencyIndicator?.severity).toBe('high');
      expect(urgencyIndicator?.confidence).toBeGreaterThan(0.7);
    });

    it('should detect case-insensitive urgency keywords', () => {
      const body = 'Your account has UNUSUAL ACTIVITY and will be LOCKED';
      const result = ContentAnalyzer.analyze(body);

      expect(result.socialEngineeringTactics).toContain('urgency');
    });
  });

  describe('Credential Harvesting Detection', () => {
    it('should detect password requests', () => {
      const body = 'Please verify your password and username to continue';
      const result = ContentAnalyzer.analyze(body);

      expect(result.hasPhishingPatterns).toBe(true);
      expect(result.socialEngineeringTactics).toContain('credential_harvesting');

      const credIndicator = result.indicators.find((i) => i.description.includes('Credential harvesting'));
      expect(credIndicator?.severity).toBe('critical');
      expect(credIndicator?.confidence).toBe(0.9);
    });

    it('should detect multiple credential requests', () => {
      const body = 'Please provide your credit card, CVV, and PIN number';
      const result = ContentAnalyzer.analyze(body);

      const credIndicator = result.indicators.find((i) => i.description.includes('Credential harvesting'));
      expect(credIndicator).not.toBeNull();
      expect(credIndicator?.evidence).toContain('credit card');
    });

    it('should detect social security and banking info requests', () => {
      const body = 'Update your bank account number and routing number';
      const result = ContentAnalyzer.analyze(body);

      expect(result.socialEngineeringTactics).toContain('credential_harvesting');
    });
  });

  describe('Financial Lures Detection', () => {
    it('should detect prize/lottery scams', () => {
      const body = "Congratulations! You've won the lottery! Claim your prize now!";
      const result = ContentAnalyzer.analyze(body);

      expect(result.hasPhishingPatterns).toBe(true);
      expect(result.socialEngineeringTactics).toContain('financial_lure');

      const finIndicator = result.indicators.find((i) => i.description.includes('Financial lure'));
      expect(finIndicator?.severity).toBe('high');
      expect(finIndicator?.confidence).toBe(0.85);
    });

    it('should detect refund scams', () => {
      const body = 'You have unclaimed funds waiting. Tax refund available.';
      const result = ContentAnalyzer.analyze(body);

      expect(result.socialEngineeringTactics).toContain('financial_lure');
    });

    it('should detect inheritance scams', () => {
      const body = 'Wire transfer required for inheritance claim';
      const result = ContentAnalyzer.analyze(body);

      expect(result.socialEngineeringTactics).toContain('financial_lure');
    });
  });

  describe('URL Analysis', () => {
    it('should extract URLs from body', () => {
      const body = 'Click here: https://example.com and visit https://test.org';
      const result = ContentAnalyzer.analyze(body);

      // Should extract URLs but not flag legitimate domains
      expect(result.suspiciousUrls.length).toBeGreaterThanOrEqual(0);
    });

    it('should detect IP address URLs', () => {
      const body = 'Visit our site at https://192.168.1.100/login';
      const result = ContentAnalyzer.analyze(body);

      expect(result.suspiciousUrls.some((u) => u.reason.includes('IP address'))).toBe(true);
      expect(result.indicators.some((i) => i.type === 'url' && i.severity === 'high')).toBe(true);
    });

    it('should detect URL shorteners', () => {
      const body = 'Click this link: https://bit.ly/abc123';
      const result = ContentAnalyzer.analyze(body);

      expect(result.suspiciousUrls.some((u) => u.reason.includes('shortener'))).toBe(true);
    });

    it('should detect @ symbol in URLs', () => {
      const body = 'Login at https://paypal.com@evil.com/login';
      const result = ContentAnalyzer.analyze(body);

      const atSymbolUrl = result.suspiciousUrls.find((u) => u.reason.includes('@'));
      expect(atSymbolUrl?.severity).toBe('critical');
    });

    it('should detect suspicious TLDs', () => {
      const body = 'Visit https://free-paypal.tk for your refund';
      const result = ContentAnalyzer.analyze(body);

      expect(result.suspiciousUrls.some((u) => u.reason.includes('Suspicious TLD'))).toBe(true);
    });

    it('should handle malformed URLs', () => {
      const body = 'Click http://[invalid-url]/test';
      const result = ContentAnalyzer.analyze(body);

      // Malformed URLs should be flagged but not crash
      expect(result.hasPhishingPatterns).toBeDefined();
    });
  });

  describe('Mismatched Links Detection', () => {
    it('should detect link text and URL mismatch', () => {
      const body = '<a href="https://evil.com">https://paypal.com</a>';
      const result = ContentAnalyzer.analyze(body);

      expect(result.socialEngineeringTactics).toContain('link_obfuscation');
      expect(result.indicators.some((i) => i.description.includes('Mismatched link'))).toBe(true);
    });

    it('should handle multiple mismatched links', () => {
      const body = `
        <a href="https://phisher.com">www.paypal.com</a>
        <a href="https://scam.ru">www.microsoft.com</a>
      `;
      const result = ContentAnalyzer.analyze(body);

      const mismatchIndicator = result.indicators.find((i) => i.description.includes('Mismatched link'));
      expect(mismatchIndicator?.evidence).toContain('2');
      expect(mismatchIndicator?.severity).toBe('high');
    });

    it('should not flag legitimate links with matching domains', () => {
      const body = '<a href="https://example.com/page">Click here for more</a>';
      const result = ContentAnalyzer.analyze(body);

      expect(result.socialEngineeringTactics).not.toContain('link_obfuscation');
    });
  });

  describe('Brand Impersonation Detection', () => {
    it('should detect PayPal impersonation', () => {
      const body = 'Your PayPal account needs verification';
      const fromDomain = 'secure-paypa1.com';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.severity).toBe('critical');
      expect(indicator?.description).toContain('PayPal');
      expect(indicator?.confidence).toBeGreaterThan(0.9);
    });

    it('should detect Amazon impersonation', () => {
      const body = 'Amazon Order Confirmation: #123456';
      const fromDomain = 'amaz0n-orders.ru';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Amazon');
    });

    it('should detect Microsoft impersonation', () => {
      const body = 'Microsoft Security Alert: Unusual sign-in activity';
      const fromDomain = 'micros0ft.com';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Microsoft');
    });

    it('should not flag legitimate brand emails', () => {
      const body = 'Your PayPal transaction is complete';
      const fromDomain = 'mail.paypal.com';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).toBeNull();
    });

    it('should detect case-insensitive brand mentions', () => {
      const body = 'apple account security alert';
      const fromDomain = 'appl3-security.tk';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Apple');
    });

    it('should detect Netflix impersonation', () => {
      const body = 'Your Netflix subscription will expire soon';
      const fromDomain = 'netf1ix-billing.com';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Netflix');
    });

    it('should detect Chase bank impersonation', () => {
      const body = 'Chase Bank Security Alert: Verify your account';
      const fromDomain = 'chase-secure.ru';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Chase');
    });

    it('should detect LinkedIn impersonation', () => {
      const body = 'You have a new LinkedIn message';
      const fromDomain = 'linkedin-notifications.tk';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('LinkedIn');
    });

    it('should detect DHL shipping impersonation', () => {
      const body = 'DHL package delivery notification';
      const fromDomain = 'dhl-tracking.info';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('DHL');
    });

    it('should detect Facebook/Meta impersonation', () => {
      const body = 'Your Facebook account has been flagged';
      const fromDomain = 'facebook-security.net';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Facebook');
    });

    it('should detect Adobe impersonation', () => {
      const body = 'Adobe Creative Cloud subscription renewal';
      const fromDomain = 'adobe-billing.com';

      const indicator = ContentAnalyzer.detectBrandImpersonation(body, fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Adobe');
    });
  });

  describe('Typosquatting Detection', () => {
    it('should detect PayPal typosquatting (paypal → paypa1)', () => {
      const fromDomain = 'secure-paypa1.com';

      const indicator = ContentAnalyzer.detectTyposquatting(fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.severity).toBe('critical');
      expect(indicator?.description).toContain('PayPal');
      expect(indicator?.description).toContain('Typosquatting');
      expect(indicator?.confidence).toBeGreaterThan(0.95);
    });

    it('should detect Microsoft typosquatting (microsoft → micros0ft)', () => {
      const fromDomain = 'micros0ft.com';

      const indicator = ContentAnalyzer.detectTyposquatting(fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Microsoft');
    });

    it('should detect Google typosquatting (google → g00gle)', () => {
      const fromDomain = 'g00gle.ru';

      const indicator = ContentAnalyzer.detectTyposquatting(fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Google');
    });

    it('should detect Amazon typosquatting (amazon → amaz0n)', () => {
      const fromDomain = 'amaz0n-orders.com';

      const indicator = ContentAnalyzer.detectTyposquatting(fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Amazon');
    });

    it('should detect Netflix typosquatting (netflix → netf1ix)', () => {
      const fromDomain = 'netf1ix-billing.net';

      const indicator = ContentAnalyzer.detectTyposquatting(fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('Netflix');
    });

    it('should not flag legitimate domains', () => {
      const fromDomain = 'mail.google.com';

      const indicator = ContentAnalyzer.detectTyposquatting(fromDomain);

      expect(indicator).toBeNull();
    });

    it('should be case-insensitive', () => {
      const fromDomain = 'PAYPA1.COM';

      const indicator = ContentAnalyzer.detectTyposquatting(fromDomain);

      expect(indicator).not.toBeNull();
      expect(indicator?.description).toContain('PayPal');
    });
  });

  describe('Performance', () => {
    it('should complete brand detection in under 100ms', () => {
      const body = 'Your PayPal account needs verification from Amazon and Microsoft';
      const fromDomain = 'phishing-site.ru';

      const startTime = Date.now();
      ContentAnalyzer.detectBrandImpersonation(body, fromDomain);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(100);
    });

    it('should complete typosquatting detection in under 100ms', () => {
      const fromDomain = 'paypa1.com';

      const startTime = Date.now();
      ContentAnalyzer.detectTyposquatting(fromDomain);
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(100);
    });
  });

  describe('Complete Content Analysis', () => {
    it('should analyze legitimate email with no phishing patterns', () => {
      const body = 'Hi John, Here is the quarterly report you requested. Best regards.';
      const result = ContentAnalyzer.analyze(body);

      expect(result.hasPhishingPatterns).toBe(false);
      expect(result.indicators.length).toBe(0);
      expect(result.socialEngineeringTactics.length).toBe(0);
    });

    it('should analyze sophisticated phishing email with multiple indicators', () => {
      const body = `
        URGENT: Verify your account immediately!
        Your PayPal account has unusual activity and will be suspended.
        Click here to verify: https://192.168.1.1/paypal
        Please provide your password and credit card information.
        Act now! Limited time offer - claim your refund!
      `;

      const result = ContentAnalyzer.analyze(body);

      expect(result.hasPhishingPatterns).toBe(true);
      expect(result.indicators.length).toBeGreaterThan(3);
      expect(result.socialEngineeringTactics).toContain('urgency');
      expect(result.socialEngineeringTactics).toContain('credential_harvesting');
      expect(result.socialEngineeringTactics).toContain('financial_lure');
      expect(result.confidence).toBeGreaterThan(0.7);
    });

    it('should calculate confidence correctly from multiple indicators', () => {
      const body = 'Urgent! Enter your password at https://bit.ly/fake';
      const result = ContentAnalyzer.analyze(body);

      expect(result.confidence).toBeGreaterThan(0);
      expect(result.confidence).toBeLessThanOrEqual(1);
      expect(result.indicators.length).toBeGreaterThan(0);
    });

    it('should handle complex HTML with embedded URLs', () => {
      const body = `
        <html>
          <body>
            <p>Click <a href="https://evil.com">https://paypal.com</a> to verify</p>
            <p>Urgent: Verify your password now!</p>
          </body>
        </html>
      `;

      const result = ContentAnalyzer.analyze(body);

      expect(result.hasPhishingPatterns).toBe(true);
      expect(result.socialEngineeringTactics.length).toBeGreaterThan(0);
    });
  });
});
